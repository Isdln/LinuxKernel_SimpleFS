#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/statfs.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <crypto/hash.h>

#include "SimpleFS.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student");
MODULE_DESCRIPTION("SimpleFS kernel module");

static char* device_name = "";
static int sb1_offset = 0;
static int sb2_offset = SIMPLEFS_DEFAULT_SB2_OFFSET;
static int max_name_len = SIMPLEFS_DEFAULT_MAX_NAME;
static int max_file_size = SIMPLEFS_DEFAULT_MAX_FILESZ;

module_param(device_name, charp, 0444);
MODULE_PARM_DESC(device_name, "Block device name (informational)");
module_param(sb1_offset, int, 0444);
MODULE_PARM_DESC(sb1_offset, "Sector of the first superblock copy (default 0)");
module_param(sb2_offset, int, 0444);
MODULE_PARM_DESC(sb2_offset, "Sector of the second superblock copy (default 1024)");
module_param(max_name_len, int, 0444);
MODULE_PARM_DESC(max_name_len, "Maximum filename length");
module_param(max_file_size, int, 0444);
MODULE_PARM_DESC(max_file_size, "Maximum file size in sectors (M)");

struct simplefs_sb_info {
	sector_t sb1_sector;
	sector_t sb2_sector;
	u32 file_size_sectors;
	u32 num_files;
	sector_t first_file_sector;
	u32 max_name_len;
	u64 total_sectors;
};

struct simplefs_inode_info {
	struct inode vfs_inode;
	u32 file_index;
};

static inline struct simplefs_inode_info* SIMPLEFS_I(struct inode* inode)
{
	return container_of(inode, struct simplefs_inode_info, vfs_inode);
}

#define SIMPLEFS_ROOT_INO 1u
#define SIMPLEFS_FIRST_FILE_INO 2u

static struct kmem_cache* simplefs_inode_cachep;

static int sha256(const void* data, size_t len, u8* out)
{
	struct crypto_shash* tfm;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("SimpleFS: cannot allocate sha256: %ld\n", PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	{
		SHASH_DESC_ON_STACK(desc, tfm);
		desc->tfm = tfm;
		ret = crypto_shash_digest(desc, data, len, out);
		shash_desc_zero(desc);
	}
	crypto_free_shash(tfm);
	return ret;
}

static int compute_sb_hash(const struct simplefs_disk_sb* dsb, u8* out)
{
	const size_t hash_off = offsetof(struct simplefs_disk_sb, hash);
	return sha256(dsb, hash_off, out);
}

static u32 calc_num_files(sector_t total_sectors, sector_t sb1, sector_t sb2, u32 file_sz)
{
	sector_t r1_start, r1_end, r2_start, r2_end;
	u64 r1_files, r2_files;

	if (sb1 >= sb2 || sb2 >= total_sectors || file_sz == 0) {
		return 0;
	}

	r1_start = sb1 + 1;
	r1_end = sb2;
	r2_start = sb2 + 1;
	r2_end = total_sectors;

	r1_files = (u64)(r1_end - r1_start) / file_sz;
	r2_files = (u64)(r2_end - r2_start) / file_sz;
	return (u32)(r1_files + r2_files);
}

static sector_t file_first_sector(const struct simplefs_sb_info* sbi, u32 idx)
{
	sector_t r1_start = sbi->sb1_sector + 1;
	sector_t r1_end = sbi->sb2_sector;
	u32 r1_files = (u32)((u64)(r1_end - r1_start) / sbi->file_size_sectors);

	if (idx < r1_files) {
		return r1_start + (sector_t)idx * sbi->file_size_sectors;
	}

	return sbi->sb2_sector + 1 + (sector_t)(idx - r1_files) * sbi->file_size_sectors;
}

static int read_sb(struct super_block* sb, sector_t sector, struct simplefs_disk_sb* out)
{
	struct buffer_head* bh = sb_bread(sb, sector);
	if (!bh) {
		return -EIO;
	}

	memcpy(out, bh->b_data, sizeof(*out));
	brelse(bh);
	return 0;
}

static int write_sb(struct super_block* sb, sector_t sector, const struct simplefs_disk_sb* in)
{
	struct buffer_head* bh = sb_getblk(sb, sector);
	if (!bh) {
		return -EIO;
	}

	lock_buffer(bh);
	memset(bh->b_data, 0, bh->b_size);
	memcpy(bh->b_data, in, sizeof(*in));
	set_buffer_uptodate(bh);
	mark_buffer_dirty(bh);
	unlock_buffer(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
	return 0;
}

static bool sb_valid(const struct simplefs_disk_sb* dsb)
{
	u8 h[SIMPLEFS_HASH_SIZE];

	if (le32_to_cpu(dsb->magic) != SIMPLEFS_MAGIC) {
		return false;
	}

	if (compute_sb_hash(dsb, h)) {
		return false;
	}

	return memcmp(h, dsb->hash, SIMPLEFS_HASH_SIZE) == 0;
}

static bool sb_blank(const struct simplefs_disk_sb* dsb)
{
	return le32_to_cpu(dsb->magic) == 0;
}

static int persist_sb(struct super_block* sb, struct simplefs_disk_sb* dsb)
{
	int ret;

	memset(dsb->hash, 0, SIMPLEFS_HASH_SIZE);
	ret = compute_sb_hash(dsb, dsb->hash);

	if (ret) {
		return ret;
	}

	ret = write_sb(sb, le64_to_cpu(dsb->sb1_sector), dsb);
	if (ret) {
		return ret;
	}

	return write_sb(sb, le64_to_cpu(dsb->sb2_sector), dsb);
}

static int zero_file(struct super_block* sb, const struct simplefs_sb_info* sbi, u32 idx)
{
	sector_t start = file_first_sector(sbi, idx);
	u32 i;

	for (i = 0; i < sbi->file_size_sectors; i++) {
		struct buffer_head* bh = sb_getblk(sb, start + i);

		if (!bh) {
			return -EIO;
		}

		lock_buffer(bh);
		memset(bh->b_data, 0, bh->b_size);
		set_buffer_uptodate(bh);
		mark_buffer_dirty(bh);
		unlock_buffer(bh);
		brelse(bh);
	}
	return 0;
}

static int format_fs(struct super_block* sb, sector_t total_sectors)
{
	struct simplefs_sb_info* sbi = sb->s_fs_info;
	struct simplefs_disk_sb dsb;
	u32 i;
	int ret;

	if (sb1_offset < 0 || sb2_offset <= sb1_offset) {
		pr_err("SimpleFS: invalid SB offsets (sb1=%d sb2=%d)\n", sb1_offset, sb2_offset);
		return -EINVAL;
	}
	if (max_file_size < 1 || max_file_size > 1024) {
		pr_err("SimpleFS: invalid max_file_size=%d\n", max_file_size);
		return -EINVAL;
	}
	if ((sector_t)sb2_offset >= total_sectors) {
		pr_err("SimpleFS: sb2_offset (%d) >= total_sectors (%llu)\n",
			sb2_offset, (u64)total_sectors);
		return -EINVAL;
	}

	memset(&dsb, 0, sizeof(dsb));

	dsb.magic = cpu_to_le32(SIMPLEFS_MAGIC);
	dsb.file_size_sectors = cpu_to_le32((u32)max_file_size);
	dsb.max_name_len = cpu_to_le32((u32)max_name_len);
	dsb.sb1_sector = cpu_to_le64((u64)sb1_offset);
	dsb.sb2_sector = cpu_to_le64((u64)sb2_offset);
	dsb.first_file_sector = cpu_to_le64((u64)sb1_offset + 1);
	dsb.total_sectors = cpu_to_le64((u64)total_sectors);
	dsb.num_files = cpu_to_le32(calc_num_files(total_sectors, sb1_offset, sb2_offset, max_file_size));

	sbi->sb1_sector = le64_to_cpu(dsb.sb1_sector);
	sbi->sb2_sector = le64_to_cpu(dsb.sb2_sector);
	sbi->file_size_sectors = le32_to_cpu(dsb.file_size_sectors);
	sbi->num_files = le32_to_cpu(dsb.num_files);
	sbi->first_file_sector = le64_to_cpu(dsb.first_file_sector);
	sbi->max_name_len = le32_to_cpu(dsb.max_name_len);
	sbi->total_sectors = le64_to_cpu(dsb.total_sectors);

	pr_info("SimpleFS: formatted: sb1=%llu sb2=%llu file_sz=%u num_files=%u total=%llu\n", (u64)sbi->sb1_sector, (u64)sbi->sb2_sector, sbi->file_size_sectors, sbi->num_files, sbi->total_sectors);

	for (i = 0; i < sbi->num_files; i++) {
		ret = zero_file(sb, sbi, i);
		if (ret) {
			pr_err("SimpleFS: failed to zero file %u: %d\n", i, ret);
			return ret;
		}
	}

	ret = persist_sb(sb, &dsb);
	if (ret) {
		pr_err("SimpleFS: failed to write SB: %d\n", ret);
		return ret;
	}

	sync_blockdev(sb->s_bdev);
	return 0;
}

static long parse_name(const char* name, u32 num_files)
{
	const size_t pref_len = sizeof(SIMPLEFS_NAME_PREFIX) - 1;
	u32 idx;

	if (strncmp(name, SIMPLEFS_NAME_PREFIX, pref_len) != 0) {
		return -ENOENT;
	}

	if (kstrtouint(name + pref_len, 10, &idx)) {
		return -ENOENT;
	}

	if (idx >= num_files) {
		return -ENOENT;
	}

	return idx;
}

static void make_name(char* buf, size_t buflen, u32 idx)
{
	snprintf(buf, buflen, "%s%u", SIMPLEFS_NAME_PREFIX, idx);
}

static ssize_t file_read(struct file* file, char __user* ubuf, size_t count, loff_t* ppos)
{
	struct inode* inode = file_inode(file);
	struct super_block* sb = inode->i_sb;
	struct simplefs_sb_info* sbi = sb->s_fs_info;
	struct simplefs_inode_info* mi = SIMPLEFS_I(inode);
	loff_t file_size = (loff_t)sbi->file_size_sectors * SIMPLEFS_SECTOR_SIZE;
	loff_t pos = *ppos;
	size_t done = 0;

	if (pos < 0) {
		return -EINVAL;
	}

	if (pos >= file_size) {
		return 0;
	}

	if (pos + count > file_size) {
		count = file_size - pos;
	}

	while (count > 0) {
		sector_t base = file_first_sector(sbi, mi->file_index);
		sector_t block = base + (sector_t)(pos / SIMPLEFS_SECTOR_SIZE);
		size_t off_in = pos % SIMPLEFS_SECTOR_SIZE;
		size_t chunk = min(count, (size_t)(SIMPLEFS_SECTOR_SIZE - off_in));
		struct buffer_head* bh;

		bh = sb_bread(sb, block);

		if (!bh) {
			return done ? done : -EIO;
		}

		if (copy_to_user(ubuf + done, bh->b_data + off_in, chunk)) {
			brelse(bh);
			return done ? done : -EFAULT;
		}

		brelse(bh);

		done += chunk;
		pos += chunk;
		count -= chunk;
	}

	*ppos = pos;
	return done;
}

static ssize_t file_write(struct file* file, const char __user* ubuf, size_t count, loff_t* ppos)
{
	struct inode* inode = file_inode(file);
	struct super_block* sb = inode->i_sb;
	struct simplefs_sb_info* sbi = sb->s_fs_info;
	struct simplefs_inode_info* mi = SIMPLEFS_I(inode);
	loff_t file_size = (loff_t)sbi->file_size_sectors * SIMPLEFS_SECTOR_SIZE;
	loff_t pos = (file->f_flags & O_APPEND) ? 0 : *ppos;
	size_t done = 0;

	if (pos < 0) {
		return -EINVAL;
	}

	if (pos >= file_size) {
		return -ENOSPC;
	}

	if (pos + count > file_size) {
		count = file_size - pos;
	}

	while (count > 0) {
		sector_t base = file_first_sector(sbi, mi->file_index);
		sector_t block = base + (sector_t)(pos / SIMPLEFS_SECTOR_SIZE);
		size_t off_in = pos % SIMPLEFS_SECTOR_SIZE;
		size_t chunk = min(count, (size_t)(SIMPLEFS_SECTOR_SIZE - off_in));
		struct buffer_head* bh;

		if (off_in == 0 && chunk == SIMPLEFS_SECTOR_SIZE) {
			bh = sb_getblk(sb, block);
		}
		else {
			bh = sb_bread(sb, block);
		}

		if (!bh) {
			return done ? done : -EIO;
		}

		lock_buffer(bh);

		if (copy_from_user(bh->b_data + off_in, ubuf + done, chunk)) {
			unlock_buffer(bh);
			brelse(bh);
			return done ? done : -EFAULT;
		}

		set_buffer_uptodate(bh);
		mark_buffer_dirty(bh);
		unlock_buffer(bh);
		brelse(bh);

		done += chunk;
		pos += chunk;
		count -= chunk;
	}

	*ppos = pos;

	inode_set_mtime_to_ts(inode, current_time(inode));
	mark_inode_dirty(inode);
	return done;
}

static int file_fsync(struct file* file, loff_t s, loff_t e, int datasync)
{
	struct super_block* sb = file_inode(file)->i_sb;
	sync_blockdev(sb->s_bdev);
	return 0;
}

static long ioctl_zero_all(struct super_block* sb)
{
	struct simplefs_sb_info* sbi = sb->s_fs_info;
	u32 i;
	int ret;

	for (i = 0; i < sbi->num_files; i++) {
		ret = zero_file(sb, sbi, i);

		if (ret) {
			return ret;
		}
	}

	sync_blockdev(sb->s_bdev);
	return 0;
}

static long ioctl_erase(struct super_block* sb)
{
	struct simplefs_sb_info* sbi = sb->s_fs_info;
	struct buffer_head* bh;
	int ret;

	bh = sb_getblk(sb, sbi->sb1_sector);

	if (bh) {
		lock_buffer(bh);
		memset(bh->b_data, 0, bh->b_size);
		set_buffer_uptodate(bh);
		mark_buffer_dirty(bh);
		unlock_buffer(bh);
		sync_dirty_buffer(bh);
		brelse(bh);
	}

	bh = sb_getblk(sb, sbi->sb2_sector);

	if (bh) {
		lock_buffer(bh);
		memset(bh->b_data, 0, bh->b_size);
		set_buffer_uptodate(bh);
		mark_buffer_dirty(bh);
		unlock_buffer(bh);
		sync_dirty_buffer(bh);
		brelse(bh);
	}

	ret = ioctl_zero_all(sb);

	if (ret) {
		return ret;
	}

	sbi->num_files = 0;

	pr_info("SimpleFS: FS erased (both SBs and all files cleared). Unmount and remount to reformat.\n");
	return 0;
}

static int compute_content_hash(struct super_block* sb, const struct simplefs_sb_info* sbi, u32 idx, struct shash_desc* desc, u8* out)
{
	sector_t start = file_first_sector(sbi, idx);
	u32 i;
	int ret;

	ret = crypto_shash_init(desc);

	if (ret) {
		return ret;
	}

	for (i = 0; i < sbi->file_size_sectors; i++) {
		struct buffer_head* bh = sb_bread(sb, start + i);

		if (!bh) {
			return -EIO;
		}

		ret = crypto_shash_update(desc, bh->b_data, SIMPLEFS_SECTOR_SIZE);
		brelse(bh);

		if (ret) {
			return ret;
		}
	}

	return crypto_shash_final(desc, out);
}

static int file_content_hash(struct super_block* sb, const struct simplefs_sb_info* sbi, u32 idx, u8* out)
{
	struct crypto_shash* tfm;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, 0);

	if (IS_ERR(tfm)) {
		return PTR_ERR(tfm);
	}

	{
		SHASH_DESC_ON_STACK(desc, tfm);
		desc->tfm = tfm;
		ret = compute_content_hash(sb, sbi, idx, desc, out);
		shash_desc_zero(desc);
	}
	crypto_free_shash(tfm);
	return ret;
}

static long ioctl_get_hashes(struct super_block* sb, unsigned long arg)
{
	struct simplefs_sb_info* sbi = sb->s_fs_info;
	struct simplefs_hash_list hl;
	struct simplefs_file_hash __user* uarr;
	u32 i, n;
	int ret;

	if (copy_from_user(&hl, (void __user*)arg, sizeof(hl))) {
		return -EFAULT;
	}

	uarr = (struct simplefs_file_hash __user*)(uintptr_t)hl.hashes_ptr;

	hl.count = sbi->num_files;
	n = min(hl.capacity, sbi->num_files);
	hl.copied = n;

	for (i = 0; i < n; i++) {
		struct simplefs_file_hash entry;

		memset(&entry, 0, sizeof(entry));
		entry.file_index = i;
		make_name(entry.name, sizeof(entry.name), i);
		ret = file_content_hash(sb, sbi, i, entry.hash);

		if (ret) {
			return ret;
		}

		if (copy_to_user(&uarr[i], &entry, sizeof(entry))) {
			return -EFAULT;
		}
	}

	if (copy_to_user((void __user*)arg, &hl, sizeof(hl))) {
		return -EFAULT;
	}

	return 0;
}

static long ioctl_get_map(struct super_block* sb, unsigned long arg)
{
	struct simplefs_sb_info* sbi = sb->s_fs_info;
	struct simplefs_sector_map m;
	long idx;

	if (copy_from_user(&m, (void __user*)arg, sizeof(m))) {
		return -EFAULT;
	}

	if (m.file_index == ~0u) {
		m.name[SIMPLEFS_NAME_BUF - 1] = '\0';
		idx = parse_name(m.name, sbi->num_files);

		if (idx < 0) {
			return idx;
		}

		m.file_index = (u32)idx;
	}
	else if (m.file_index >= sbi->num_files) {
		return -ENOENT;
	}

	make_name(m.name, sizeof(m.name), m.file_index);
	m.first_sector = (u64)file_first_sector(sbi, m.file_index);
	m.num_sectors = (u64)sbi->file_size_sectors;

	if (copy_to_user((void __user*)arg, &m, sizeof(m))) {
		return -EFAULT;
	}
	return 0;
}

static long unlocked_ioctl(struct file* file, unsigned int cmd,
	unsigned long arg)
{
	struct super_block* sb = file_inode(file)->i_sb;

	switch (cmd) {
	case SIMPLEFS_IOC_ZERO_ALL: return ioctl_zero_all(sb);
	case SIMPLEFS_IOC_ERASE: return ioctl_erase(sb);
	case SIMPLEFS_IOC_GET_HASHES: return ioctl_get_hashes(sb, arg);
	case SIMPLEFS_IOC_GET_MAP: return ioctl_get_map(sb, arg);
	default: return -ENOTTY;
	}
}

static const struct file_operations simplefs_file_fops = {
	.owner = THIS_MODULE,
	.llseek = generic_file_llseek,
	.read = file_read,
	.write = file_write,
	.fsync = file_fsync,
	.unlocked_ioctl = unlocked_ioctl,
};


static struct dentry* lookup(struct inode* dir, struct dentry* dentry, unsigned int flags);

static const struct inode_operations simplefs_dir_iops = {
	.lookup = lookup,
};

static int file_setattr(struct mnt_idmap* idmap, struct dentry* dentry, struct iattr* iattr)
{
	struct inode* inode = d_inode(dentry);
	struct super_block* sb = inode->i_sb;
	struct simplefs_sb_info* sbi = sb->s_fs_info;
	struct simplefs_inode_info* mi = SIMPLEFS_I(inode);
	loff_t fsz = (loff_t)sbi->file_size_sectors * SIMPLEFS_SECTOR_SIZE;

	if (iattr->ia_valid & ATTR_SIZE) {
		if (iattr->ia_size == 0) {
			int ret = zero_file(sb, sbi, mi->file_index);

			if (ret) {
				return ret;
			}
		}
		else if (iattr->ia_size != fsz) {
			return -EPERM;
		}

		iattr->ia_valid &= ~ATTR_SIZE;
	}

	if (!iattr->ia_valid) {
		return 0;
	}

	return simple_setattr(idmap, dentry, iattr);
}

static const struct inode_operations simplefs_file_iops = {
	.setattr = file_setattr,
	.getattr = simple_getattr,
};

static struct inode* make_inode(struct super_block* sb, u32 file_index)
{
	struct simplefs_sb_info* sbi = sb->s_fs_info;
	struct inode* inode;
	struct simplefs_inode_info* mi;
	loff_t fsz = (loff_t)sbi->file_size_sectors * SIMPLEFS_SECTOR_SIZE;

	inode = iget_locked(sb, SIMPLEFS_FIRST_FILE_INO + file_index);

	if (!inode) {
		return ERR_PTR(-ENOMEM);
	}

	if (!(inode->i_state & I_NEW)) {
		return inode;
	}

	mi = SIMPLEFS_I(inode);
	mi->file_index = file_index;

	inode->i_mode = S_IFREG | 0644;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_size = fsz;
	inode->i_blocks = sbi->file_size_sectors;
	simple_inode_init_ts(inode);
	inode->i_op = &simplefs_file_iops;
	inode->i_fop = &simplefs_file_fops;
	unlock_new_inode(inode);
	return inode;
}

static struct dentry* lookup(struct inode* dir, struct dentry* dentry, unsigned int flags)
{
	struct simplefs_sb_info* sbi = dir->i_sb->s_fs_info;
	long idx;
	struct inode* inode = NULL;

	if (dentry->d_name.len > sbi->max_name_len) {
		return ERR_PTR(-ENAMETOOLONG);
	}

	idx = parse_name(dentry->d_name.name, sbi->num_files);

	if (idx >= 0) {
		inode = make_inode(dir->i_sb, (u32)idx);

		if (IS_ERR(inode)) {
			return ERR_CAST(inode);
		}
	}

	return d_splice_alias(inode, dentry);
}

static int readdir(struct file* file, struct dir_context* ctx)
{
	struct inode* inode = file_inode(file);
	struct simplefs_sb_info* sbi = inode->i_sb->s_fs_info;

	if (!dir_emit_dots(file, ctx)) {
		return 0;
	}

	while (ctx->pos >= 2 && (u64)(ctx->pos - 2) < sbi->num_files) {
		u32 idx = (u32)(ctx->pos - 2);
		char name[SIMPLEFS_NAME_BUF];
		size_t nlen;

		make_name(name, sizeof(name), idx);
		nlen = strlen(name);

		if (!dir_emit(ctx, name, nlen, SIMPLEFS_FIRST_FILE_INO + idx, DT_REG)) {
			break;
		}

		ctx->pos++;
	}
	return 0;
}

static const struct file_operations simplefs_dir_fops = {
	.owner = THIS_MODULE,
	.read = generic_read_dir,
	.iterate_shared = readdir,
	.llseek = generic_file_llseek,
	.unlocked_ioctl = unlocked_ioctl,
};

static struct inode* make_root(struct super_block* sb)
{
	struct inode* inode;
	struct simplefs_inode_info* mi;

	inode = iget_locked(sb, SIMPLEFS_ROOT_INO);

	if (!inode) {
		return ERR_PTR(-ENOMEM);
	}

	if (!(inode->i_state & I_NEW)) {
		return inode;
	}

	mi = SIMPLEFS_I(inode);
	mi->file_index = 0;

	inode->i_mode = S_IFDIR | 0755;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	simple_inode_init_ts(inode);
	set_nlink(inode, 2);
	inode->i_op = &simplefs_dir_iops;
	inode->i_fop = &simplefs_dir_fops;
	unlock_new_inode(inode);
	return inode;
}

static struct inode* alloc_inode(struct super_block* sb)
{
	struct simplefs_inode_info* mi;

	mi = alloc_inode_sb(sb, simplefs_inode_cachep, GFP_NOFS);

	if (!mi) {
		return NULL;
	}

	mi->file_index = 0;
	return &mi->vfs_inode;
}

static void free_inode(struct inode* inode)
{
	kmem_cache_free(simplefs_inode_cachep, SIMPLEFS_I(inode));
}

static void put_super(struct super_block* sb)
{
	struct simplefs_sb_info* sbi = sb->s_fs_info;
	if (sbi) {
		kfree(sbi);
	}
	sb->s_fs_info = NULL;
	pr_info("SimpleFS: unmounted\n");
}

static int statfs(struct dentry* dentry, struct kstatfs* buf)
{
	struct super_block* sb = dentry->d_sb;
	struct simplefs_sb_info* sbi = sb->s_fs_info;

	buf->f_type = SIMPLEFS_MAGIC;
	buf->f_bsize = SIMPLEFS_SECTOR_SIZE;
	buf->f_blocks = sbi->total_sectors;
	buf->f_bfree = 0;
	buf->f_bavail = 0;
	buf->f_files = sbi->num_files;
	buf->f_ffree = 0;
	buf->f_namelen = sbi->max_name_len;
	return 0;
}

static int show_options(struct seq_file* m, struct dentry* root)
{
	struct simplefs_sb_info* sbi = root->d_sb->s_fs_info;
	seq_printf(m, ",sb1=%llu,sb2=%llu,file_sz=%u,num_files=%u", (u64)sbi->sb1_sector, (u64)sbi->sb2_sector, sbi->file_size_sectors, sbi->num_files);
	return 0;
}

static const struct super_operations simplefs_sops = {
	.alloc_inode = alloc_inode,
	.free_inode = free_inode,
	.put_super = put_super,
	.statfs = statfs,
	.show_options = show_options,
};

static int do_fill_super(struct super_block* sb)
{
	struct simplefs_sb_info* sbi = sb->s_fs_info;
	struct simplefs_disk_sb dsb1, dsb2;
	struct simplefs_disk_sb* good = NULL;
	struct inode* root_inode;
	sector_t total_sectors;
	int ret1, ret2;
	bool valid1, valid2;
	bool need_format = false;

	total_sectors = (sector_t)(bdev_nr_bytes(sb->s_bdev) / SIMPLEFS_SECTOR_SIZE);

	if (total_sectors < 4) {
		pr_err("SimpleFS: device too small (%llu sectors)\n",
			(u64)total_sectors);
		return -ENOSPC;
	}

	ret1 = read_sb(sb, (sector_t)sb1_offset, &dsb1);
	ret2 = read_sb(sb, (sector_t)sb2_offset, &dsb2);
	valid1 = (ret1 == 0) && sb_valid(&dsb1);
	valid2 = (ret2 == 0) && sb_valid(&dsb2);

	if (valid1) {
		good = &dsb1;

		if (!valid2) {
			pr_info("SimpleFS: SB2 invalid, recovering from SB1\n");
		}
	}
	else if (valid2) {
		good = &dsb2;
		pr_info("SimpleFS: SB1 invalid, recovering from SB2\n");
	}
	else {
		if (ret1 == 0 && ret2 == 0 && sb_blank(&dsb1) && sb_blank(&dsb2)) {
			pr_info("SimpleFS: no superblock found - formatting device\n");
			need_format = true;
		}
		else {
			pr_err("SimpleFS: both superblocks corrupted - refusing to mount\n");
			return -EUCLEAN;
		}
	}

	if (need_format) {
		ret1 = format_fs(sb, total_sectors);
		if (ret1) {
			return ret1;
		}
	}
	else {
		sbi->sb1_sector = le64_to_cpu(good->sb1_sector);
		sbi->sb2_sector = le64_to_cpu(good->sb2_sector);
		sbi->file_size_sectors = le32_to_cpu(good->file_size_sectors);
		sbi->num_files = le32_to_cpu(good->num_files);
		sbi->first_file_sector = le64_to_cpu(good->first_file_sector);
		sbi->max_name_len = le32_to_cpu(good->max_name_len);
		sbi->total_sectors = le64_to_cpu(good->total_sectors);

		if (!valid1 || !valid2) {
			persist_sb(sb, good);
		}
	}

	pr_info("SimpleFS: mounted: sb1=%llu sb2=%llu file_sz=%u num_files=%u total=%llu\n", (u64)sbi->sb1_sector, (u64)sbi->sb2_sector, sbi->file_size_sectors, sbi->num_files, sbi->total_sectors);

	root_inode = make_root(sb);

	if (IS_ERR(root_inode)) {
		return PTR_ERR(root_inode);
	}

	sb->s_root = d_make_root(root_inode);

	if (!sb->s_root) {
		return -ENOMEM;
	}

	return 0;
}

static int fill_super(struct super_block* sb, struct fs_context* fc)
{
	struct simplefs_sb_info* sbi;
	int ret;

	if (!sb_set_blocksize(sb, SIMPLEFS_SECTOR_SIZE)) {
		pr_err("SimpleFS: failed to set blocksize=%u\n", SIMPLEFS_SECTOR_SIZE);
		return -EINVAL;
	}

	sb->s_magic = SIMPLEFS_MAGIC;
	sb->s_op = &simplefs_sops;
	sb->s_time_gran = 1;
	sb->s_maxbytes = ((u64)max_file_size) * SIMPLEFS_SECTOR_SIZE;

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);

	if (!sbi) {
		return -ENOMEM;
	}

	sb->s_fs_info = sbi;

	ret = do_fill_super(sb);

	if (ret) {
		kfree(sbi);
		sb->s_fs_info = NULL;
	}

	return ret;
}

static int get_tree(struct fs_context* fc)
{
	return get_tree_bdev(fc, fill_super);
}

static void free_fc(struct fs_context* fc) { }

static const struct fs_context_operations simplefs_context_ops = {
	.get_tree = get_tree,
	.free = free_fc,
};

static int init_fs_context(struct fs_context* fc)
{
	fc->ops = &simplefs_context_ops;
	return 0;
}

static struct file_system_type simplefs_type = {
	.owner = THIS_MODULE,
	.name = SIMPLEFS_FSNAME,
	.init_fs_context = init_fs_context,
	.kill_sb = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV,
};

static void inode_once_ctor(void* p)
{
	struct simplefs_inode_info* mi = p;
	inode_init_once(&mi->vfs_inode);
}

static int __init simplefs_init(void)
{
	int ret;
	pr_info("SimpleFS: loading module (sb1=%d sb2=%d max_name=%d M=%d device=%s)\n", sb1_offset, sb2_offset, max_name_len, max_file_size, device_name);

	simplefs_inode_cachep = kmem_cache_create("simplefs_inode_cache", sizeof(struct simplefs_inode_info), 0, SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT, inode_once_ctor);

	if (!simplefs_inode_cachep) {
		return -ENOMEM;
	}

	ret = register_filesystem(&simplefs_type);

	if (ret) {
		kmem_cache_destroy(simplefs_inode_cachep);
		return ret;
	}

	pr_info("SimpleFS: filesystem '%s' registered\n", SIMPLEFS_FSNAME);
	return 0;
}

static void __exit simplefs_exit(void)
{
	unregister_filesystem(&simplefs_type);
	rcu_barrier();
	kmem_cache_destroy(simplefs_inode_cachep);
	pr_info("SimpleFS: unloaded\n");
}

module_init(simplefs_init);
module_exit(simplefs_exit);