#ifndef _SIMPLEFS_H
#define _SIMPLEFS_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>

#else
#include <linux/types.h>
#include <sys/ioctl.h>
#endif

#define SIMPLEFS_MAGIC 0x53494D50u
#define SIMPLEFS_SECTOR_SIZE 512u
#define SIMPLEFS_HASH_SIZE 32u
#define SIMPLEFS_NAME_BUF 64u
#define SIMPLEFS_NAME_PREFIX "file_"
#define SIMPLEFS_FSNAME "simplefs"
#define SIMPLEFS_DEFAULT_SB2_OFFSET 1024u
#define SIMPLEFS_DEFAULT_MAX_NAME 32u
#define SIMPLEFS_DEFAULT_MAX_FILESZ 8u
#define SIMPLEFS_IOC_MAGIC 'S'

struct simplefs_disk_sb {
	__le32 magic;
	__le32 file_size_sectors;
	__le32 max_name_len;
	__le32 num_files;
	__le64 sb1_sector;
	__le64 sb2_sector;
	__le64 first_file_sector;
	__le64 total_sectors;
	__u8 hash[SIMPLEFS_HASH_SIZE];
} __attribute__((packed));

struct simplefs_file_hash {
	__u32 file_index;
	char name[SIMPLEFS_NAME_BUF];
	__u8 hash[SIMPLEFS_HASH_SIZE];
};

struct simplefs_hash_list {
	__u32 capacity;
	__u32 count;
	__u32 copied;
	__u32 _pad;
	__u64 hashes_ptr;
};

struct simplefs_sector_map {
	__u32 file_index;
	__u32 _pad;
	char name[SIMPLEFS_NAME_BUF];
	__u64 first_sector;
	__u64 num_sectors;
};

#define SIMPLEFS_IOC_ZERO_ALL _IO(SIMPLEFS_IOC_MAGIC, 1)
#define SIMPLEFS_IOC_ERASE _IO(SIMPLEFS_IOC_MAGIC, 2)
#define SIMPLEFS_IOC_GET_HASHES _IOWR(SIMPLEFS_IOC_MAGIC, 3, struct simplefs_hash_list)
#define SIMPLEFS_IOC_GET_MAP _IOWR(SIMPLEFS_IOC_MAGIC, 4, struct simplefs_sector_map)

#endif
