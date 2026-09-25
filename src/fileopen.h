#ifndef __FILEOPEN_H
#define __FILEOPEN_H

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN 256
#define NAME_MAX_LEN 64

#define HK_OPEN   1
#define HK_UNLINK 2
#define HK_RENAME 3
#define HK_LINK   4

struct event {
	__u64 ts;
	__u64 ino;
	__u64 cgroup_id;
	__u32 dev;
	__u32 uid; 
	__u32 ruid;
	__u32 loginuid;
	__u32 tgid;
	__u32 pid; 
	__u32 ppid;
	__u32 mnt_ns;
	__u32 pid_ns;
	__u32 flags;
	__u32 inode_flag;
	__u32 path_flag;
	__u32 inode_changed;
	__u32 hook;
	__u32 foreign_ns;
	char comm[TASK_COMM_LEN];
	char path[PATH_MAX_LEN];
	char watched[PATH_MAX_LEN];
	char other[PATH_MAX_LEN];
};

struct inode_key {
	__u64 ino;
	__u32 dev;
};

struct path_key {
	char path[PATH_MAX_LEN];
};

struct rule {
	__u8 on_read;
	__u8 on_write;
	struct inode_key current_ikey;
	__u32 mnt_ns;
};

#endif
