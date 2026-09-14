#ifndef __FILEOPEN_H
#define __FILEOPEN_H

#define TASK_COMM_LEN 16

struct event {
	__u64 ino;
	__u32 dev;
	__u32 pid;
	__u32 uid;
	__u32 flags;
	char comm[TASK_COMM_LEN];
};

struct file_key {
	__u64 ino;
	__u32 dev;
};

struct rule {
	__u8 on_read;
	__u8 on_write;
};

#endif
