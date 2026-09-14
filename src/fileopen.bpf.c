#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fileopen.h"

#define EPERM     1

/* Access mode bits of f_flags */
#define O_ACCMODE 0003
#define O_RDONLY  0000
#define O_WRONLY  0001
#define O_RDWR    0002

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct file_key);
	__type(value, struct rule);
} watched SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file, int ret)
{
	struct event *e;
	struct file_key key;
	struct rule *r;
	__u64 id;
	long unsigned int ino;
	dev_t dev;
	unsigned int flags, mode;

	if (ret != 0)
		return -EPERM;

	if (BPF_CORE_READ_INTO(&ino, file, f_inode, i_ino))
		return 0;
	if (BPF_CORE_READ_INTO(&dev, file, f_inode, i_sb, s_dev))
		return 0;

	__builtin_memset(&key, 0, sizeof(key));
	key.ino = ino;
	key.dev = dev;

	r = bpf_map_lookup_elem(&watched, &key);
	if (!r)
		return 0;

	if (BPF_CORE_READ_INTO(&flags, file, f_flags))
		return 0;

	mode = flags & O_ACCMODE;

	if (mode == O_RDONLY && !r->on_read)
		return 0;
	if (mode == O_WRONLY && !r->on_write)
		return 0;
	if (mode == O_RDWR && !r->on_read && !r->on_write)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->uid = bpf_get_current_uid_gid();
	e->ino = ino;
	e->dev = dev;
	e->flags = flags;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);

	return 0;
}