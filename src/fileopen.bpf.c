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
	__uint(max_entries, 1024 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct inode_key);
	__type(value, struct rule);
} watched_inode SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries,1024);
	__type(key, struct path_key);
	__type(value, struct rule);
} watched_path SEC(".maps");


struct add_mem {
	char raw_path[PATH_MAX_LEN];
	struct path_key clean_key;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct add_mem);
} array SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file, int ret)
{
	struct event *e;
	struct inode_key ikey;
	struct rule *r, *r_inode, *r_path;
	__u64 id;
	long unsigned int ino;
	dev_t dev;
	unsigned int flags, mode;
	u32 zero = 0;

	if (ret != 0)
		return -EPERM;

	if (BPF_CORE_READ_INTO(&ino, file, f_inode, i_ino))
		return 0;
	if (BPF_CORE_READ_INTO(&dev, file, f_inode, i_sb, s_dev))
		return 0;

	struct add_mem *mem = bpf_map_lookup_elem(&array, &zero);
    if (!mem)
        return 0;

    long n = bpf_d_path(&file->f_path, mem->raw_path, sizeof(mem->raw_path));
    if (n < 0) {
        return 0;
    }

    __builtin_memset(&mem->clean_key, 0, sizeof(mem->clean_key));
    bpf_probe_read_kernel_str(mem->clean_key.path, sizeof(mem->clean_key.path), mem->raw_path);

    __builtin_memset(&ikey, 0, sizeof(ikey));
    ikey.ino = ino;
    ikey.dev = dev;

    r_inode = bpf_map_lookup_elem(&watched_inode, &ikey);
    r_path = bpf_map_lookup_elem(&watched_path, &mem->clean_key);

	if (r_inode)
		r = r_inode;
	else if (r_path)
		r = r_path;
	else
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

	struct task_struct *task = bpf_get_current_task_btf();

	id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = id;
	e->uid = bpf_get_current_uid_gid();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ino = ino;
	e->dev = dev;
	e->flags = flags;
	e->inode_flag = r_inode ? 1 : 0;
	e->path_flag = r_path ? 1 : 0;

	BPF_CORE_READ_INTO(&e->ruid, task, real_cred, uid.val);
	BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);
	BPF_CORE_READ_INTO(&e->loginuid, task, loginuid.val);
	BPF_CORE_READ_INTO(&e->mnt_ns, task, nsproxy, mnt_ns, ns.inum);
	BPF_CORE_READ_INTO(&e->pid_ns, task, nsproxy, pid_ns_for_children, ns.inum);

	bpf_probe_read_kernel_str(e->path, sizeof(e->path), mem->clean_key.path);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);

	return 0;
}