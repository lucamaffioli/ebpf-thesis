#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fileopen.h"

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
	__type(value, struct path_key);
} resolved_inode SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries,1024);
	__type(key, struct path_key);
	__type(value, struct rule);
} watched_path SEC(".maps");


struct add_mem {
	char raw_path[PATH_MAX_LEN];
	struct path_key clean_key;
	char dir_path[PATH_MAX_LEN];
	struct path_key dest_key;
	struct path_key src_key;
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
	struct rule *r;
	int by_inode = 0, by_path = 0, inode_changed = 0, same_ns = 0;
	__u64 id;
	long n;
	long unsigned int ino;
	dev_t dev;
	unsigned int flags, mode;
	u32 zero = 0;
	__u32 cur_mnt_ns = 0;
	struct path_key *cached_path;
	struct task_struct *task;
	struct add_mem *mem;

	if (ret < 0)
		return ret;

	if (BPF_CORE_READ_INTO(&ino, file, f_inode, i_ino))
		return 0;
	if (BPF_CORE_READ_INTO(&dev, file, f_inode, i_sb, s_dev))
		return 0;

	mem = bpf_map_lookup_elem(&array, &zero);
    if (!mem)
        return 0;

    n = bpf_path_d_path(&file->f_path, mem->raw_path, sizeof(mem->raw_path));
    if (n < 0) {
        return 0;
    }

    __builtin_memset(&mem->clean_key, 0, sizeof(mem->clean_key));
    bpf_probe_read_kernel_str(mem->clean_key.path, sizeof(mem->clean_key.path), mem->raw_path);

    __builtin_memset(&ikey, 0, sizeof(ikey));
    ikey.ino = ino;
    ikey.dev = dev;

	r = bpf_map_lookup_elem(&watched_path, &mem->clean_key);
	if (r) {
		by_path = 1;
	}

	cached_path = bpf_map_lookup_elem(&resolved_inode, &ikey);
	if (cached_path) {
		by_inode = 1;
		if (!r) {
			r = bpf_map_lookup_elem(&watched_path, cached_path);
		}
	}

	if (!r) {
		return 0;
	}

	task = bpf_get_current_task_btf();
	BPF_CORE_READ_INTO(&cur_mnt_ns, task, nsproxy, mnt_ns, ns.inum);
	same_ns = (cur_mnt_ns == r->mnt_ns);

	if (by_path && !by_inode && same_ns) {
		inode_changed = 1;
		bpf_map_delete_elem(&resolved_inode, &r->current_ikey);
		bpf_map_update_elem(&resolved_inode, &ikey, &mem->clean_key, BPF_ANY);
		r->current_ikey = ikey;
	}

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


	e->ts = bpf_ktime_get_tai_ns();
	
	id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = id;
	e->uid = bpf_get_current_uid_gid();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ino = ino;
	e->dev = dev;
	e->flags = flags;
	e->inode_changed = inode_changed;
	e->inode_flag = by_inode;
	e->path_flag = by_path;
	e->hook = HK_OPEN;
	e->foreign_ns = !same_ns;

	BPF_CORE_READ_INTO(&e->ruid, task, real_cred, uid.val);
	BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);
	BPF_CORE_READ_INTO(&e->loginuid, task, loginuid.val);
	BPF_CORE_READ_INTO(&e->mnt_ns, task, nsproxy, mnt_ns, ns.inum);
	BPF_CORE_READ_INTO(&e->pid_ns, task, nsproxy, pid_ns_for_children, ns.inum);

	bpf_probe_read_kernel_str(e->path, sizeof(e->path), mem->clean_key.path);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	if (by_path)
		bpf_probe_read_kernel_str(e->watched, sizeof(e->watched), mem->clean_key.path);
	else
		bpf_probe_read_kernel_str(e->watched, sizeof(e->watched), cached_path->path);

	bpf_ringbuf_submit(e, 0);

	return 0;
}


static __always_inline int compose_path(struct path_key *dst, struct path *dir, struct dentry *dentry, char *buf)
{
	const unsigned char *name;
	unsigned int name_len;
	long n;
	__u32 off;

	n = bpf_path_d_path(dir, buf, PATH_MAX_LEN);
	if (n <= 0 || n > PATH_MAX_LEN - NAME_MAX_LEN) {
		return -1;
	}
		
	off = n - 1;

	if (off > 1) {
		buf[off++] = '/';
	}

	name = BPF_CORE_READ(dentry, d_name.name);
	if (!name) {
		return -1;
	}

	name_len = BPF_CORE_READ(dentry, d_name.len);
	if (name_len >= NAME_MAX_LEN) {
		return -1;
	}

	if (bpf_probe_read_kernel_str(&buf[off], NAME_MAX_LEN, name) < 0) {
		return -1;
	}

	__builtin_memset(dst, 0, sizeof(*dst));
	bpf_probe_read_kernel_str(dst->path, sizeof(dst->path), buf);

	return 0;
}


SEC("lsm/path_unlink")
int BPF_PROG(handle_path_unlink, struct path *dir, struct dentry *dentry, int ret)
{
	struct event *e;
	struct inode_key ikey;
	struct path_key *cached_path;
	struct task_struct *task;
	__u64 id;
	__u32 cur_mnt_ns = 0;
	long unsigned int ino;
	dev_t dev;
	struct rule *r;
	struct add_mem *mem;
	u32 zero = 0;
	unsigned int nlink = 0;
	int composed, drop_binding, last_link, same_ns = 0;

	if (ret < 0)
		return ret;

	if (BPF_CORE_READ_INTO(&ino, dentry, d_inode, i_ino))
		return 0;
	if (BPF_CORE_READ_INTO(&dev, dentry, d_inode, i_sb, s_dev))
		return 0;

	__builtin_memset(&ikey, 0, sizeof(ikey));
	ikey.ino = ino;
	ikey.dev = dev;

	cached_path = bpf_map_lookup_elem(&resolved_inode, &ikey);
	if (!cached_path) {
		return 0;
	}

	r = bpf_map_lookup_elem(&watched_path, cached_path);
	if (!r) {
		return 0;
	}

	task = bpf_get_current_task_btf();
	BPF_CORE_READ_INTO(&cur_mnt_ns, task, nsproxy, mnt_ns, ns.inum);
	same_ns = (cur_mnt_ns == r->mnt_ns);

	mem = bpf_map_lookup_elem(&array, &zero);
	if (!mem) {
		return 0;
	}

	BPF_CORE_READ_INTO(&nlink, dentry, d_inode, i_nlink);
	last_link = (nlink <= 1);

	composed = (compose_path(&mem->dest_key, dir, dentry, mem->dir_path) == 0);

	if (last_link) {
		drop_binding = 1;
	} else if (!same_ns) {
		drop_binding = 0;
	} else if (composed) {
		drop_binding = (__builtin_memcmp(&mem->dest_key, cached_path, sizeof(mem->dest_key)) == 0);
	} else {
		drop_binding = 1;
	}

	if (drop_binding) {
		__builtin_memset(&r->current_ikey, 0, sizeof(r->current_ikey));
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	e->ts = bpf_ktime_get_tai_ns();
	e->hook = HK_UNLINK;

	id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = id;
	e->uid = bpf_get_current_uid_gid();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ino = ino;
	e->dev = dev;
	e->flags = nlink;
	e->inode_flag = 1;
	e->path_flag = 0;
	e->inode_changed = 0;
	e->foreign_ns = !same_ns;

	BPF_CORE_READ_INTO(&e->ruid, task, real_cred, uid.val);
	BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);
	BPF_CORE_READ_INTO(&e->loginuid, task, loginuid.val);
	BPF_CORE_READ_INTO(&e->mnt_ns, task, nsproxy, mnt_ns, ns.inum);
	BPF_CORE_READ_INTO(&e->pid_ns, task, nsproxy, pid_ns_for_children, ns.inum);

	bpf_probe_read_kernel_str(e->watched, sizeof(e->watched), cached_path->path);
	e->path[0] = '\0';

	if (composed) {
		bpf_probe_read_kernel_str(e->other, sizeof(e->other), mem->dest_key.path);
	} else {
		e->other[0] = '\0';
	}
		
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);

	if (last_link) {
		bpf_map_delete_elem(&resolved_inode, &ikey);
	}

	return 0;
}


SEC("lsm/path_link")
int BPF_PROG(handle_path_link, struct dentry *old_dentry, struct path *new_dir, struct dentry *new_dentry, int ret)
{
	struct event *e;
	struct inode_key ikey;
	struct path_key *cached_path;
	struct add_mem *mem;
	struct task_struct *task;
	struct rule *r_src = NULL;
	struct rule *r_dest;
	__u64 id;
	__u32 cur_mnt_ns = 0;
	long unsigned int ino;
	dev_t dev;
	u32 zero = 0;
	int src_watched = 0, dest_watched = 0, composed, same_ns = 0;

	if (ret < 0)
		return ret;

	if (BPF_CORE_READ_INTO(&ino, old_dentry, d_inode, i_ino))
		return 0;
	if (BPF_CORE_READ_INTO(&dev, old_dentry, d_inode, i_sb, s_dev))
		return 0;

	__builtin_memset(&ikey, 0, sizeof(ikey));
	ikey.ino = ino;
	ikey.dev = dev;

	mem = bpf_map_lookup_elem(&array, &zero);
	if (!mem) {
		return 0;
	}

	task = bpf_get_current_task_btf();
	BPF_CORE_READ_INTO(&cur_mnt_ns, task, nsproxy, mnt_ns, ns.inum);

	cached_path = bpf_map_lookup_elem(&resolved_inode, &ikey);
	if (cached_path) {
		r_src = bpf_map_lookup_elem(&watched_path, cached_path);
		if (r_src) {
			src_watched = 1;
		}
	}

	composed = (compose_path(&mem->dest_key, new_dir, new_dentry, mem->dir_path) == 0);
	if (composed) {
		r_dest = bpf_map_lookup_elem(&watched_path, &mem->dest_key);
		if (r_dest && cur_mnt_ns == r_dest->mnt_ns) {
			dest_watched = 1;
		}
	}

	if (!src_watched && !dest_watched) {
		return 0;
	}

	if (r_src) {
		same_ns = (cur_mnt_ns == r_src->mnt_ns);
	} else {
		same_ns = 1;
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) 
		return 0;

	e->ts = bpf_ktime_get_tai_ns();
	e->hook = HK_LINK;

	id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = id;
	e->uid = bpf_get_current_uid_gid();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ino = ino;
	e->dev = dev;
	e->flags = 0;
	e->inode_flag = src_watched;
	e->path_flag = dest_watched;
	e->inode_changed = 0;
	e->foreign_ns = !same_ns;

	BPF_CORE_READ_INTO(&e->ruid, task, real_cred, uid.val);
	BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);
	BPF_CORE_READ_INTO(&e->loginuid, task, loginuid.val);
	BPF_CORE_READ_INTO(&e->mnt_ns, task, nsproxy, mnt_ns, ns.inum);
	BPF_CORE_READ_INTO(&e->pid_ns, task, nsproxy, pid_ns_for_children, ns.inum);

	if (composed) {
		bpf_probe_read_kernel_str(e->other, sizeof(e->other), mem->dest_key.path);
	} else {
		e->other[0] = '\0';
	}
	if (src_watched && cached_path) {
		bpf_probe_read_kernel_str(e->watched, sizeof(e->watched), cached_path->path);
	} else {
		bpf_probe_read_kernel_str(e->watched, sizeof(e->watched), mem->dest_key.path);
	}
		
	e->path[0] = '\0';

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);

	return 0;
}


SEC("lsm/path_rename")
int BPF_PROG(handle_path_rename, struct path *old_dir, struct dentry *old_dentry, struct path *new_dir, struct dentry *new_dentry, unsigned int flags, int ret)
{
	struct event *e;
	struct inode_key ikey;
	struct inode_key dest_ikey;
	struct inode_key old_dest_ikey;
	struct path_key *cached_path;
	struct path_key *dest_cached = NULL;
	struct add_mem *mem;
	struct task_struct *task;
	struct inode *dest_inode;
	struct rule *r_src = NULL;
	struct rule *r_dest = NULL;
	struct rule *r_dobj = NULL;
	__u64 id;
	__u32 cur_mnt_ns = 0;
	long unsigned int ino;
	dev_t dev;
	u32 zero = 0;
	unsigned int dest_nlink = 0;
	int src_watched = 0, dest_watched = 0, dest_obj_watched = 0;
	int src_composed, dest_composed;
	int same_ns = 0, drop_dest_obj = 0, del_old_dest = 0, del_dest_obj = 0;

	if (ret < 0)
		return ret;

	if (BPF_CORE_READ_INTO(&ino, old_dentry, d_inode, i_ino))
		return 0;
	if (BPF_CORE_READ_INTO(&dev, old_dentry, d_inode, i_sb, s_dev))
		return 0;

	mem = bpf_map_lookup_elem(&array, &zero);
	if (!mem) {
		return 0;
	}

	task = bpf_get_current_task_btf();
	BPF_CORE_READ_INTO(&cur_mnt_ns, task, nsproxy, mnt_ns, ns.inum);

	__builtin_memset(&ikey, 0, sizeof(ikey));
	ikey.ino = ino;
	ikey.dev = dev;

	cached_path = bpf_map_lookup_elem(&resolved_inode, &ikey);
	if (cached_path) {
		r_src = bpf_map_lookup_elem(&watched_path, cached_path);
		if (r_src) {
			src_watched = 1;
		}
	}

	dest_composed = (compose_path(&mem->dest_key, new_dir, new_dentry, mem->dir_path) == 0);
	if (dest_composed) {
		r_dest = bpf_map_lookup_elem(&watched_path, &mem->dest_key);
		if (r_dest && cur_mnt_ns == r_dest->mnt_ns) {
			dest_watched = 1;
		}
	}

	dest_inode = BPF_CORE_READ(new_dentry, d_inode);
	if (dest_inode) {
		__builtin_memset(&dest_ikey, 0, sizeof(dest_ikey));
		dest_ikey.ino = BPF_CORE_READ(dest_inode, i_ino);
		dest_ikey.dev = BPF_CORE_READ(dest_inode, i_sb, s_dev);

		dest_cached = bpf_map_lookup_elem(&resolved_inode, &dest_ikey);
		if (dest_cached) {
			dest_obj_watched = 1;
			r_dobj = bpf_map_lookup_elem(&watched_path, dest_cached);
			dest_nlink = BPF_CORE_READ(dest_inode, i_nlink);
		}
	}

	if (!src_watched && !dest_watched && !dest_obj_watched) {
		return 0;
	}

	src_composed = (compose_path(&mem->src_key, old_dir, old_dentry, mem->dir_path) == 0);

	if (r_src) {
		same_ns = (cur_mnt_ns == r_src->mnt_ns);
	} else if (r_dobj) {
		same_ns = (cur_mnt_ns == r_dobj->mnt_ns);
	} else {
		same_ns = 1;
	}

	if (src_watched && same_ns && src_composed) {
		if (__builtin_memcmp(&mem->src_key, cached_path, sizeof(mem->src_key)) == 0) {
			__builtin_memset(&r_src->current_ikey, 0, sizeof(r_src->current_ikey));
		}
	}

	if (dest_watched && r_dest) {
		old_dest_ikey = r_dest->current_ikey;
		del_old_dest = 1;
		__builtin_memset(&r_dest->current_ikey, 0, sizeof(r_dest->current_ikey));
	}

	if (dest_obj_watched) {
		if (dest_nlink <= 1) {
			drop_dest_obj = 1;
			del_dest_obj = 1;
		} else if (!r_dobj || cur_mnt_ns != r_dobj->mnt_ns) {
			drop_dest_obj = 0;
		} else if (dest_composed) {
			drop_dest_obj = (__builtin_memcmp(&mem->dest_key, dest_cached, sizeof(mem->dest_key)) == 0);
		} else {
			drop_dest_obj = 1;
		}

		if (drop_dest_obj && r_dobj) {
			__builtin_memset(&r_dobj->current_ikey, 0, sizeof(r_dobj->current_ikey));
		}
	}

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	e->ts = bpf_ktime_get_tai_ns();
	e->hook = HK_RENAME;

	id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = id;
	e->uid = bpf_get_current_uid_gid();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ino = ino;
	e->dev = dev;
	e->flags = flags;
	e->inode_flag = src_watched || dest_obj_watched;
	e->path_flag = dest_watched;
	e->inode_changed = 0;
	e->foreign_ns = !same_ns;

	BPF_CORE_READ_INTO(&e->ruid, task, real_cred, uid.val);
	BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);
	BPF_CORE_READ_INTO(&e->loginuid, task, loginuid.val);
	BPF_CORE_READ_INTO(&e->mnt_ns, task, nsproxy, mnt_ns, ns.inum);
	BPF_CORE_READ_INTO(&e->pid_ns, task, nsproxy, pid_ns_for_children, ns.inum);

	if (dest_composed) {
		bpf_probe_read_kernel_str(e->other, sizeof(e->other), mem->dest_key.path);
	} else {
		e->other[0] = '\0';
	}

	if (src_composed) {
		bpf_probe_read_kernel_str(e->path, sizeof(e->path), mem->src_key.path);
	} else {
		e->path[0] = '\0';
	}

	if (src_watched && cached_path) {
		bpf_probe_read_kernel_str(e->watched, sizeof(e->watched), cached_path->path);
	} else if (dest_obj_watched && dest_cached) {
		bpf_probe_read_kernel_str(e->watched, sizeof(e->watched), dest_cached->path);
	} else {
		bpf_probe_read_kernel_str(e->watched, sizeof(e->watched), mem->dest_key.path);
	}

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);

	if (del_old_dest) {
		bpf_map_delete_elem(&resolved_inode, &old_dest_ikey);
	}

	if (del_dest_obj) {
		bpf_map_delete_elem(&resolved_inode, &dest_ikey);
	}

	return 0;
}
