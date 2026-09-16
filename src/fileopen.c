#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include "fileopen.h"
#include "fileopen.skel.h"

struct entry {
	struct inode_key ikey;
	struct path_key pkey;
	struct rule val;
};

static volatile bool stop;

static void sig_handler(int sig) { 
	stop = true; 
}

static void instructions(const char *prog)
{
	fprintf(stderr, "usage: %s [-r|-w|-rw] <file> [file...]\n\n", prog);
	fprintf(stderr, "  -r    watch reads only\n");
	fprintf(stderr, "  -w    watch writes only\n");
	fprintf(stderr, "  -rw   watch both (default)\n");
	fprintf(stderr, "  -h    show this help\n\n");
	fprintf(stderr, "Options apply to the files that follow them.\n");
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct event *e = data;
	const char *mode;
	const char *match;

	switch (e->flags & 0003) {
		case 1:  
			mode = "W";  
			break;
		case 2:  
			mode = "RW"; 
			break;
		default: 
			mode = "R";  
			break;
	}

	if (e->inode_flag && e->path_flag) {
		match = "both";
	} else if (e->inode_flag) {
		match = "ino";
	} else {
		match = "path";
	}                               
	printf("%-8u %-8u %-6s %-6s %-16s %s\n",
		e->tgid, e->uid, mode, match, e->comm, e->path);
	printf("pid=%u ppid=%u ruid=%u loginuid=%u dev=%u ino=%llu cgroup=%llu mntns=%u pidns=%u\n\n",
	    e->pid, e->ppid, e->ruid, e->loginuid, e->dev, e->ino,
	    (unsigned long long)e->cgroup_id, e->mnt_ns, e->pid_ns);
	return 0;
}

int main(int argc, char **argv)
{
	struct entry *entries = NULL;
	struct ring_buffer *rb = NULL;
	struct fileopen_bpf *skel = NULL;
	int n_entries = 0;
	int opt_r = 1;
	int opt_w = 1;
	int ret = 0;
	int err, i;

	if (argc < 2) {
		instructions(argv[0]);
		return 1;
	}

	entries = calloc(argc - 1, sizeof(*entries));
	if (!entries) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	for (i = 1; i < argc; i++) {
		struct stat sb;
		char real_path[PATH_MAX];

		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			instructions(argv[0]);
			goto cleanup;
		}
		if (strcmp(argv[i], "-r") == 0) {
			opt_r = 1;
			opt_w = 0;
			continue;
		}
		if (strcmp(argv[i], "-w") == 0) {
			opt_r = 0;
			opt_w = 1;
			continue;
		}
		if (strcmp(argv[i], "-rw") == 0 || strcmp(argv[i], "-wr") == 0) {
			opt_r = 1;
			opt_w = 1;
			continue;
		}
		if (argv[i][0] == '-') {
			fprintf(stderr, "unknown option: %s\n", argv[i]);
			instructions(argv[0]);
			ret = 1;
			goto cleanup;
		}

		if (!realpath(argv[i], real_path)) {
			fprintf(stderr, "%s: %s\n", argv[i], strerror(errno));
			continue;
		}

		if (strlen(real_path) >= PATH_MAX_LEN) {
			fprintf(stderr, "%s: path too long\n", real_path);
			continue;
		}

		if (stat(real_path, &sb) == -1) {
			fprintf(stderr, "%s: %s\n", real_path, strerror(errno));
			continue;
		}

		entries[n_entries].ikey.ino = sb.st_ino;
		entries[n_entries].ikey.dev = (major(sb.st_dev) << 20) | minor(sb.st_dev);
		entries[n_entries].val.on_read = opt_r;
		entries[n_entries].val.on_write = opt_w;
		strncpy(entries[n_entries].pkey.path, real_path, PATH_MAX_LEN - 1);
		n_entries++;
	}

	if (n_entries == 0) {
		fprintf(stderr, "no valid files to watch\n");
		ret = 1;
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = fileopen_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open and load BPF skeleton\n");
		ret = 1;
		goto cleanup;
	}

	for (i = 0; i < n_entries; i++) {
		err = bpf_map__update_elem(skel->maps.watched_inode,
					   &entries[i].ikey, sizeof(entries[i].ikey),
					   &entries[i].val, sizeof(entries[i].val),
					   BPF_ANY);
		if (err) {
			fprintf(stderr, "failed to add %s: %d\n", entries[i].pkey.path, err);
			ret = 1;
			goto cleanup;
		}

		err = bpf_map__update_elem(skel->maps.watched_path,
					   &entries[i].pkey, sizeof(entries[i].pkey),
					   &entries[i].val, sizeof(entries[i].val),
					   BPF_ANY);
		if (err) {
			fprintf(stderr, "failed to add %s: %d\n", entries[i].pkey.path, err);
			ret = 1;
			goto cleanup;
		}

		printf("watching %s (ino=%llu dev=%u, %s%s)\n",
		       entries[i].pkey.path,
		       (unsigned long long)entries[i].ikey.ino,
		       entries[i].ikey.dev,
		       entries[i].val.on_read ? "r" : "",
		       entries[i].val.on_write ? "w" : "");
	}

	err = fileopen_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF skeleton: %d\n", err);
		ret = 1;
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		ret = 1;
		goto cleanup;
	}

	printf("%-8s %-8s %-6s %-6s %-16s %s\n",
		"PID", "UID", "MODE", "MATCH", "COMM", "FILE");

	while (!stop) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "polling error: %d\n", err);
			ret = 1;
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	fileopen_bpf__destroy(skel);
	free(entries);
	return ret;
}