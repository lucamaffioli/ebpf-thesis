#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/libbpf.h>
#include "fileopen.h"
#include "fileopen.skel.h"

struct entry {
	struct file_key key;
	struct rule val;
	const char *path;
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

	printf("%-8u %-8u %-8s %-10u %-12llu %-16s\n", e->pid, e->uid, mode, e->dev, e->ino, e->comm);
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

		if (stat(argv[i], &sb) == -1) {
			fprintf(stderr, "%s: %s\n", argv[i], strerror(errno));
			continue;
		}

		entries[n_entries].key.ino = sb.st_ino;
		entries[n_entries].key.dev = (major(sb.st_dev) << 20) | minor(sb.st_dev);
		entries[n_entries].val.on_read = opt_r;
		entries[n_entries].val.on_write = opt_w;
		entries[n_entries].path = argv[i];
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
		err = bpf_map__update_elem(skel->maps.watched,
					   &entries[i].key, sizeof(entries[i].key),
					   &entries[i].val, sizeof(entries[i].val),
					   BPF_ANY);
		if (err) {
			fprintf(stderr, "failed to add %s: %d\n", entries[i].path, err);
			ret = 1;
			goto cleanup;
		}

		printf("watching %s (ino=%llu dev=%u, %s%s)\n",
		       entries[i].path,
		       (unsigned long long)entries[i].key.ino,
		       entries[i].key.dev,
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

	printf("%-8s %-8s %-8s %-10s %-12s %-16s\n", "PID", "UID", "MODE", "DEV", "INO", "COMM");

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