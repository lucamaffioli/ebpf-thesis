# ebpf-thesis

An eBPF program that traces access to a configurable set of files, using the LSM hooks `file_open`, `path_unlink`, `path_rename` and `path_link`.

Files are identified by the pair (inode, device) and their absolute path. Paths are resolved in user space using `realpath()` and `stat()` and stored in two separate BPF hash maps: one from path to rule, the other from (inode, device) back to the path it belongs to. The three `path_*` hooks keep the two in agreement, so that the watched file is still followed when it is reached under another name, and the watched name is followed when a different file takes its place. Since a path is relative to the root of the process that produced it, each rule also records the mount namespace it was defined in, and path comparisons only apply to operations coming from that namespace.

## Requirements

- Kernel with BTF (`/sys/kernel/btf/vmlinux`)
- `bpf` among the active LSMs
- `CONFIG_SECURITY_PATH=y`, required by the `path_*` hooks
- clang, make, bpftool, libelf-dev, zlib1g-dev
- Root privileges to run

## Build

libbpf is included as a git submodule and built statically, so clone with:

    git clone --recurse-submodules https://github.com/lucamaffioli/ebpf-thesis.git

Generate `vmlinux.h` for your kernel:

    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

Then build:

    make

## Usage

    sudo ./fileopen [-r|-w|-rw] <file> [file...]

Options apply to the files that follow them:

- `-r` report reads only
- `-w` report writes only
- `-rw` report both (default)

### Examples

Watch all accesses to `/etc/shadow`:

    sudo ./fileopen /etc/shadow

Watch reads of `/etc/shadow` and writes to `/etc/sudoers`:

    sudo ./fileopen -r /etc/shadow -w /etc/sudoers

Output:

    watching /root/tests/prova.txt (ino=1060133 dev=265289729 mntns=4026531832, r w)

    [2026-09-23T16:22:14.974] OPEN   | both | R  | comm="cat         " path="/root/tests/prova.txt"
    pid=6019 ppid=5999 uid=0 ruid=0 loginuid=1000 dev=265289729 ino=1060133 cgroup=7935 mntns=4026531832 pidns=4026531836

The third field says how the event matched the rule: `ino` by file, `path` by name, `both` when they agree. Four markers can follow:

- `[ALIAS_ACCESS]` the watched file was reached under another name
- `[replaced]` the watched name now resolves to a different file, and monitoring follows the name
- `[PATH_COLLISION]` another mount namespace used the same path string for a different file
- `[ns=N]` the operation came from a mount namespace other than the one of the rule

The program only observes, it never denies an operation. It traces the opening of a file, so a descriptor that was already open produces no events, and operations that do not go through `open()` are not reported.