# ebpf-thesis

An eBPF program that traces `open()` calls on a configurable set of files, using the LSM `file_open` hook.

Files are identified by the pair (inode, device) and their absolute path. Paths are resolved in user space using `realpath()` and `stat()` and stored in two separate BPF hash maps.

## Requirements

- Kernel with BTF (`/sys/kernel/btf/vmlinux`)
- `bpf` among the active LSMs
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

    watching /etc/shadow (ino=1796 dev=265289729, rw)

    PID      UID      MODE   DEV        INO          COMM
    15469    0        R      265289729  1796         cat   