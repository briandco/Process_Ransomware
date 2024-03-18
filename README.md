# sudo watcher
The purpose of this code is to monitor and log information about processes related to the "sudo" command. It tracks the PIDs of processes with the name "sudo", PIDs of processes forked by "sudo" processes, and the parent-child relationship between these processes.

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
