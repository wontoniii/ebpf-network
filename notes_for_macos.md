# Running eBPF Experiments on macOS with Docker

This guide provides two approaches for running eBPF experiments in Docker on macOS. 

**⚠️ IMPORTANT: These instructions have NOT been tested and are provided as-is. Please report any issues or improvements.**

## Prerequisites

- Docker Desktop for Mac installed and running
- Basic familiarity with Docker and command line

## The Challenge

eBPF requires direct access to the Linux kernel. On macOS, Docker Desktop runs a Linux VM, so eBPF programs will run against that VM's kernel, not the macOS kernel.

## Option 1: Using a Pre-built Image (Recommended)

This is the simplest approach using an existing eBPF development image.
```bash
docker run -it --rm \
  --privileged \
  --pid=host \
  --cgroupns=host \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  -v $(pwd):/workspace \
  -w /workspace \
  cilium/ebpf-builder
```

## Option 2: Custom Development Container

Build your own container with all necessary eBPF tools.

### Create a Dockerfile
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    libbpf-tools \
    bpftool \
    linux-tools-generic \
    linux-headers-generic \
    build-essential \
    git \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
```

### Build and Run
```bash
# Build the image
docker build -t ebpf-dev .

# Run the container
docker run -it --rm \
  --privileged \
  --pid=host \
  --cgroupns=host \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  -v $(pwd):/workspace \
  ebpf-dev
```

## Required Flags Explained

- `--privileged`: Grants full access to kernel features
- `--pid=host`: Shares PID namespace with the host VM
- `--cgroupns=host`: Shares cgroup namespace with the host VM
- `-v /sys/kernel/debug`: Provides access to kernel debug filesystem
- `-v $(pwd):/workspace`: Mounts your current directory into the container

## Verifying eBPF Works

Once inside the container, test that eBPF is accessible:
```bash
# List loaded eBPF programs
bpftool prog list

# Check tracing capabilities
ls /sys/kernel/debug/tracing/

# Check kernel version (5.x+ recommended)
uname -r
```

## Known Limitations

- eBPF programs run against the Docker Desktop VM kernel, not macOS
- Some eBPF features may be unavailable depending on the VM's kernel version
- Network-related eBPF programs may behave differently than on native Linux

## Troubleshooting

If you encounter issues:
1. Ensure Docker Desktop is running and up to date
2. Check the VM's kernel version supports required eBPF features
3. Verify all required flags are present when running the container
4. Consider using a native Linux environment (VM or dual-boot) for full eBPF functionality

## Contributing

If you test these instructions and find issues or improvements, please submit a pull request or open an issue.