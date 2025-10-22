### Dependencies

```sh
sudo apt update
sudp apt install -y clang llvm libbpf-dev libelf-dev iproute2 bpfcc-tools libc6-dev-i386
```

### Generate `vmlinux.h`

Some of the BPF files include `../vmlinux.h`, which depend on
the architecture of and the kernel installed on your machine. You have to
generate it (in this directory) for your specific configuration by running:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### Compile exercises

You should be able to compile a program with the given `Makefile`; for instance
to compile the `minimal` program:

```
make minimal
```

For the `tc_icmp_filter.bpf.c`, we do not generate an executable, but only an
object (`.o`) file. Therefore, you should run:

```
make tc_icmp_filter.o
```

### tc and qdisc

First, find your network interface with `ip addr`. Replace `wlp3s0` with your
interface in the following.
We attach a BPF program to a network interface in two steps: first, create a
`qdisc` (queuing discipline) for the interface, and then attach a BPF program
to it.

#### Create a qdisc

```sh
sudo tc qdisc add dev wlp3s0 clsact
```

The `clsact` type of qdisc corresponds to classification and action types of
program.

#### Delete a qdisc

```sh
sudo tc qdisc delete dev wlp3s0 clsact
```

#### Attach a filter to the qdisc

```sh
sudo tc filter add dev wlp3s0 ingress bpf obj icmp_filter.o sec action direct-action
```

This attaches the filter `icmp_filter` on the ingress queue. `sec action` is
the section of the program to attach, and `direct-action` is a `tc` flag, it is
not a duplicate.

#### Detach a filter from the qdisc

```sh
sudo tc filter delete dev wlp3s0 ingress
```

If you modify `icmp_filter.bpf.c` and re-attach `icmp_filter.o`, the previously
attached filter won't be removed: they just stack and are called in the order
they were attached.  You will need to detach previously attached filters every
time you need to recompile and re-attach your filter.
