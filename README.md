# Introduction to kernel extensions with eBPF

## Introduction

The goal of this lab session is twofold:
1. Discover some general eBPF programming concepts
2. Discover how to use eBPF for Network programming

To do so, we will build two small eBPF applications: a first one that measures the time spent in the `write` system call, and a second one that tracks incoming ICMP (`ping`) packets and filters them.

### Lab code

The repository contains:
- One code directory, in `exercises` with the code files you will have to complete.
- The eBPF introduction slides inside the `slides` folder.

The `exercises` directory contains a `README.md` that you should read before trying to compile and run the exercises.

## First steps in eBPF programming

The goal of this section is to discover some core concepts of eBPF programming by studying a tracer which monitors the time spent in the `write` system call. The studied concepts are:
- Structure of an eBPF application
- Attaching an eBPF program to a hook
- Storing and accessing data from eBPF maps
- Communicating with the user space from eBPF programs

### Compile and run your first eBPF program

First, let's try to understand and run the `minimal` application, which is an example program shipped with the `libbpf` library. Its purpose is to instrument the `sys_enter_write` tracepoint, which is triggered at the beginning of any write operation.

The application is made of two files: a BPF file `minimal.bpf.c` and a C file `minimal.c`. The BPF file usually contains the definitions of the BPF programs which attach to kernel hooks, and also the declaration of BPF data structures used in the application (none in `minimal`).

Have a look at the BPF file, and try to understand what it does. You can also have a look at the C file, but its only purpose here is to load the BPF program in the kernel and attach it to the hook, which is the tracepoint `sys_enter_write`.

Now let's run it! First, compile the application with `make minimal`. Then, run it as root: `sudo ./minimal`. The `bpf_printk` macro in the BPF file writes to the trace pipe, so open it as asked by the application. You should see some movement!

### Measuring the time spent in the syscall

For now, our application just writes a message in the trace pipe when the write system call starts. Next, we will add a second BPF program which we will hook to the exit of the write system call, and use it to measure the time spent in the system call.

There are several steps to perform:
1. Take a timestamp when entering the write system call
2. Write this timestamp *somewhere*
3. Take a timestamp when exiting the write system call
4. Fetch the entry timestamp from *somewhere* and compute the difference between the two timestamps
5. Write the result in the trace pipe

What I called *somewhere* will be a BPF map: a data structure provided by BPF to store temporary data directly in the kernel. There exist many types of maps, but for our use case we need a hash map: you can store a value behind a key and fetch the value later if you have the same key.

Have a look at the `hashmap` BPF code: I wrote for you the declaration of the hash map. You can see that the key is an integer, which will store a PID. The PID is a unique identifier for a process: if a process enters the write system call, the same process will leave it later, therefore the PID can be used to match our entry and exit programs, and thus compute the time spent in the system call.

The type of the value items of the hash map is a `struct event_to_match`, a structure defined in `hashmap.h`, which stores basic information about the execution: a timestamp and a file descriptor, to identify which file the current process is writing to.

I also wrote the code for the program hooked at `sys_enter_write`: it gets the current PID, a timestamp, the file descriptor, and writes the two latter in the hash map using the first as the key.

Now is your turn: write the code of the program hooked to the exit tracepoint. You should re-use most of the code of the enter program, plus the following:

```c
struct event_to_match *e = bpf_map_lookup_elem(&match_map, &pid);
```

This will look in the `match_map` with the PID as the key, and return a pointer to a structure containing the data we filled earlier in the entry program.

Don't forget to write the result to the trace pipe using `bpf_printk` so you can see your application at work!

### Better communication with the user space

Our application has room for improvement. For instance, reading the trace pipe is not convenient at all, and is actually a debugging mechanism for developers, it should not be used in real-life BPF applications. We can do better when we know that *BPF maps can be accessed from the user space*.

Therefore, we will use a new type of map which is specifically designed for efficient message passing from the kernel to the user space, the BPF ring buffer. The idea is simple: the BPF programs write data in the ring buffer, which is basically circular queue, and the user space side of our application continuously polls the ring buffer to read the fresh data as it arrives.

Have a look at the `ringbuf` exercise. In the BPF file, I added the declaration of the ring buffer, and in the header `ringbuf.h` there is a structure that is used to contain the events we send into it. I also edited the program hooked at the exit of the write system call as the usage of the ring buffer is a bit particular: first you reserve space in it, then you fill the allocated space with your data, and finally you submit it. I let you fill the `rb_event` that will be sent to the user space.

Then, have a look at the C file of the application. The ring buffer needs to be polled, which is done at the end of `main()`. You will have to complete the `handle_event` function, which is called on every event found in the ring buffer while polling it. Make it print the information you read from the ring buffer to stdout.

A quick note: for the previous examples, we were watching only the writes triggered from our user space program PID, from the loop printing dots at the end of the `main()` function of `minimal.c` and `hashmap.c`. However, our `ringbuf` application will now be performing a write operation for every event read in the ring buffer, which happens for every write operation from our application (...). This loop might break your application; in order to avoid that, I changed the BPF code in `ringbuf.bpf.c` so that it now monitors write operations from *every PID but the one of our user space program*. You will see that this is a lot.

### (Bonus) Further improvement

This part proposes further improvement to our tracer, but keep it for after you finish the remaining of the lab. It is much more free and no extra code is provided.

As you noticed, there is a lot of write operations occuring in the kernel. What I suggest is to declare a second hash map, let's say `stats_map`, which will store for each file descriptor (key) a structure (value) containing some per-file statistics that your BPF program will compute directly in the kernel. For instance, you can compute the number of occurrences, the total time spent in the syscall, the average time spent there, and you can even have fun collecting more data, like the size of the read opreations performed.

Then you will update this hash map every time a write operation ends, once you collected fresh data.

Finally, you will send these statistics to the user space. You can choose the way, but I can suggest two approaches:
- You can send statistics in the ring buffer every *n* events on a given file descriptor, or no more than every *n* seconds.
- You can remove the ring buffer and read directly the hash map from the user space every *n* seconds. You might want to have a look at [this function](https://docs.kernel.org/bpf/map_hash.html#bpf-map-get-next-key) to iterate over the hash map from the user space.

## An example of Network programming with eBPF

Our first tool is a performance measurement tool, which is one of the use cases of eBPF. We will see here a different use case, which is packet processing with a bit of security. We will write a BPF program that we can attach to a network interface, and that will monitor all incoming ICMP (ping) packets, and filter abusive sources to prevent flooding.

This time, the eBPF program `tc_icmp_filter` will not be attached to a kernel tracepoint, but to a network queue using `bpf/tc` (traffic control). It can be used to perform some management in the network packets: read them, redirect them, rewrite them, or drop them.

See the `Readme.md` for information on how to compile and attach the program to a network interface.

I provide you with a minimal program in `tc_icmp_filter.bpf.c`. Read it to understand how it watches all network packets, ignore everything that is not ICMP, and drop all ICMP packets. Compile it, and observe how all the ping requests, yours as well as incoming ones (try with your neighbor), fail. This is because all types of ICMP packets are dropped: incoming requests, as well as echo replies.

Your task is to perform a kind of moderation on the incoming ping requests: for every source address pinging you, count the number of pings in one second. If it exceeds a given threshold (50 for instance), blacklist this address and drop incoming ping requests from it.

Here is a list of tips to reach this goal:
- Store information per peer with a hash maps, whose keys are source addresses.
- Use a `struct` containing the time of the first ping, the number of pings since, and the state of the peer: blocked or not.

## Credits

Many thanks to Théophile Dubuc who developed the [original](https://gitlab.aliens-lyon.fr/tdubuc/tp-ebpf-network) version of this lab.