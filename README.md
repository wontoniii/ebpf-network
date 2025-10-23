# Introduction to Kernel Extensions with eBPF

## Introduction

This lab session has two primary objectives:
1. Introduce fundamental eBPF programming concepts
2. Demonstrate the application of eBPF for network programming

To achieve these objectives, students will develop two eBPF applications: the first measures execution time within the `write` system call, and the second tracks and filters incoming ICMP (`ping`) packets.

### Lab Materials

The repository contains:
- One code directory (`exercises`) containing the code files to be completed
- eBPF introduction slides within the `slides` folder

The `exercises` directory includes a `README.md` file that should be consulted before attempting to compile and execute the exercises.

## Part 1: Fundamentals of eBPF Programming

This section introduces core eBPF programming concepts through the development of a tracer that monitors execution time within the `write` system call. The concepts covered include:
- Structure and architecture of eBPF applications
- Attachment of eBPF programs to kernel hooks
- Storage and retrieval of data using eBPF maps
- Communication between eBPF programs and user space

### Exercise 1.1: Compiling and Running Your First eBPF Program

Begin by examining the `minimal` application, an example program provided with the `libbpf` library. This program instruments the `sys_enter_write` tracepoint, which is triggered at the beginning of any write operation.

The application consists of two files: a BPF file (`minimal.bpf.c`) and a C file (`minimal.c`). The BPF file typically contains the definitions of BPF programs that attach to kernel hooks, as well as declarations of BPF data structures used in the application (none are present in the `minimal` example).

Review the BPF file to understand its functionality. The C file may also be examined, though its primary purpose is to load the BPF program into the kernel and attach it to the `sys_enter_write` tracepoint.

To execute the application, first compile it using `make minimal`. Then run it with root privileges: `sudo ./minimal`. The `bpf_printk` macro in the BPF file writes to the trace pipe; open it as instructed by the application. Output should be observable in the trace pipe.

### Exercise 1.2: Measuring System Call Execution Time

The current application simply writes a message to the trace pipe when the write system call begins. The next step is to add a second BPF program that hooks to the exit point of the write system call to measure the total execution time.

This requires the following steps:
1. Capture a timestamp upon entering the write system call
2. Store this timestamp in persistent storage
3. Capture a timestamp upon exiting the write system call
4. Retrieve the entry timestamp and compute the difference between the two timestamps
5. Output the result to the trace pipe

The persistent storage mechanism will be a BPF map: a kernel-resident data structure provided by BPF for temporary data storage. While many map types exist, this use case requires a hash map, which allows values to be stored and retrieved using unique keys.

Examine the `hashmap` BPF code, which includes the declaration of the hash map. Note that the key is an integer representing a Process ID (PID). Since the same process that enters the write system call will eventually exit it, the PID can be used to correlate the entry and exit programs, enabling computation of system call execution time.

The hash map's value type is `struct event_to_match`, defined in `hashmap.h`, which stores execution information including a timestamp and a file descriptor to identify the target file of the write operation.

The code for the program hooked to `sys_enter_write` has been provided: it retrieves the current PID and timestamp, obtains the file descriptor, and writes this data to the hash map using the PID as the key.

Your task is to implement the program hooked to the exit tracepoint. You should reuse most of the entry program's code and incorporate the following:

```c
struct event_to_match *e = bpf_map_lookup_elem(&match_map, &pid);
```

This function searches the `match_map` using the PID as the key and returns a pointer to the structure containing the data populated by the entry program.

Ensure that the result is written to the trace pipe using `bpf_printk` to verify the application's functionality.

### Exercise 1.3: Enhanced User Space Communication

The current application has several limitations. Reading from the trace pipe is inconvenient and represents a debugging mechanism intended for developers rather than production use. A more robust solution leverages the fact that BPF maps can be accessed from user space.

This exercise introduces a new map type specifically designed for efficient kernel-to-user-space message passing: the BPF ring buffer. The mechanism is straightforward: BPF programs write data to the ring buffer (a circular queue), while the user space component continuously polls the buffer to read incoming data.

Review the `ringbuf` exercise. The BPF file includes the ring buffer declaration, and the header file `ringbuf.h` defines a structure for the events sent through it. The program hooked to the write system call exit has been modified to accommodate ring buffer usage, which follows a specific pattern: space is reserved in the buffer, the allocated space is populated with data, and finally the data is submitted. Your task is to populate the `rb_event` that will be transmitted to user space.

Next, examine the application's C file. The ring buffer requires polling, which occurs at the end of the `main()` function. Complete the `handle_event` function, which is invoked for each event retrieved from the ring buffer during polling. Implement code to print the information read from the ring buffer to standard output.

Note: Previous examples monitored only writes triggered by the user space program's PID, specifically from the loop printing dots at the end of `main()` in `minimal.c` and `hashmap.c`. However, the `ringbuf` application now performs write operations for every event read from the ring buffer, which occurs for every write operation from the application itself. To prevent potential issues, the BPF code in `ringbuf.bpf.c` has been modified to monitor write operations from all PIDs except the user space program's PID. This will generate substantial output.

### Exercise 1.4: Further Enhancement (Optional)

This optional section proposes additional improvements to the tracer. Complete this exercise after finishing the remaining laboratory sections. This portion is less structured and does not include additional code templates.

As observed, numerous write operations occur within the kernel. Consider declaring a second hash map (e.g., `stats_map`) that stores per-file-descriptor statistics computed directly in the kernel. The file descriptor serves as the key, and the value is a structure containing statistical information such as:
- Number of occurrences
- Total time spent in the system call
- Average execution time
- Additional metrics such as the size of write operations

Update this hash map at the conclusion of each write operation after collecting the relevant data.

Finally, transmit these statistics to user space. Two suggested approaches are:
- Send statistics through the ring buffer every *n* events on a given file descriptor, or at most every *n* seconds
- Remove the ring buffer and read the hash map directly from user space every *n* seconds (refer to [bpf_map_get_next_key](https://docs.kernel.org/bpf/map_hash.html#bpf-map-get-next-key) for hash map iteration from user space)

## Part 2: Network Programming with eBPF

The first tool developed in this lab is a performance measurement tool, demonstrating one use case of eBPF. This section explores a different application: packet processing with security considerations. Students will develop a BPF program that attaches to a network interface to monitor incoming ICMP (ping) packets and filter abusive sources to prevent flooding.

Unlike previous exercises, the `tc_icmp_filter` eBPF program attaches not to a kernel tracepoint but to a network queue using `bpf/tc` (traffic control). This attachment point enables various packet management operations: inspection, redirection, modification, or dropping.

Consult the `README.md` file for instructions on compiling and attaching the program to a network interface.

A minimal program is provided in `tc_icmp_filter.bpf.c`. Examine it to understand how it monitors all network packets, ignores non-ICMP traffic, and drops all ICMP packets. Compile the program and observe that all ping requests (both outgoing and incoming, including from neighboring machines) fail. This occurs because all ICMP packet types are dropped, including both incoming requests and echo replies.

Your task is to implement rate limiting for incoming ping requests: for each source address, count the number of pings within a one-second window. If the count exceeds a specified threshold (e.g., 50), blacklist the address and drop subsequent ping requests from it.

Guidelines for implementation:
- Utilize a hash map with source addresses as keys to store per-peer information
- Define a `struct` containing the timestamp of the first ping, the cumulative ping count, and the peer's state (blocked or permitted)

## Acknowledgments

The development of this laboratory exercise was based on the [original work](https://gitlab.aliens-lyon.fr/tdubuc/tp-ebpf-network) by Théophile Dubuc. His contribution is gratefully acknowledged.