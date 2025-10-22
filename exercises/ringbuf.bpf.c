// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
//#include <linux/bpf.h>
#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "ringbuf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Global variable declaration */
int my_pid = 0;

/* BPF maps declarations */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int); // pid
    __type(value, struct event_to_match); // File descriptor and timestamps
    __uint(max_entries, 1024);
} match_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*sizeof(struct rb_event));
} rb SEC(".maps");

/* BPF programs declarations */

SEC("tp/syscalls/sys_enter_write")
int handle_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    /* Get the pid of the process triggering this BPF program */
	int pid = bpf_get_current_pid_tgid() >> 32;

    /* Ignore if the write was triggered by us */
    if (pid == my_pid)
        return 0;

    /* Get the file descriptor of the written file */
    unsigned int fd = ctx->args[0];
    /* Get a timestamp */
    unsigned long long ts = bpf_ktime_get_ns();

    struct event_to_match e = {fd, ts};

    /* Save the timestamp in the match map to match it later. */
    bpf_map_update_elem(&match_map, &pid, &e, BPF_ANY);

	return 0;
}

SEC("tp/syscalls/sys_exit_write")
int handle_exit_write(struct trace_event_raw_sys_exit *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == my_pid)
        return 0;

    /* Get current timestamp */
    unsigned long long ts_end = bpf_ktime_get_ns();

    /* Match event with start of write operation using our match_map */
    struct event_to_match *e = bpf_map_lookup_elem(&match_map, &pid);
    /* Always check your pointers with BPF */
    if (!e)
        return 0;

    /* Get timestamp of write operation start */
    unsigned long long ts_start = e->ts;

    unsigned long long delta = ts_end - ts_start;

    /* Now we send an event to the user space using the ring buffer to pass the
     * information we collected.
     * First, reserve space in the ringbuffer to write our event */
    struct rb_event *rb_e = bpf_ringbuf_reserve(&rb, sizeof(*rb_e), 0);
    /* Checkkkk yourrr pointerrrrs */
    if(!rb_e)
        return 0;

    /* Then, fill the allocated space with data */
    /* TODO TODO TODO */

    /* Finally, submit the data */
    bpf_ringbuf_submit(rb_e, 0);

    /* And c'est ciao */
    return 0;
}


