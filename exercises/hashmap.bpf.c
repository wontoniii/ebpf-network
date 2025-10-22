// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "hashmap.h"

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

/* BPF programs declarations */

SEC("tp/syscalls/sys_enter_write")
int handle_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    /* Get the pid of the process triggering this BPF program */
	int pid = bpf_get_current_pid_tgid() >> 32;

    /* Ignore every write from other processes than our user space program */
    if (pid != my_pid)
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
    /* TODO TODO TODO */

    return 0;
}

