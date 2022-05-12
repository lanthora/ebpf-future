// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	void *fname;
	struct event *e;
	pid_t pid;
	u64 ts;

	/* 记录执行 exec() 的进程号 pid 和执行时间 ts */
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* 如果指定了进程最少运行时间,就不上报进程启动事件 */
	if (min_duration_ns)
		return 0;

	/* 申请 ring buffer 保留内存 */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* 填充进程启动相关数据 */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname = (void *)ctx + (ctx->__data_loc_filename & 0xFFFF);
	bpf_probe_read_str(&e->filename, sizeof(e->filename), fname);

	/* 通过 ring buffer 提交数据 */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;

	/* 获取进程号和线程号 */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	/* 忽略线程退出 */
	if (pid != tid)
		return 0;

	/* 尝试从 map 中获取当前进程启动时间 */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);

	/* 忽略无法获取启动时间的进程 */
	if (!start_ts)
		return 0;

	/* 计算执行时间,并从 map 中移除 */
	duration_ns = bpf_ktime_get_ns() - *start_ts;
	bpf_map_delete_elem(&exec_start, &pid);

	/* 忽略执行时间不够长的进程 */
	if (duration_ns < min_duration_ns)
		return 0;

	/* 申请 ring buffer 保留内存 */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* 填充进程启动相关数据 */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = true;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* 通过 ring buffer 提交数据 */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
