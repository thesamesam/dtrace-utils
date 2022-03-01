#ifdef DEBUGGING
// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021, Oracle and/or its affiliates. All rights reserved.
 */
#include <linux/bpf.h>
#include <stdint.h>
#include <bpf-helpers.h>

#ifndef noinline
# define noinline	__attribute__((noinline))
#endif

noinline void dt_trace_ptr(uint64_t counter, uint64_t ptr)
{
	/*
	 * Can't use a straight string constant: DTrace cannot yet process
	 * rodata relocs.
	 */
	char fmt[] = "debug: %d: %lx\n";
	bpf_trace_printk(fmt, 16, counter, ptr);
}
#endif
