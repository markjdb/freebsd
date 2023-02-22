/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2022 Richard L. Sites <dick.sites@gmail.com>.
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice(s), this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified other than the possible
 *    addition of one or more copyright notices.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice(s), this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * Kernel include file kutrace.h FOR FreeBSD ONLY, not Linux
 *
 * KUtrace is a facility to produce a trace of every transition between kernel-mode
 * execution and user-mode execution on every CPU core of a running production system,
 * with less than 1% overhead. In addition to every non-debug non-fatal system call/
 * return, interrupt/return, trap/return, and context switch, there are trace entries
 * for making a thread runnable, thread wakeup via IPI or monitor/mwait, CPU frequency,
 * low-power states, and text names for everything. Optionally, instructions per cycle,
 * IPC, is recorded for every microsecond-scale time interval.
 *
 * The companion loadable module allocates the kernel-memory raw trace buffer, implements
 * the calls defined here, and implements a simple control interface to start/stop
 * tracing, insert user-provided markers and other trace entries, and extract the
 * recorded data.
 *
 * Companion postprocessing routines turn raw traces into dynamic HTML whose timeline
 * can be panned and zoomed over nine orders of magnitude, from about 100 seconds across
 * to 100 nanoseconds across.
 *
 * Most kernel source patches will be something like
 *   kutrace1(event, arg);
 *
 */


#ifndef KUTRACE_H
#define KUTRACE_H

#include <sys/types.h>

/* This is a shortened list of kernel-mode raw trace 12-bit event numbers */
/* See user-mode kutrace_lib.h for the full set */

/* Entry to provide names for PIDs (actually thread IDs) */
#define KUTRACE_PIDNAME		0x002

#define KUTRACE_PC_TEMP		0x101	/* postproc turns into PC_U or PC_K */

// Specials are point events
#define KUTRACE_USERPID		0x200	/* Context switch: new PID */
#define KUTRACE_RPCIDRXPKT	0x204
#define KUTRACE_RPCIDTXPKT	0x205
#define KUTRACE_RUNNABLE	0x206	/* Set process runnable: PID/TID */
#define KUTRACE_IPI		0x207	/* Send IPI; receive is an interrupt */
#define KUTRACE_MWAIT		0x208	/* C-states */
#define KUTRACE_PSTATE		0x209	/* P-states (frequency) */
#define KUTRACE_MONITORSTORE	0x21E	/* Store into a monitored location; wakeup */
#define KUTRACE_MONITOREXIT	0x21f	/* Mwait exit due to store above */

/* These are in blocks of 256 numbers */
#define KUTRACE_TRAP		0x0400  /* AKA fault */
#define KUTRACE_IRQ		0x0500
#define KUTRACE_TRAPRET		0x0600
#define KUTRACE_IRQRET		0x0700

/* These are in blocks of 512 numbers */
#define KUTRACE_SYSCALL64	0x0800
#define KUTRACE_SYSRET64	0x0A00
#define KUTRACE_SYSCALL32	0x0C00	/* Now syscall64 high block */
#define KUTRACE_SYSRET32	0x0E00	/* Now sysret64 high block */

/* Specific syscall numbers */
/* Take over last syscall32 number for tracing the scheduler call/return */
#define KUTRACE_SCHEDSYSCALL 1535	/* Top syscall32: 1023 + 512 */

/* Specific trap numbers */
#define KUTRACE_DNA		7	/* Device (8087) not available */
#define KUTRACE_PAGEFAULT	14

/* Specific IRQ numbers. Picked from arch/x86/include/asm/irq_vectors.h */
#define KUTRACE_LOCAL_TIMER_VECTOR	0xec

/* Reuse the spurious_apic vector to show bottom halves (AST) executing */
#define KUTRACE_BOTTOM_HALF	255
#define AST_SOFTIRQ		15

#ifdef KUTRACE
/* Procedure interface to loadable module or compiled-in kutrace.c */
struct kutrace_ops {
	void (*kutrace_trace_1)(uint64_t num, uint64_t arg);
	void (*kutrace_trace_2)(uint64_t num, uint64_t arg1, uint64_t arg2);
	void (*kutrace_trace_many)(uint64_t num, uint64_t len, const char *arg);
	uint64_t (*kutrace_trace_control)(uint64_t command, uint64_t arg);
};

/* Packet tracing is not yet implemented for FreeBSD */
/* Packet filter parameters */
struct kutrace_nf {
	uint64_t hash_init;
	uint64_t hash_mask[3];
};

/* Global variables used by KUtrace */
/* Declared here and instantiated in sys/kern/subr_trap.c */
extern bool kutrace_tracing;
extern struct kutrace_ops kutrace_global_ops;
extern uint64_t *kutrace_pid_filter;

/* Macros used by KUtrace */
/* Insert pid name if first time seen. Races don't matter here. */
#define kutrace_pidname(next) \
	if (kutrace_tracing) { \
		uint32_t tid = next->td_tid - (PID_MAX + 1); \
		uint32_t pid16 = tid & 0xffff; \
		uint32_t pid_hi = pid16 >> 6; \
		uint64_t pid_bit = 1ull << (pid16 & 0x3f); \
		if ((kutrace_pid_filter[pid_hi] & pid_bit) == 0) { \
			uint64_t name_entry[3]; \
			name_entry[0] = tid; \
			memcpy(&name_entry[1], next->td_name, 16); \
			(*kutrace_global_ops.kutrace_trace_many)( \
			KUTRACE_PIDNAME, 3l, (const char*)&name_entry[0]); \
			kutrace_pid_filter[pid_hi] |= pid_bit; \
		} \
	}

/* Unconditionally insert or reset pid name. Races don't matter here. */
#define kutrace_pidrename(next) \
	if (kutrace_tracing) { \
		uint32_t tid = next->td_tid - (PID_MAX + 1); \
		uint32_t pid16 = tid & 0xffff; \
		uint32_t pid_hi = pid16 >> 6; \
		uint64_t pid_bit = 1ull << (pid16 & 0x3f); \
		if (true) { \
			uint64_t name_entry[3]; \
			name_entry[0] = tid; \
			memcpy(&name_entry[1], next->td_name, 16); \
			(*kutrace_global_ops.kutrace_trace_many)( \
			 KUTRACE_PIDNAME, 3l, (const char*)&name_entry[0]); \
			kutrace_pid_filter[pid_hi] |= pid_bit; \
		} \
	}

/* Packet tracing is not yet implemented for FreeBSD */
/* Filter packet payload; if it passes insert a payload hash into trace */
/* Mask first payload 24 bytes, XOR, and check for expected value */
/* ku_payload might not be 8-byte aligned, but only 4-byte */
#define kutrace_pkttrace(rx_tx, ku_payload) \
	if (kutrace_tracing) { \
		uint64_t hash = kutrace_net_filter.hash_init; \
		hash ^= (ku_payload[0] & kutrace_net_filter.hash_mask[0]); \
		hash ^= (ku_payload[1] & kutrace_net_filter.hash_mask[1]); \
		hash ^= (ku_payload[2] & kutrace_net_filter.hash_mask[2]); \
		hash ^= (hash >> 32); \
		hash &= 0x00000000ffffffffLLU;	/* The filter hash */ \
		if (hash == 0) { \
			/* We passed the filter; hash unmasked first 32 bytes to 4 */ \
			hash = ku_payload[0] ^ ku_payload[1] ^ \
			       ku_payload[2] ^ ku_payload[3]; \
			hash ^= (hash >> 32); \
			hash &= 0x00000000ffffffffLLU; \
			kutrace1(rx_tx, hash); \
		} \
	}

/* Record 64-bit PC sample and CPU frequency if available at timer interrupts */
#define kutrace_pc(arg) \
	if (kutrace_tracing) { \
		(*kutrace_global_ops.kutrace_trace_2)(KUTRACE_PC_TEMP, 0, arg); \
	}

/* Record a normal 64-bit raw trace entry */
#define kutrace1(event, arg) \
	if (kutrace_tracing) { \
		(*kutrace_global_ops.kutrace_trace_1)(event, arg); \
	}

/* Historically, syscall numbers were < 512, but now less-dense numbering exceeds 512.
 * We store these in two dis-contiguous 512-number blocks, repurposing the unused
 * 32-bit syscall block.
 * map_nr moves high 64-bit syscalls 0x200..3FF to low sys32 space 0x400..5FF
 */
#define	kutrace_map_nr(nr) (nr + (nr & 0x200))

#else

#define kutrace_pidname(next)
#define kutrace_pidrename(next)
#define kutrace_pkttrace(rx_tx, ku_payload)
#define kutrace_pc(arg)
#define kutrace1(event, arg)
#define kutrace_map_nr(nr) (nr)

#endif /* KUTRACE */

#endif /* KUTRACE_H */
