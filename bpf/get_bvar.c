// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020, 2021, Oracle and/or its affiliates. All rights reserved.
 */
#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>
#include <bpf-helpers.h>
#include <dtrace/conf.h>
#include <dtrace/dif_defines.h>
#include <dtrace/faults_defines.h>
#include <dt_bpf_maps.h>
#include <dt_dctx.h>
#include <dt_state.h>
#include <dt_varint.h>

#include "probe_error.h"

#ifndef noinline
# define noinline	__attribute__((noinline))
#endif

extern struct bpf_map_def cpuinfo;
extern struct bpf_map_def probes;
extern struct bpf_map_def state;

extern uint64_t STBSZ;

#define error(dctx, fault, illval) \
	({ \
		dt_probe_error((dctx), -1, (fault), (illval)); \
		-1; \
	})

noinline uint64_t dt_get_bvar(dt_dctx_t *dctx, uint32_t id)
{
	dt_mstate_t	*mst = dctx->mst;

	switch (id) {
	case DIF_VAR_CURTHREAD:
		return bpf_get_current_task();
	case DIF_VAR_TIMESTAMP:
		if (mst->tstamp == 0)
			mst->tstamp = bpf_ktime_get_ns();

		return mst->tstamp;
	case DIF_VAR_EPID:
		return mst->epid;
	case DIF_VAR_ID:
		return mst->prid;
	case DIF_VAR_ARG0: case DIF_VAR_ARG1: case DIF_VAR_ARG2:
	case DIF_VAR_ARG3: case DIF_VAR_ARG4: case DIF_VAR_ARG5:
	case DIF_VAR_ARG6: case DIF_VAR_ARG7: case DIF_VAR_ARG8:
	case DIF_VAR_ARG9:
		return mst->argv[id - DIF_VAR_ARG0];
	case DIF_VAR_STACKDEPTH: {
		/* FIXME: no stack() yet */
		return 0;
	}
	case DIF_VAR_CALLER: {
		uint64_t flags = 0 & BPF_F_SKIP_FIELD_MASK;
		uint64_t buf[2];

		if (bpf_get_stack(dctx->ctx, buf, sizeof(buf), flags) < 0)
			return 0;
		return buf[1];
	}
	case DIF_VAR_PROBEPROV:
	case DIF_VAR_PROBEMOD:
	case DIF_VAR_PROBEFUNC:
	case DIF_VAR_PROBENAME: {
		uint32_t	key;
		dt_bpf_probe_t	*pinfo;
		uint64_t	off;

		key = mst->prid;
		pinfo = bpf_map_lookup_elem(&probes, &key);
		if (pinfo == NULL)
			return (uint64_t)dctx->strtab;

		switch (id) {
		case DIF_VAR_PROBEPROV:
			off = pinfo->prv;
			break;
		case DIF_VAR_PROBEMOD:
			off = pinfo->mod;
			break;
		case DIF_VAR_PROBEFUNC:
			off = pinfo->fun;
			break;
		case DIF_VAR_PROBENAME:
			off = pinfo->prb;
		}
		if (off > (uint64_t)&STBSZ)
			return (uint64_t)dctx->strtab;

		return (uint64_t)(dctx->strtab + off);
	}
	case DIF_VAR_PID: {
		uint64_t	val = bpf_get_current_pid_tgid();

		return val >> 32;
	}
	case DIF_VAR_TID: {
		uint64_t	val = bpf_get_current_pid_tgid();

		return val & 0x00000000ffffffffUL;
	}
	case DIF_VAR_PPID: {
		uint64_t	ptr;
		int32_t		val = -1;
		uint32_t	key;
		uint32_t	*parent_off;
		uint32_t	*tgid_off;

		/*
		 * In the "state" map, look up the "struct task_struct" offsets
		 * of real_parent and tgid.
		 */
		key = DT_STATE_TASK_PARENT_OFF;
		parent_off = bpf_map_lookup_elem(&state, &key);
		if (parent_off == NULL)
			return -1;

		key = DT_STATE_TASK_TGID_OFF;
		tgid_off = bpf_map_lookup_elem(&state, &key);
		if (tgid_off == NULL)
			return -1;

		/* Chase pointers val = current->real_parent->tgid. */
		ptr = bpf_get_current_task();
		if (ptr == 0)
			return error(dctx, DTRACEFLT_BADADDR, ptr);
		if (bpf_probe_read((void *)&ptr, 8,
		    (const void *)(ptr + *parent_off)))
			return error(dctx, DTRACEFLT_BADADDR, ptr + *parent_off);
		if (bpf_probe_read((void *)&val, 4,
		    (const void *)(ptr + *tgid_off)))
			return error(dctx, DTRACEFLT_BADADDR, ptr + *tgid_off);

		return (uint64_t)val;
	}
	case DIF_VAR_UID: {
		uint64_t	val = bpf_get_current_uid_gid();

		return val & 0x00000000ffffffffUL;
	}
	case DIF_VAR_GID: {
		uint64_t	val = bpf_get_current_uid_gid();

		return val >> 32;
	}
	case DIF_VAR_CURCPU: {
		uint32_t	key = 0;
		void		*val = bpf_map_lookup_elem(&cpuinfo, &key);

		if (val == NULL)
			return (uint64_t)NULL;	/* FIXME */

		return (uint64_t)val;
	}
	default:
		/* Not implemented yet. */
		return error(dctx, DTRACEFLT_ILLOP, 0);
	}
}
