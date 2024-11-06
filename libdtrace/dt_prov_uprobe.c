/*
 * Oracle Linux DTrace.
 * Copyright (c) 2021, 2024, Oracle and/or its affiliates. All rights reserved.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 *
 * The uprobe-based provider for DTrace (implementing pid and USDT providers).
 *
 * This file uses both overlying probes (specified by the user) as well as
 * underlying probes (the uprobes provided by the kernel).  To minimize
 * confusion, this file uses the following convention for variable names:
 *
 *     dt_probe_t	*prp;   //  overlying probe
 *     dt_probe_t	*uprp;  // underlying probe
 *
 *     dt_uprobe_t	*upp;   // uprobe associated with an underlying probe
 *
 *     list_probe_t	*pop;   //  overlying probe list
 *     list_probe_t	*pup;   // underlying probe list
 *
 * The provider-specific prv_data has these meanings:
 *
 *     prp->prv_data            // dt_list_t of associated underlying probes
 *     uprp->prv_data           // upp (the associated uprobe)
 *
 * Finally, note that upp->probes is a dt_list_t of overlying probes.
 */
#include <sys/types.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include <bpf_asm.h>

#include "dt_dctx.h"
#include "dt_cg.h"
#include "dt_list.h"
#include "dt_provider_tp.h"
#include "dt_probe.h"
#include "dt_program.h"
#include "dt_pid.h"
#include "dt_string.h"
#include "port.h"

/* Provider name for the underlying probes. */
static const char	prvname[] = "uprobe";

#define PP_IS_RETURN	0x1
#define PP_IS_FUNCALL	0x2
#define PP_IS_ENABLED	0x4
#define PP_IS_USDT	0x8
#define PP_IS_MAPPED	0x10

typedef struct dt_uprobe {
	dev_t		dev;
	ino_t		inum;
	char		*fn;
	uint64_t	off;
	int		flags;
	tp_probe_t	*tp;
	int		argc;		   /* number of args */
	dt_argdesc_t	*args;		   /* args array (points into argvbuf) */
	char		*argvbuf;	   /* arg strtab */
	dt_list_t	probes;		   /* pid/USDT probes triggered by it */
} dt_uprobe_t;

typedef struct list_probe {
	dt_list_t	list;
	dt_probe_t	*probe;
} list_probe_t;

typedef struct list_key {
	dt_list_t		list;
	usdt_prids_map_key_t	key;
} list_key_t;

static const dtrace_pattr_t	pattr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
};

dt_provimpl_t	dt_pid;
dt_provimpl_t	dt_usdt;

static int populate(dtrace_hdl_t *dtp)
{
	if (dt_provider_create(dtp, dt_uprobe.name, &dt_uprobe, &pattr,
			       NULL) == NULL ||
	    dt_provider_create(dtp, dt_pid.name, &dt_pid, &pattr,
			       NULL) == NULL)
		return -1;			/* errno already set */

	return 0;
}

static int populate_usdt(dtrace_hdl_t *dtp)
{
	if (dt_provider_create(dtp, dt_usdt.name, &dt_usdt, &pattr,
			       NULL) == NULL)
		return -1;			/* errno already set */

	return 0;
}

static void free_probe_list(dtrace_hdl_t *dtp, list_probe_t *elem)
{
	while (elem != NULL) {
		list_probe_t	*next;

		next = dt_list_next(elem);
		dt_free(dtp, elem);
		elem = next;
	}
}

/*
 * Destroy an underlying (uprobe) probe.
 */
static void probe_destroy_underlying(dtrace_hdl_t *dtp, void *datap)
{
	dt_uprobe_t	*upp = datap;
	tp_probe_t	*tpp = upp->tp;

	dt_tp_destroy(dtp, tpp);
	free_probe_list(dtp, dt_list_next(&upp->probes));
	dt_free(dtp, upp->fn);
	dt_free(dtp, upp->args);
	dt_free(dtp, upp->argvbuf);
	dt_free(dtp, upp);
}

/*
 * Destroy an overlying (pid/USDT) probe.
 */
static void probe_destroy(dtrace_hdl_t *dtp, void *datap)
{
	free_probe_list(dtp, datap);
}

/*
 * Disable an overlying USDT probe.
 */
static void probe_disable(dtrace_hdl_t *dtp, dt_probe_t *prp)
{
	list_probe_t	*pup;

	/* Remove from enablings. */
	dt_list_delete(&dtp->dt_enablings, prp);

	/* Make it evident from the probe that it is not in enablings. */
	((dt_list_t *)prp)->dl_prev = NULL;
	((dt_list_t *)prp)->dl_next = NULL;

	/* Free up its list of underlying probes. */
	while ((pup = dt_list_next(prp->prv_data)) != NULL) {
		dt_list_delete(prp->prv_data, pup);
		dt_free(dtp, pup);
	}
	dt_free(dtp, prp->prv_data);
	prp->prv_data = NULL;
}

/*
 * Clean up stale pids from among the USDT probes.
 */
static int
clean_usdt_probes(dtrace_hdl_t *dtp)
{
	int			fdprids = dtp->dt_usdt_pridsmap_fd;
	int			fdnames = dtp->dt_usdt_namesmap_fd;
	usdt_prids_map_key_t	key, nxt;
	usdt_prids_map_val_t	val;
	list_key_t		keys_to_delete, *elem, *elem_next;
	dt_probe_t		*prp, *prp_next;

	/* Initialize list of usdt_prids keys to delete. */
	memset(&keys_to_delete, 0, sizeof(keys_to_delete));

	/* Initialize usdt_prids key to a pid/uprid that cannot be found. */
	key.pid = 0;
	key.uprid = 0;

	/* Loop over usdt_prids entries. */
	while (dt_bpf_map_next_key(fdprids, &key, &nxt) == 0) {
		memcpy(&key, &nxt, sizeof(usdt_prids_map_key_t));

		if (dt_bpf_map_lookup(fdprids, &key, &val) == -1)
			return dt_set_errno(dtp, EDT_BPF);

		/* Check if the process is still running. */
		if (!Pexists(key.pid)) {
			/*
			 * Delete the usdt_names entry.
			 *
			 * Note that a PRID might correspond to multiple
			 * sites.  So, as we loop over usdt_prids entries,
			 * we might delete the same usdt_names entry
			 * multiple times.  That's okay.
			 */
			dt_bpf_map_delete(fdnames, &val.prid);

			/*
			 * Delete the usdt_prids entry.
			 *
			 * Note that we do not want to disrupt the iterator.
			 * So we just add the key to a list and will walk
			 * the list later for actual deletion.
			 */
			elem = calloc(1, sizeof(list_key_t));
			elem->key.pid = key.pid;
			elem->key.uprid = key.uprid;
			dt_list_append((dt_list_t *)&keys_to_delete, elem);

			continue;
		}

		/*
		 * FIXME.  There might be another case, where the process
		 * is still running, but some of its USDT probes are gone?
		 * So maybe we have to check for the existence of one of
		 *     dtrace_probedesc_t *pdp = dtp->dt_probes[val.prid]->desc;
		 *     char *prv = ...pdp->prv minus the numerial part;
		 *
		 *     /run/dtrace/probes/$pid/$pdp->prv/$pdp->mod/$pdp->fun/$pdp->prb
		 *     /run/dtrace/stash/dof-pid/$pid/0/parsed/$prv:$pdp->mod:$pdp->fun:$pdp->prb
		 *     /run/dtrace/stash/dof-pid/$pid/.../parsed/$prv:$pdp->mod:$pdp->fun:$pdp->prb
		 */
	}

	/*
	 * Delete the usdt_prids keys in our list.
	 */
	for (elem = dt_list_next(&keys_to_delete); elem != NULL; elem = elem_next) {
		elem_next = dt_list_next(elem);

		dt_bpf_map_delete(fdprids, &elem->key);
		free(elem);
	}

	/* Clean up enablings. */
	for (prp = dt_list_next(&dtp->dt_enablings); prp != NULL; prp = prp_next) {
		pid_t		pid;

		prp_next = dt_list_next(prp);

		/* Make sure it is an overlying USDT probe. */
		if (prp->prov->impl != &dt_usdt)
			continue;

		/* FIXME passing in NULL pcb and dpr wreaks havoc on error reporting? */
		/*
		 * Nick writes:
		 * This is a general problem with running compiler-adjacent things outside
		 * compile time. I think we should adjust dt_pid_error() so that it works
		 * with NULL pcb and dpr at once, probably by using the code path for
		 * pcb != NULL and augmenting it so that it passes in NULL for the region and
		 * filename args and 0 for the lineno if pcb is NULL. (dt_set_errmsg can
		 * already handle this case.)
		 */
		pid = dt_pid_get_pid(prp->desc, dtp, NULL, NULL);

		if (Pexists(pid))
			continue;

		probe_disable(dtp, prp);
	}

	return 0;
}

/*
 * Judge whether clause "n" could ever be called as a USDT probe
 * for this underlying probe.
 */
static int
ignore_clause(dtrace_hdl_t *dtp, int n, const dt_probe_t *uprp)
{
	dtrace_stmtdesc_t	*stp = dtp->dt_stmts[n];
	dtrace_probedesc_t	*pdp = &stp->dtsd_ecbdesc->dted_probe;

	/*
	 * Some clauses could never be called for a USDT probe,
	 * regardless of the underlying probe uprp.  Cache this
	 * status in the clause flags for dt_stmts[n].
	 */
	if (dt_stmt_clsflag_test(stp, DT_CLSFLAG_USDT_INCLUDE | DT_CLSFLAG_USDT_EXCLUDE) == 0) {
		char lastchar = pdp->prv[strlen(pdp->prv) - 1];

		/*
		 * If the last char in the provider description is
		 * neither '*' nor a digit, it cannot be a USDT probe.
		 */
		if (lastchar != '*' && !isdigit(lastchar)) {
			dt_stmt_clsflag_set(stp, DT_CLSFLAG_USDT_EXCLUDE);
			return 1;
		}

		/*
		 * If the provider description is "pid[0-9]*", it
		 * is a pid probe, not USDT.
		 */
		if (strncmp(pdp->prv, "pid", 3) == 0) {
			int i, l = strlen(pdp->prv);

			for (i = 3; i < l; i++)
				if (!isdigit((pdp->prv[i])))
					break;

			if (i == l) {
				dt_stmt_clsflag_set(stp, DT_CLSFLAG_USDT_EXCLUDE);
				return 1;
			}
		}

		/* Otherwise, it is possibly a USDT probe. */
		dt_stmt_clsflag_set(stp, DT_CLSFLAG_USDT_INCLUDE);
	}
	if (dt_stmt_clsflag_test(stp, DT_CLSFLAG_USDT_EXCLUDE) == 1)
		return 1;

	/*
	 * If we cannot ignore this statement, try to use uprp.
	 */

	/* We know what function we're in.  It must match the probe description (unless "-"). */
	if (strcmp(pdp->fun, "-") != 0 &&
	    !dt_gmatch(uprp->desc->fun, pdp->fun))
		return 1;

	return 0;
}

static int add_probe_uprobe(dtrace_hdl_t *dtp, dt_probe_t *prp)
{
	dtrace_difo_t   *dp;
	int		cflags, fd, rc = -1;
	dtrace_optval_t	dest_ok = DTRACEOPT_UNSET;

	if (dtp->dt_active == 0)
		return 0;

	/*
	 * Strictly speaking, we want the value passed in to
	 * dtrace_go().  In practice, its flags pertain to
	 * compilation and disassembly, which at this stage
	 * no longer interest us.
	 * FIXME:  Actually, we might want debug output (e.g.,
	 * disassembly) for trampoline construction.
	 */
	cflags = 0;

	/* Check if the probe is already set up. */
	if (prp->difo)
		return 0;

	/* Make program. */
	dp = dt_construct(dtp, prp, cflags, NULL);
	if (dp == NULL)
		return 0;        // FIXME in dt_bpf_make_progs() this is a fatal error; should we do the same here?
	prp->difo = dp;

	/* Load program. */
	if (dt_link(dtp, prp, dp, NULL) == -1)
		return 0;        // FIXME in dt_bpf_load_progs() this is a fatal error; should we do the same here?

	dtrace_getopt(dtp, "destructive", &dest_ok);
	if (dp->dtdo_flags & DIFOFLG_DESTRUCTIVE &&
	    dest_ok == DTRACEOPT_UNSET)
		return dt_set_errno(dtp, EDT_DESTRUCTIVE);

	fd = dt_bpf_load_prog(dtp, prp, dp, cflags);
	if (fd == -1)
		return 0;        // FIXME in dt_bpf_load_progs() this is a fatal error; should we do the same here?

	if (prp->prov->impl->attach)
		rc = prp->prov->impl->attach(dtp, prp, fd);

	if (rc == -ENOTSUPP) {
		char    *s;

		close(fd);
		if (asprintf(&s, "Failed to enable %s:%s:%s:%s",
			      prp->desc->prv, prp->desc->mod,
			      prp->desc->fun, prp->desc->prb) == -1)
			return dt_set_errno(dtp, EDT_ENABLING_ERR);
		dt_handle_rawerr(dtp, s);
		free(s);
	} else if (rc < 0) {
		close(fd);
		return dt_set_errno(dtp, EDT_ENABLING_ERR);
	}

	return 0;
}

static int add_probe_usdt(dtrace_hdl_t *dtp, dt_probe_t *prp)
{
	char				probnam[DTRACE_FULLNAMELEN], *p;
	const dtrace_probedesc_t	*pdp = prp->desc;
	int				fd = dtp->dt_usdt_namesmap_fd;
	pid_t				pid;
	list_probe_t			*pup;

	/* Add probe name elements to usdt_names map. */
	p = probnam;
	memset(p, 0, sizeof(probnam));
	snprintf(p, DTRACE_PROVNAMELEN, "%s", pdp->prv);
	p += DTRACE_PROVNAMELEN;
	snprintf(p, DTRACE_MODNAMELEN, "%s", pdp->mod);
	p += DTRACE_MODNAMELEN;
	snprintf(p, DTRACE_FUNCNAMELEN, "%s", pdp->fun);
	p += DTRACE_FUNCNAMELEN;
	snprintf(p, DTRACE_NAMELEN, "%s", pdp->prb);
	if (dt_bpf_map_update(fd, &pdp->id, probnam) == -1)
		assert(0);   // FIXME do something here

	/* FIXME passing in NULL pcb and dpr wreaks havoc on error reporting? */
	/*
	 * Nick writes:
	 * This is a general problem with running compiler-adjacent things outside
	 * compile time. I think we should adjust dt_pid_error() so that it works
	 * with NULL pcb and dpr at once, probably by using the code path for
	 * pcb != NULL and augmenting it so that it passes in NULL for the region and
	 * filename args and 0 for the lineno if pcb is NULL. (dt_set_errmsg can
	 * already handle this case.)
	 */
	pid = dt_pid_get_pid(prp->desc, dtp, NULL, NULL);

	/* Even though we just enabled this, check it's still live. */
	if (!Pexists(pid)) {
		probe_disable(dtp, prp);
		dt_bpf_map_delete(fd, &pdp->id);

		return 0;
	}

	/* Add prid and bit mask to usdt_prids map. */
	for (pup = prp->prv_data; pup != NULL; pup = dt_list_next(pup)) {
		dt_probe_t		*uprp = pup->probe;
		long long		mask = 0, bit = 1;
		usdt_prids_map_key_t	key;
		usdt_prids_map_val_t	val;
		dt_uprobe_t		*upp = uprp->prv_data;

		/*
		 * For is-enabled probes, the bit mask does not matter.
		 * It is possible that we have this underlying probe due to
		 * an overlying pid-offset probe and that we will not know
		 * until later, when some new pid is created, that we also
		 * have an overlying USDT is-enabled probe, but missing this
		 * optimization opportunity is okay.
		 */
		if (uprp->prov->impl == &dt_uprobe && !(upp->flags & PP_IS_ENABLED)) {
			int n;

			for (n = 0; n < dtp->dt_stmt_nextid; n++) {
				dtrace_stmtdesc_t *stp;

				stp = dtp->dt_stmts[n];
				if (stp == NULL)
					continue;

				if (ignore_clause(dtp, n, uprp))
					continue;

				if (dt_gmatch(prp->desc->prv, stp->dtsd_ecbdesc->dted_probe.prv) &&
				    dt_gmatch(prp->desc->mod, stp->dtsd_ecbdesc->dted_probe.mod) &&
				    dt_gmatch(prp->desc->fun, stp->dtsd_ecbdesc->dted_probe.fun) &&
				    dt_gmatch(prp->desc->prb, stp->dtsd_ecbdesc->dted_probe.prb))
					mask |= bit;

				bit <<= 1;
			}
		}

		key.pid = pid;
		key.uprid = uprp->desc->id;

		val.prid = prp->desc->id;
		val.mask = mask;

		// FIXME Check return value, but how should errors be handled?
		dt_bpf_map_update(dtp->dt_usdt_pridsmap_fd, &key, &val);
	}

	return 0;
}

/*
 * Discover new probes.
 */
static int discover(dtrace_hdl_t *dtp)
{
	int		i;
	dt_pcb_t	pcb;

	/* Clean up stale pids from among the USDT probes. */
	clean_usdt_probes(dtp);

	/* Discover new probes, placing them in dt_probes[]. */
	/*
	 * pcb is only used inside of dt_pid_error() to get:
	 *     pcb->pcb_region
	 *     pcb->pcb_filetag
	 *     pcb->pcb_fileptr
	 * While pcb cannot be NULL, these other things apparently can be.
	 */
	memset(&pcb, 0, sizeof(dt_pcb_t));
	for (i = 0; i < dtp->dt_stmt_nextid; i++) {
		dtrace_stmtdesc_t *stp;

		stp = dtp->dt_stmts[i];
		if (stp == NULL)
			continue;
		if (dt_stmt_clsflag_test(stp, DT_CLSFLAG_USDT_EXCLUDE) != 1)
			dt_pid_create_usdt_probes(&stp->dtsd_ecbdesc->dted_probe, dtp, &pcb);
	}

	return 0;
}

/*
 * Populate args for an underlying probe for use by the overlying USDT probe.
 * The overlying probe does not exist yet at this point, so the arg data is
 * stored in the underlying probe instead and will be accessed when probe_info
 * is called in the overlying probe.
 *
 * Move it into dt_argdesc_t's for use later on. The char *'s in that structure
 * are pointers into the argvbuf array, which is a straight concatenated copy of
 * the nargv/xargv in the pid_probespec_t.
 */
static int populate_args(dtrace_hdl_t *dtp, const pid_probespec_t *psp,
			 dt_uprobe_t *upp)
{
	char	**nargv = NULL;
	char	*nptr = NULL, *xptr = NULL;
	size_t	i;

	upp->argc = psp->pps_xargc;

	/*
	 * If we have a nonzero number of args, we always have at least one narg
	 * and at least one xarg.  Double-check to be sure.  (These are not
	 * populated, and thus left 0/NULL, for non-USDT probes.)
	 */
	if (upp->argc == 0 || psp->pps_xargv == NULL || psp->pps_nargv == NULL
		|| psp->pps_xargvlen == 0 || psp->pps_nargvlen == 0)
		return 0;

	upp->argvbuf = dt_alloc(dtp, psp->pps_xargvlen + psp->pps_nargvlen);
	if(upp->argvbuf == NULL)
		return -1;
	memcpy(upp->argvbuf, psp->pps_xargv, psp->pps_xargvlen);
	xptr = upp->argvbuf;

	memcpy(upp->argvbuf + psp->pps_xargvlen, psp->pps_nargv, psp->pps_nargvlen);
	nptr = upp->argvbuf + psp->pps_xargvlen;

	upp->args = dt_calloc(dtp, upp->argc, sizeof(dt_argdesc_t));
	if (upp->args == NULL)
		return -1;

	/*
	 * Construct an array to allow accessing native args by index.
	 */
	if ((nargv = dt_calloc(dtp, psp->pps_nargc, sizeof (char *))) == NULL)
		goto fail;

	for (i = 0; i < psp->pps_nargc; i++, nptr += strlen(nptr) + 1)
		nargv[i] = nptr;

	/*
	 * Fill up the upp->args array based on xargs.  If this indicates that
	 * mapping is needed, note as much.
	 */
	for (i = 0; i < upp->argc; i++, xptr += strlen(xptr) + 1) {
		int map_arg = psp->pps_argmap[i];

		upp->args[i].native = nargv[map_arg];
		upp->args[i].xlate = xptr;
		upp->args[i].mapping = map_arg;
		upp->args[i].flags = 0;

                if (i != map_arg)
			upp->flags |= PP_IS_MAPPED;
	}

	free(nargv);
	return 0;

 fail:
	free(nargv);
	return -1;
}

/*
 * Look up or create an underlying (real) probe, corresponding directly to a
 * uprobe.  Since multiple pid and USDT probes may all map onto the same
 * underlying probe, we may already have one in the system.
 *
 * If not found, we create a new probe.
 */
static dt_probe_t *create_underlying(dtrace_hdl_t *dtp,
				     const pid_probespec_t *psp)
{
	char			mod[DTRACE_MODNAMELEN];
	char			prb[DTRACE_NAMELEN];
	dtrace_probedesc_t	pd;
	dt_probe_t		*uprp;
	dt_uprobe_t		*upp = NULL;

	/*
	 * The underlying probes (uprobes) represent the tracepoints that pid
	 * and USDT probes are associated with.  They follow a standard naming
	 * convention because an underlying probe could be a tracepoint for one
	 * or more pid and/or USDT probes.
	 *
	 * The probe description for non-return probes is:
	 *
	 *	uprobe:<dev>_<inode>:<func>:<offset>
	 *
	 * The probe description for return probes is:
	 *
	 *	uprobe:<dev>_<inode>:<func>:return
	 */
	snprintf(mod, sizeof(mod), "%lx_%lx", psp->pps_dev, psp->pps_inum);

	switch (psp->pps_type) {
	case DTPPT_RETURN:
		strcpy(prb, "return");
		break;
	case DTPPT_IS_ENABLED:
	case DTPPT_ENTRY:
	case DTPPT_OFFSETS:
	case DTPPT_USDT:
		snprintf(prb, sizeof(prb), "%lx", psp->pps_off);
		break;
	default:
		dt_dprintf("pid: unknown PID probe type %i\n", psp->pps_type);
		return NULL;
	}

	pd.id = DTRACE_IDNONE;
	pd.prv = prvname;
	pd.mod = mod;
	pd.fun = psp->pps_fun;
	pd.prb = prb;

	dt_dprintf("Providing underlying probe %s:%s:%s:%s @ %lx\n", psp->pps_prv,
		   psp->pps_mod, psp->pps_fn, psp->pps_prb, psp->pps_off);
	uprp = dt_probe_lookup(dtp, &pd);
	if (uprp == NULL) {
		dt_provider_t	*pvp;

		/* Get the provider for underlying probes. */
		pvp = dt_provider_lookup(dtp, pd.prv);
		if (pvp == NULL)
			return NULL;

		/* Set up the probe data. */
		upp = dt_zalloc(dtp, sizeof(dt_uprobe_t));
		if (upp == NULL)
			return NULL;

		upp->dev = psp->pps_dev;
		upp->inum = psp->pps_inum;
		upp->off = psp->pps_off;
		upp->fn = strdup(psp->pps_fn);
		upp->tp = dt_tp_alloc(dtp);
		if (upp->tp == NULL)
			goto fail;

		uprp = dt_probe_insert(dtp, pvp, pd.prv, pd.mod, pd.fun, pd.prb,
				       upp);
		if (uprp == NULL)
			goto fail;
	} else
		upp = uprp->prv_data;

	/*
	 * Only one USDT probe can correspond to each underlying probe.
	 */
	if (psp->pps_type == DTPPT_USDT && upp->flags == PP_IS_USDT) {
		dt_dprintf("Found overlapping USDT probe at %lx/%lx/%lx/%s\n",
			   upp->dev, upp->inum, upp->off, upp->fn);
		goto fail;
	}

	if (populate_args(dtp, psp, upp) < 0)
		goto fail;

	switch (psp->pps_type) {
	case DTPPT_RETURN:
	    upp->flags |= PP_IS_RETURN;
	    break;
	case DTPPT_IS_ENABLED:
	    upp->flags |= PP_IS_ENABLED;
	    break;
	case DTPPT_USDT:
	    upp->flags |= PP_IS_USDT;
	    break;
	default: ;
	    /*
	     * No flags needed for other types.
	     */
	}

        return uprp;

fail:
	dt_dprintf("Failed to instantiate %s:%s:%s:%s\n", psp->pps_prv,
		   psp->pps_mod, psp->pps_fn, psp->pps_prb);
	probe_destroy(dtp, upp);
	return NULL;
}

static int provide_probe(dtrace_hdl_t *dtp, const pid_probespec_t *psp,
			 const char *prb, const dt_provimpl_t *pvops, int flags)
{
	char			prv[DTRACE_PROVNAMELEN];
	dt_provider_t		*pvp;
	dtrace_probedesc_t	pd;
	dt_uprobe_t		*upp;
	dt_probe_t		*prp, *uprp;
	list_probe_t		*pop, *pup;

	snprintf(prv, sizeof(prv), "%s%d", psp->pps_prv, psp->pps_pid);

	pd.id = DTRACE_IDNONE;
	pd.prv = prv;
	pd.mod = psp->pps_mod;
	pd.fun = psp->pps_fun;
	pd.prb = prb;

	/* Get (or create) the provider for the PID of the probe. */
	pvp = dt_provider_lookup(dtp, pd.prv);
	if (pvp == NULL) {
		pvp = dt_provider_create(dtp, pd.prv, pvops, &pattr, NULL);
		if (pvp == NULL)
			return -1;

		/* Mark the provider as a PID-based provider. */
		pvp->pv_flags |= DT_PROVIDER_PID;
	}

	/* Create and/or lookup the underlying probe. */
	uprp = create_underlying(dtp, psp);
	if (uprp == NULL)
		return -1;

	upp = uprp->prv_data;
	upp->flags |= flags;

	/* Look up the overlying probe. */
	prp = dt_probe_lookup(dtp, &pd);
	if (prp != NULL) {
		/*
		 * Probe already exists.  If it's already in the underlying
		 * probe's probe list, there is nothing left to do.
		 */
		for (pop = dt_list_next(&upp->probes); pop != NULL;
		     pop = dt_list_next(pop)) {
			if (pop->probe == prp)
				return 0;
		}
	}

	/*
	 * Overlying and underlying probe list entries.
	 */
	pop = dt_zalloc(dtp, sizeof(list_probe_t));
	if (pop == NULL)
		return -1;

	pup = dt_zalloc(dtp, sizeof(list_probe_t));
	if (pup == NULL) {
		dt_free(dtp, pop);
		return -1;
	}

	/*
	 * Add the underlying probe to the list of probes for the overlying probe,
	 * adding the overlying probe if we need to.
	 */

	pup->probe = uprp;
	if (prp == NULL)
		prp = dt_probe_insert(dtp, pvp, pd.prv, pd.mod, pd.fun, pd.prb,
				      pup);
	else
		dt_list_append((dt_list_t *)prp->prv_data, pup);

	if (prp == NULL) {
		dt_free(dtp, pop);
		dt_free(dtp, pup);
		return -1;
	}

	/*
	 * Add the overlying probe to the list of probes for the underlying probe.
	 */
	pop->probe = prp;
	dt_list_append(&upp->probes, pop);

	return 0;
}

static int provide_pid_probe(dtrace_hdl_t *dtp, const pid_probespec_t *psp)
{
	char	prb[DTRACE_NAMELEN];

	switch (psp->pps_type) {
	case DTPPT_ENTRY:
		strcpy(prb, "entry");
		break;
	case DTPPT_RETURN:
		strcpy(prb, "return");
		break;
	case DTPPT_OFFSETS:
		snprintf(prb, sizeof(prb), "%lx", psp->pps_nameoff);
		break;
	default:
		dt_dprintf("pid: unknown PID probe type %i\n", psp->pps_type);
		return -1;
	}

	return provide_probe(dtp, psp, prb, &dt_pid, 0);
}

static int provide_usdt_probe(dtrace_hdl_t *dtp, const pid_probespec_t *psp)
{
	if (psp->pps_type != DTPPT_USDT &&
	    psp->pps_type != DTPPT_IS_ENABLED) {
		dt_dprintf("pid: unknown USDT probe type %i\n", psp->pps_type);
		return -1;
	}

	return provide_probe(dtp, psp, psp->pps_prb, &dt_usdt, PP_IS_FUNCALL);
}

static void enable(dtrace_hdl_t *dtp, dt_probe_t *prp, int is_usdt)
{
	const list_probe_t	*pup;

	assert(prp->prov->impl == &dt_pid || prp->prov->impl == &dt_usdt);

	/*
	 * We need to enable the underlying probes (if not enabled yet).
	 */
	for (pup = prp->prv_data; pup != NULL; pup = dt_list_next(pup)) {
		dt_probe_t *uprp = pup->probe;
		dt_probe_enable(dtp, uprp);
	}

	/*
	 * Finally, ensure we're in the list of enablings as well.
	 * (This ensures that, among other things, the probes map
	 * gains entries for us.)
	 */
	if (!dt_in_list(&dtp->dt_enablings, prp))
		dt_list_append(&dtp->dt_enablings, prp);
}

static void enable_pid(dtrace_hdl_t *dtp, dt_probe_t *prp)
{
	enable(dtp, prp, 0);
}

/*
 * USDT enabling has to enable any is-enabled probes as well.
 */
static void enable_usdt(dtrace_hdl_t *dtp, dt_probe_t *prp)
{
	enable(dtp, prp, 1);
}

/*
 * Generate a BPF trampoline for a pid or USDT probe.
 *
 * The trampoline function is called when one of these probes triggers, and it
 * must satisfy the following prototype:
 *
 *	int dt_uprobe(dt_pt_regs *regs)
 *
 * The trampoline will first populate a dt_dctx_t struct.  It will then emulate
 * the firing of all dependent pid* and USDT probes and their clauses, or (in
 * the case of is-enabled probes), do the necessary copying (is-enabled probes
 * have no associated clauses and their behaviour is hardwired).
 */
static int trampoline(dt_pcb_t *pcb, uint_t exitlbl)
{
	dtrace_hdl_t		*dtp = pcb->pcb_hdl;
	dt_irlist_t		*dlp = &pcb->pcb_ir;
	const dt_probe_t	*uprp = pcb->pcb_probe;
	const dt_uprobe_t	*upp = uprp->prv_data;
	const list_probe_t	*pop;
	uint_t			lbl_exit = pcb->pcb_exitlbl;
	dt_ident_t		*usdt_prids = dt_dlib_get_map(dtp, "usdt_prids");
	int			n;

	assert(usdt_prids != NULL);

	dt_cg_tramp_prologue(pcb);

	/*
	 * After the dt_cg_tramp_prologue() call, we have:
	 *				//     (%r7 = dctx->mst)
	 *				//     (%r8 = dctx->ctx)
	 */
	dt_cg_tramp_copy_regs(pcb);

	/*
	 * Hold the PID of the process that caused the probe to fire in %r6.
	 */
	emit(dlp,  BPF_CALL_HELPER(BPF_FUNC_get_current_pid_tgid));
	emit(dlp,  BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32));
	emit(dlp,  BPF_MOV_REG(BPF_REG_6, BPF_REG_0));

	/*
	 * pid probes.
	 *
	 * Loop over overlying pid probes, calling clauses for those that match:
	 *
	 *	for overlying pid probes (that match except possibly for pid)
	 *		if (pid matches) {
	 *			dctx->mst->prid = PRID1;
	 *			< any number of clause calls >
	 *		}
	 */
	for (pop = dt_list_next(&upp->probes); pop != NULL;
	     pop = dt_list_next(pop)) {
		const dt_probe_t	*prp = pop->probe;
		uint_t			lbl_next = dt_irlist_label(dlp);
		pid_t			pid;
		dt_ident_t		*idp;

		if (prp->prov->impl != &dt_pid)
			continue;

		pid = dt_pid_get_pid(prp->desc, pcb->pcb_hdl, pcb, NULL);
		assert(pid != -1);

		idp = dt_dlib_add_probe_var(pcb->pcb_hdl, prp);
		assert(idp != NULL);

		/*
		 * Populate probe arguments.
		 */
		if (upp->flags & PP_IS_RETURN)
			dt_cg_tramp_copy_rval_from_regs(pcb);
		else
			dt_cg_tramp_copy_args_from_regs(pcb, 1);

		/*
		 * Check whether this pid-provider probe serves the current
		 * process, and emit a sequence of clauses for it when it does.
		 */
		emit(dlp,  BPF_BRANCH_IMM(BPF_JNE, BPF_REG_6, pid, lbl_next));
		emite(dlp, BPF_STORE_IMM(BPF_W, BPF_REG_7, DMST_PRID, prp->desc->id), idp);
		dt_cg_tramp_call_clauses(pcb, prp, DT_ACTIVITY_ACTIVE);
		emitl(dlp, lbl_next,
			   BPF_NOP());
	}

	/*
	 * USDT.
	 */

	/* In some cases, we know there are no USDT probes. */  // FIXME: add more checks
	if (upp->flags & PP_IS_RETURN)
		goto out;

	dt_cg_tramp_copy_args_from_regs(pcb, 0);

	/*
	 * Apply arg mappings, if needed.
	 */
	if (upp->flags & PP_IS_MAPPED) {

		/* dt_cg_tramp_map_args() works from the saved args. */
		dt_cg_tramp_save_args(pcb);
		dt_cg_tramp_map_args(pcb, upp->args, upp->argc);
	}

	/*
	 * Retrieve the PID of the process that caused the probe to fire.
	 */
	emit(dlp,  BPF_CALL_HELPER(BPF_FUNC_get_current_pid_tgid));
	emit(dlp,  BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32));

	/*
	 * Look up in the BPF 'usdt_prids' map.  Space for the look-up key
	 * will be used on the BPF stack:
	 *
	 *     offset                                       value
	 *
	 *     -sizeof(usdt_prids_map_key_t)                pid (in %r0)
	 *
	 *     -sizeof(usdt_prids_map_key_t) + sizeof(pid_t)
	 *     ==
	 *     -sizeof(dtrace_id_t)                         underlying-probe prid
	 */
	emit(dlp,  BPF_STORE(BPF_W, BPF_REG_9, (int)(-sizeof(usdt_prids_map_key_t)), BPF_REG_0));
	emit(dlp,  BPF_STORE_IMM(BPF_W, BPF_REG_9, (int)(-sizeof(dtrace_id_t)), uprp->desc->id));
	dt_cg_xsetx(dlp, usdt_prids, DT_LBL_NONE, BPF_REG_1, usdt_prids->di_id);
	emit(dlp,  BPF_MOV_REG(BPF_REG_2, BPF_REG_9));
	emit(dlp,  BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, (int)(-sizeof(usdt_prids_map_key_t))));
	emit(dlp,  BPF_CALL_HELPER(BPF_FUNC_map_lookup_elem));
	emit(dlp,  BPF_BRANCH_IMM(BPF_JEQ, BPF_REG_0, 0, lbl_exit));

	if (upp->flags & PP_IS_ENABLED) {
		/*
		 * Generate a BPF trampoline for an is-enabled probe.  The is-enabled probe
		 * prototype looks like:
		 *
		 *	int is_enabled(int *arg)
		 *
		 * The trampoline writes 1 into the location pointed to by the passed-in arg.
		 */
		emit(dlp, BPF_STORE_IMM(BPF_W, BPF_REG_FP, DT_TRAMP_SP_SLOT(0), 1));
		emit(dlp, BPF_LOAD(BPF_DW, BPF_REG_1, BPF_REG_8, PT_REGS_ARG0));
		emit(dlp, BPF_MOV_REG(BPF_REG_2, BPF_REG_FP));
		emit(dlp, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, DT_TRAMP_SP_SLOT(0)));
		emit(dlp, BPF_MOV_IMM(BPF_REG_3, sizeof(uint32_t)));
		emit(dlp, BPF_CALL_HELPER(BPF_FUNC_probe_write_user));

		goto out;
	}

	/*
	 * Continue with normal USDT probes.
	 */

	/* Read the PRID from the table lookup and store to mst->prid. */
	emit(dlp,  BPF_LOAD(BPF_W, BPF_REG_1, BPF_REG_0, 0));
	emit(dlp,  BPF_STORE(BPF_W, BPF_REG_7, DMST_PRID, BPF_REG_1));

	/* Read the bit mask from the table lookup in %r6. */    // FIXME someday, extend this past 64 bits
	emit(dlp,  BPF_LOAD(BPF_DW, BPF_REG_6, BPF_REG_0, offsetof(usdt_prids_map_val_t, mask)));

	/*
	 * Hold the bit mask in %r6 between clause calls.
	 */
	for (n = 0; n < dtp->dt_stmt_nextid; n++) {
		dtrace_stmtdesc_t *stp;
		dt_ident_t	*idp;
		uint_t		lbl_next;

		stp = dtp->dt_stmts[n];
		if (stp == NULL)
			continue;

		if (ignore_clause(dtp, n, uprp))
			continue;

		idp = stp->dtsd_clause;
		lbl_next = dt_irlist_label(dlp);

		/* If the lowest %r6 bit is 0, skip over this clause. */
		emit(dlp,  BPF_MOV_REG(BPF_REG_1, BPF_REG_6));
		emit(dlp,  BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 1));
		emit(dlp,  BPF_BRANCH_IMM(BPF_JEQ, BPF_REG_1, 0, lbl_next));

		/*
		 *      if (*dctx.act != act)   // ldw %r0, [%r9 + DCTX_ACT]
		 *	      goto exit;      // ldw %r0, [%r0 + 0]
		 *			      // jne %r0, act, lbl_exit
		 */
		emit(dlp,  BPF_LOAD(BPF_DW, BPF_REG_0, BPF_REG_9, DCTX_ACT));
		emit(dlp,  BPF_LOAD(BPF_W, BPF_REG_0, BPF_REG_0, 0));
		emit(dlp,  BPF_BRANCH_IMM(BPF_JNE, BPF_REG_0, DT_ACTIVITY_ACTIVE, lbl_exit));

		/* dctx.mst->scratch_top = 8 */
		emit(dlp,  BPF_STORE_IMM(BPF_W, BPF_REG_7, DMST_SCRATCH_TOP, 8));

		/* Call clause. */
		emit(dlp,  BPF_MOV_REG(BPF_REG_1, BPF_REG_9));
		emite(dlp, BPF_CALL_FUNC(idp->di_id), idp);

		/* Finished this clause. */
		emitl(dlp, lbl_next,
			   BPF_NOP());

		/* Right-shift %r6. */
		emit(dlp,  BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 1));
	}

out:
	dt_cg_tramp_return(pcb);

	return 0;
}

static char *uprobe_name(dev_t dev, ino_t ino, uint64_t addr, int flags)
{
	char	*name;

	if (asprintf(&name, "dt_pid/%c_%llx_%llx_%lx",
		     flags & PP_IS_RETURN ? 'r' : 'p', (unsigned long long)dev,
		     (unsigned long long)ino, (unsigned long)addr) < 0)
		return NULL;

	return name;
}

/*
 * Create a uprobe for a given dev/ino, mapping filename, and address: the
 * uprobe may be a uretprobe.  Return the probe's name as
 * a new dynamically-allocated string, or NULL on error.
 */
static char *uprobe_create(dev_t dev, ino_t ino, const char *mapping_fn,
			   uint64_t addr, int flags)
{
	int	fd = -1;
	int	rc = -1;
	char	*name;
	char	*spec;

	if (asprintf(&spec, "%s:0x%lx", mapping_fn, addr) < 0)
		return NULL;

	name = uprobe_name(dev, ino, addr, flags);
	if (!name)
		goto out;

	/* Add the uprobe. */
	fd = open(TRACEFS "uprobe_events", O_WRONLY | O_APPEND);
	if (fd == -1)
		goto out;

	rc = dprintf(fd, "%c:%s %s\n", flags & PP_IS_RETURN ? 'r' : 'p', name, spec);

out:
	if (fd != -1)
		close(fd);
	if (rc < 0) {
		free(name);
		return NULL;
	}

	return name;
}

static int attach(dtrace_hdl_t *dtp, const dt_probe_t *uprp, int bpf_fd)
{
	dt_uprobe_t	*upp = uprp->prv_data;
	tp_probe_t	*tpp = upp->tp;
	FILE		*f;
	char		*fn;
	char		*prb = NULL;
	int		rc = -1;

	if (dt_tp_has_info(tpp))
		goto attach_bpf;

	assert(upp->fn != NULL);

	prb = uprobe_create(upp->dev, upp->inum, upp->fn, upp->off,
			    upp->flags);

	/*
	 * If the uprobe creation failed, it is possible it already
	 * existed because someone else created it.  Try to access its
	 * tracefs info and if that fails, we really failed.
	 */

	if (prb == NULL)
		prb = uprobe_name(upp->dev, upp->inum, upp->off,
				  upp->flags);

	/* open format file */
	rc = asprintf(&fn, "%s%s/format", EVENTSFS, prb);
	free(prb);
	if (rc < 0)
		return -ENOENT;
	f = fopen(fn, "r");
	free(fn);
	if (f == NULL)
		return -ENOENT;

	rc = dt_tp_event_info(dtp, f, 0, tpp, NULL, NULL);
	fclose(f);

	if (rc < 0)
		return -ENOENT;

attach_bpf:
	/* attach BPF program to the probe */
	return dt_tp_attach(dtp, tpp, bpf_fd);
}

static int probe_info(dtrace_hdl_t *dtp, const dt_probe_t *prp,
		      int *argcp, dt_argdesc_t **argvp)
{
	size_t		i, j;
	list_probe_t	*pup = prp->prv_data;
	dt_uprobe_t	*upp;
	size_t		argc = 0;
	dt_argdesc_t	*argv = NULL;

	/* No underlying probes?  No args.  */
	if (!pup)
		goto done;

	upp = pup->probe->prv_data;
	if (!upp || upp->args == NULL)
		goto done;

	argc = upp->argc;
	argv = dt_calloc(dtp, argc, sizeof(dt_argdesc_t));
	if (argv == NULL)
		return dt_set_errno(dtp, EDT_NOMEM);

	for (i = 0; i < argc; i++) {
		argv[i].native = strdup(upp->args[i].native);
		if (upp->args[i].xlate)
			argv[i].xlate = strdup(upp->args[i].xlate);
		argv[i].mapping = i;

		if (argv[i].native == NULL ||
		    (upp->args[i].xlate != NULL && argv[i].xlate == NULL))
			goto oom;
	}

done:
	*argcp = argc;
	*argvp = argv;

	return 0;
oom:
	for (j = 0; j <= i; j++) {
		free((char *) argv[i].native);
		free((char *) argv[i].xlate);
	}

	dt_free(dtp, argv);
	return dt_set_errno(dtp, EDT_NOMEM);
}

/*
 * Destroy a uprobe for a given device and address.
 */
static int
uprobe_delete(dev_t dev, ino_t ino, uint64_t addr, int flags)
{
	int	fd = -1;
	int	rc = -1;
	char	*name;

	name = uprobe_name(dev, ino, addr, flags);
	if (!name)
		goto out;

	fd = open(TRACEFS "uprobe_events", O_WRONLY | O_APPEND);
	if (fd == -1)
		goto out;


	rc = dprintf(fd, "-:%s\n", name);

out:
	if (fd != -1)
		close(fd);
	free(name);

	return rc < 0 ? -1 : 0;
}

/*
 * Try to clean up system resources that may have been allocated for this
 * probe.
 *
 * If there is an event FD, we close it.
 *
 * We also try to remove any uprobe that may have been created for the probe
 * (but only if we created it, not if dtprobed did).  This is harmless for
 * probes that didn't get created.  If the removal fails for some reason we are
 * out of luck - fortunately it is not harmful to the system as a whole.
 */
static void detach(dtrace_hdl_t *dtp, const dt_probe_t *uprp)
{
	dt_uprobe_t	*upp = uprp->prv_data;
	tp_probe_t	*tpp = upp->tp;

	if (!dt_tp_has_info(tpp))
		return;

	dt_tp_detach(dtp, tpp);

	uprobe_delete(upp->dev, upp->inum, upp->off, upp->flags);
}

/*
 * Used for underlying probes (uprobes).
 */
dt_provimpl_t	dt_uprobe = {
	.name		= prvname,
	.prog_type	= BPF_PROG_TYPE_KPROBE,
	.populate	= &populate,
	.load_prog	= &dt_bpf_prog_load,
	.trampoline	= &trampoline,
	.attach		= &attach,
	.detach		= &detach,
	.probe_destroy	= &probe_destroy_underlying,
	.add_probe	= &add_probe_uprobe,
};

/*
 * Used for pid probes.
 */
dt_provimpl_t	dt_pid = {
	.name		= "pid",
	.prog_type	= BPF_PROG_TYPE_UNSPEC,
	.provide_probe	= &provide_pid_probe,
	.enable		= &enable_pid,
	.probe_destroy	= &probe_destroy,
};

/*
 * Used for usdt probes.
 */
dt_provimpl_t	dt_usdt = {
	.name		= "usdt",
	.prog_type	= BPF_PROG_TYPE_UNSPEC,
	.populate	= &populate_usdt,
	.provide_probe	= &provide_usdt_probe,
	.enable		= &enable_usdt,
	.probe_info	= &probe_info,
	.probe_destroy	= &probe_destroy,
	.discover	= &discover,
	.add_probe	= &add_probe_usdt,
};
