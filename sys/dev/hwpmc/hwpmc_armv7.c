/*-
 * Copyright (c) 2015 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/pmc.h>
#include <sys/pmckern.h>

#include <machine/pmc_mdep.h>
#include <machine/cpu.h>

#define	CPU_ID_CORTEX_VER_MASK	0xff
#define	CPU_ID_CORTEX_VER_SHIFT	4

static int armv7_npmcs;

struct armv7_event_code_map {
	enum pmc_event	pe_ev;
	uint8_t		pe_code;
};

const struct armv7_event_code_map armv7_event_codes[] = {
	{ PMC_EV_ARMV7_PMNC_SW_INCR,		0x00 },
	{ PMC_EV_ARMV7_L1_ICACHE_REFILL,	0x01 },
	{ PMC_EV_ARMV7_ITLB_REFILL,		0x02 },
	{ PMC_EV_ARMV7_L1_DCACHE_REFILL,	0x03 },
	{ PMC_EV_ARMV7_L1_DCACHE_ACCESS,	0x04 },
	{ PMC_EV_ARMV7_DTLB_REFILL,		0x05 },
	{ PMC_EV_ARMV7_MEM_READ,		0x06 },
	{ PMC_EV_ARMV7_MEM_WRITE,		0x07 },
	{ PMC_EV_ARMV7_INSTR_EXECUTED,		0x08 },
	{ PMC_EV_ARMV7_EXC_TAKEN,		0x09 },
	{ PMC_EV_ARMV7_EXC_EXECUTED,		0x0A },
	{ PMC_EV_ARMV7_CID_WRITE,		0x0B },
	{ PMC_EV_ARMV7_PC_WRITE,		0x0C },
	{ PMC_EV_ARMV7_PC_IMM_BRANCH,		0x0D },
	{ PMC_EV_ARMV7_PC_PROC_RETURN,		0x0E },
	{ PMC_EV_ARMV7_MEM_UNALIGNED_ACCESS,	0x0F },
	{ PMC_EV_ARMV7_PC_BRANCH_MIS_PRED,	0x10 },
	{ PMC_EV_ARMV7_CLOCK_CYCLES,		0x11 },
	{ PMC_EV_ARMV7_PC_BRANCH_PRED,		0x12 },
	{ PMC_EV_ARMV7_MEM_ACCESS,		0x13 },
	{ PMC_EV_ARMV7_L1_ICACHE_ACCESS,	0x14 },
	{ PMC_EV_ARMV7_L1_DCACHE_WB,		0x15 },
	{ PMC_EV_ARMV7_L2_CACHE_ACCESS,		0x16 },
	{ PMC_EV_ARMV7_L2_CACHE_REFILL,		0x17 },
	{ PMC_EV_ARMV7_L2_CACHE_WB,		0x18 },
	{ PMC_EV_ARMV7_BUS_ACCESS,		0x19 },
	{ PMC_EV_ARMV7_MEM_ERROR,		0x1A },
	{ PMC_EV_ARMV7_INSTR_SPEC,		0x1B },
	{ PMC_EV_ARMV7_TTBR_WRITE,		0x1C },
	{ PMC_EV_ARMV7_BUS_CYCLES,		0x1D },
	{ PMC_EV_ARMV7_CPU_CYCLES,		0xFF },
};

const int armv7_event_codes_size =
	sizeof(armv7_event_codes) / sizeof(armv7_event_codes[0]);

/*
 * Per-processor information.
 */
struct armv7_cpu {
	struct pmc_hw   *pc_armv7pmcs;
	int cortex_ver;
};

static struct armv7_cpu **armv7_pcpu;

/*
 * Performance Monitor Control Register
 */
static __inline uint32_t
armv7_pmnc_read(void)
{
	uint32_t reg;

	__asm __volatile("mrc p15, 0, %0, c9, c12, 0" : "=r" (reg));

	return (reg);
}

static __inline void
armv7_pmnc_write(uint32_t reg)
{

	__asm __volatile("mcr p15, 0, %0, c9, c12, 0" : : "r" (reg));
}

/*
 * Clock Counter Register (PMCCNTR)
 * Counts processor clock cycles.
 */
static __inline uint32_t
armv7_ccnt_read(void)
{
	uint32_t reg;

	__asm __volatile("mrc p15, 0, %0, c9, c13, 0" : "=r" (reg));
	
	return (reg);
}

static __inline void
armv7_ccnt_write(uint32_t reg)
{

	__asm __volatile("mcr p15, 0, %0, c9, c13, 0" : : "r" (reg));
}

/*
 * Interrupt Enable Set Register
 */
static __inline void
armv7_interrupt_enable(uint32_t pmc)
{
	uint32_t reg;

	reg = (1 << pmc);

	__asm __volatile("mcr p15, 0, %0, c9, c14, 1" : : "r" (reg));
}

/*
 * Interrupt Clear Set Register
 */
static __inline void
armv7_interrupt_disable(uint32_t pmc)
{
	uint32_t reg;

	reg = (1 << pmc);

	__asm __volatile("mcr p15, 0, %0, c9, c14, 2" : : "r" (reg));
}

/*
 * Overflow Flag Register
 */
static __inline uint32_t
armv7_flag_read(void)
{
	uint32_t reg;

	__asm __volatile("mrc p15, 0, %0, c9, c12, 3" : "=r" (reg));

	return (reg);
}

static __inline void
armv7_flag_write(uint32_t reg)
{

	__asm __volatile("mcr p15, 0, %0, c9, c12, 3" : : "r" (reg));
}

/*
 * Event Selection Register
 */
static __inline void
armv7_evtsel_write(uint32_t reg)
{

	__asm __volatile("mcr p15, 0, %0, c9, c13, 1" : : "r" (reg));
}

/*
 * PMSELR
 */
static __inline void
armv7_select_counter(unsigned int pmc)
{

	__asm __volatile("mcr p15, 0, %0, c9, c12, 5" : : "r" (pmc));
}

/*
 * Counter Set Enable Register
 */
static __inline void
armv7_counter_enable(unsigned int pmc)
{
	uint32_t reg;

	reg = (1 << pmc);

	__asm __volatile("mcr p15, 0, %0, c9, c12, 1" : : "r" (reg));
}

/*
 * Counter Clear Enable Register
 */
static __inline void
armv7_counter_disable(unsigned int pmc)
{
	uint32_t reg;

	reg = (1 << pmc);

	__asm __volatile("mcr p15, 0, %0, c9, c12, 2" : : "r" (reg));
}

/*
 * Performance Count Register N
 */
static uint32_t
armv7_pmcn_read(unsigned int pmc)
{
	uint32_t reg = 0;

	KASSERT(pmc < 4, ("[armv7,%d] illegal PMC number %d", __LINE__, pmc));

	armv7_select_counter(pmc);
	__asm __volatile("mrc p15, 0, %0, c9, c13, 2" : "=r" (reg));

	return (reg);
}

static uint32_t
armv7_pmcn_write(unsigned int pmc, uint32_t reg)
{

	KASSERT(pmc < 4, ("[armv7,%d] illegal PMC number %d", __LINE__, pmc));

	armv7_select_counter(pmc);
	__asm __volatile("mcr p15, 0, %0, c9, c13, 2" : : "r" (reg));

	return (reg);
}

static int
armv7_allocate_pmc(int cpu, int ri, struct pmc *pm,
  const struct pmc_op_pmcallocate *a)
{
	uint32_t caps, config;
	struct armv7_cpu *pac;
	enum pmc_event pe;
	int i;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[armv7,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < armv7_npmcs,
	    ("[armv7,%d] illegal row index %d", __LINE__, ri));

	pac = armv7_pcpu[cpu];

	caps = a->pm_caps;
	if (a->pm_class != PMC_CLASS_ARMV7)
		return (EINVAL);
	pe = a->pm_ev;

	for (i = 0; i < armv7_event_codes_size; i++) {
		if (armv7_event_codes[i].pe_ev == pe) {
			config = armv7_event_codes[i].pe_code;
			break;
		}
	}
	if (i == armv7_event_codes_size)
		return EINVAL;

	pm->pm_md.pm_armv7.pm_armv7_evsel = config;

	PMCDBG(MDP,ALL,2,"armv7-allocate ri=%d -> config=0x%x", ri, config);

	return 0;
}


static int
armv7_read_pmc(int cpu, int ri, pmc_value_t *v)
{
	pmc_value_t tmp;
	struct pmc *pm;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[armv7,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < armv7_npmcs,
	    ("[armv7,%d] illegal row index %d", __LINE__, ri));

	pm  = armv7_pcpu[cpu]->pc_armv7pmcs[ri].phw_pmc;

	if (pm->pm_md.pm_armv7.pm_armv7_evsel == 0xFF)
		tmp = armv7_ccnt_read();
	else
		tmp = armv7_pmcn_read(ri);

	PMCDBG(MDP,REA,2,"armv7-read id=%d -> %jd", ri, tmp);
	if (PMC_IS_SAMPLING_MODE(PMC_TO_MODE(pm)))
		*v = ARMV7_PERFCTR_VALUE_TO_RELOAD_COUNT(tmp);
	else
		*v = tmp;

	return 0;
}

static int
armv7_write_pmc(int cpu, int ri, pmc_value_t v)
{
	struct pmc *pm;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[armv7,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < armv7_npmcs,
	    ("[armv7,%d] illegal row-index %d", __LINE__, ri));

	pm  = armv7_pcpu[cpu]->pc_armv7pmcs[ri].phw_pmc;

	if (PMC_IS_SAMPLING_MODE(PMC_TO_MODE(pm)))
		v = ARMV7_RELOAD_COUNT_TO_PERFCTR_VALUE(v);
	
	PMCDBG(MDP,WRI,1,"armv7-write cpu=%d ri=%d v=%jx", cpu, ri, v);

	if (pm->pm_md.pm_armv7.pm_armv7_evsel == 0xFF)
		armv7_ccnt_write(v);
	else
		armv7_pmcn_write(ri, v);

	return 0;
}

static int
armv7_config_pmc(int cpu, int ri, struct pmc *pm)
{
	struct pmc_hw *phw;

	PMCDBG(MDP,CFG,1, "cpu=%d ri=%d pm=%p", cpu, ri, pm);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[armv7,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < armv7_npmcs,
	    ("[armv7,%d] illegal row-index %d", __LINE__, ri));

	phw = &armv7_pcpu[cpu]->pc_armv7pmcs[ri];

	KASSERT(pm == NULL || phw->phw_pmc == NULL,
	    ("[armv7,%d] pm=%p phw->pm=%p hwpmc not unconfigured",
	    __LINE__, pm, phw->phw_pmc));

	phw->phw_pmc = pm;

	return 0;
}

static int
armv7_start_pmc(int cpu, int ri)
{
	struct pmc_hw *phw;
	uint32_t config;
	struct pmc *pm;

	phw    = &armv7_pcpu[cpu]->pc_armv7pmcs[ri];
	pm     = phw->phw_pmc;
	config = pm->pm_md.pm_armv7.pm_armv7_evsel;

	/*
	 * Configure the event selection.
	 */
	armv7_select_counter(ri);
	armv7_evtsel_write(config);

	/*
	 * Enable the PMC.
	 */
	armv7_interrupt_enable(ri);
	armv7_counter_enable(ri);

	return 0;
}

static int
armv7_stop_pmc(int cpu, int ri)
{
	struct pmc_hw *phw;
	struct pmc *pm;

	phw    = &armv7_pcpu[cpu]->pc_armv7pmcs[ri];
	pm     = phw->phw_pmc;

	/*
	 * Disable the PMCs.
	 */
	armv7_counter_disable(ri);
	armv7_interrupt_disable(ri);

	return 0;
}

static int
armv7_release_pmc(int cpu, int ri, struct pmc *pmc)
{
	struct pmc_hw *phw;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[armv7,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < armv7_npmcs,
	    ("[armv7,%d] illegal row-index %d", __LINE__, ri));

	phw = &armv7_pcpu[cpu]->pc_armv7pmcs[ri];
	KASSERT(phw->phw_pmc == NULL,
	    ("[armv7,%d] PHW pmc %p non-NULL", __LINE__, phw->phw_pmc));

	return 0;
}

static int
armv7_intr(int cpu, struct trapframe *tf)
{
	struct armv7_cpu *pc;
	int retval, ri;
	struct pmc *pm;
	int error;
	int reg;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[armv7,%d] CPU %d out of range", __LINE__, cpu));

	retval = 0;
	pc = armv7_pcpu[cpu];

	for (ri = 0; ri < armv7_npmcs; ri++) {
		pm = armv7_pcpu[cpu]->pc_armv7pmcs[ri].phw_pmc;
		if (pm == NULL)
			continue;
		if (!PMC_IS_SAMPLING_MODE(PMC_TO_MODE(pm)))
			continue;

		/* Check if counter has overflowed */
		if (pm->pm_md.pm_armv7.pm_armv7_evsel == 0xFF)
			reg = (1 << 31);
		else
			reg = (1 << ri);

		if ((armv7_flag_read() & reg) == 0) {
			continue;
		}

		/* Clear Overflow Flag */
		armv7_flag_write(reg);

		retval = 1; /* Found an interrupting PMC. */
		if (pm->pm_state != PMC_STATE_RUNNING)
			continue;

		error = pmc_process_interrupt(cpu, PMC_HR, pm, tf,
		    TRAPF_USERMODE(tf));
		if (error)
			armv7_stop_pmc(cpu, ri);

		/* Reload sampling count */
		armv7_write_pmc(cpu, ri, pm->pm_sc.pm_reloadcount);
	}

	return (retval);
}

static int
armv7_describe(int cpu, int ri, struct pmc_info *pi, struct pmc **ppmc)
{
	char armv7_name[PMC_NAME_MAX];
	struct pmc_hw *phw;
	int error;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[armv7,%d], illegal CPU %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < armv7_npmcs,
	    ("[armv7,%d] row-index %d out of range", __LINE__, ri));

	phw = &armv7_pcpu[cpu]->pc_armv7pmcs[ri];
	snprintf(armv7_name, sizeof(armv7_name), "ARMV7-%d", ri);
	if ((error = copystr(armv7_name, pi->pm_name, PMC_NAME_MAX,
	    NULL)) != 0)
		return error;
	pi->pm_class = PMC_CLASS_ARMV7;
	if (phw->phw_state & PMC_PHW_FLAG_IS_ENABLED) {
		pi->pm_enabled = TRUE;
		*ppmc = phw->phw_pmc;
	} else {
		pi->pm_enabled = FALSE;
		*ppmc = NULL;
	}

	return (0);
}

static int
armv7_get_config(int cpu, int ri, struct pmc **ppm)
{

	*ppm = armv7_pcpu[cpu]->pc_armv7pmcs[ri].phw_pmc;

	return 0;
}

/*
 * XXX don't know what we should do here.
 */
static int
armv7_switch_in(struct pmc_cpu *pc, struct pmc_process *pp)
{

	return 0;
}

static int
armv7_switch_out(struct pmc_cpu *pc, struct pmc_process *pp)
{

	return 0;
}

static int
armv7_pcpu_init(struct pmc_mdep *md, int cpu)
{
	struct armv7_cpu *pac;
	struct pmc_hw  *phw;
	struct pmc_cpu *pc;
	uint32_t pmnc;
	int first_ri;
	int cpuid;
	int i;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[armv7,%d] wrong cpu number %d", __LINE__, cpu));
	PMCDBG(MDP,INI,1,"armv7-init cpu=%d", cpu);

	armv7_pcpu[cpu] = pac = malloc(sizeof(struct armv7_cpu), M_PMC,
	    M_WAITOK|M_ZERO);

	cpuid = cpu_ident();
	pac->cortex_ver = (cpuid >> CPU_ID_CORTEX_VER_SHIFT) & \
				CPU_ID_CORTEX_VER_MASK;

	pac->pc_armv7pmcs = malloc(sizeof(struct pmc_hw) * armv7_npmcs,
	    M_PMC, M_WAITOK|M_ZERO);
	pc = pmc_pcpu[cpu];
	first_ri = md->pmd_classdep[PMC_MDEP_CLASS_INDEX_ARMV7].pcd_ri;
	KASSERT(pc != NULL, ("[armv7,%d] NULL per-cpu pointer", __LINE__));

	for (i = 0, phw = pac->pc_armv7pmcs; i < armv7_npmcs; i++, phw++) {
		phw->phw_state    = PMC_PHW_FLAG_IS_ENABLED |
		    PMC_PHW_CPU_TO_STATE(cpu) | PMC_PHW_INDEX_TO_STATE(i);
		phw->phw_pmc      = NULL;
		pc->pc_hwpmcs[i + first_ri] = phw;
	}

	/* Enable unit */
	pmnc = armv7_pmnc_read();
	pmnc |= ARMV7_PMNC_ENABLE;
	armv7_pmnc_write(pmnc);

	return 0;
}

static int
armv7_pcpu_fini(struct pmc_mdep *md, int cpu)
{
	uint32_t pmnc;

	pmnc = armv7_pmnc_read();
	pmnc &= ~ARMV7_PMNC_ENABLE;
	armv7_pmnc_write(pmnc);

	return 0;
}

struct pmc_mdep *
pmc_armv7_initialize()
{
	struct pmc_mdep *pmc_mdep;
	struct pmc_classdep *pcd;
	int reg;

	reg = armv7_pmnc_read();

	armv7_npmcs = (reg >> ARMV7_PMNC_N_SHIFT) & \
				ARMV7_PMNC_N_MASK;

	PMCDBG(MDP,INI,1,"armv7-init npmcs=%d", armv7_npmcs);
	
	/*
	 * Allocate space for pointers to PMC HW descriptors and for
	 * the MDEP structure used by MI code.
	 */
	armv7_pcpu = malloc(sizeof(struct armv7_cpu *) * pmc_cpu_max(),
		M_PMC, M_WAITOK | M_ZERO);

	/* Just one class */
	pmc_mdep = pmc_mdep_alloc(1);
	pmc_mdep->pmd_cputype = PMC_CPU_ARMV7;

	pcd = &pmc_mdep->pmd_classdep[PMC_MDEP_CLASS_INDEX_ARMV7];
	pcd->pcd_caps  = ARMV7_PMC_CAPS;
	pcd->pcd_class = PMC_CLASS_ARMV7;
	pcd->pcd_num   = armv7_npmcs;
	pcd->pcd_ri    = pmc_mdep->pmd_npmc;
	pcd->pcd_width = 32;

	pcd->pcd_allocate_pmc   = armv7_allocate_pmc;
	pcd->pcd_config_pmc     = armv7_config_pmc;
	pcd->pcd_pcpu_fini      = armv7_pcpu_fini;
	pcd->pcd_pcpu_init      = armv7_pcpu_init;
	pcd->pcd_describe       = armv7_describe;
	pcd->pcd_get_config	= armv7_get_config;
	pcd->pcd_read_pmc       = armv7_read_pmc;
	pcd->pcd_release_pmc    = armv7_release_pmc;
	pcd->pcd_start_pmc      = armv7_start_pmc;
	pcd->pcd_stop_pmc       = armv7_stop_pmc;
	pcd->pcd_write_pmc      = armv7_write_pmc;

	pmc_mdep->pmd_intr       = armv7_intr;
	pmc_mdep->pmd_switch_in  = armv7_switch_in;
	pmc_mdep->pmd_switch_out = armv7_switch_out;
	
	pmc_mdep->pmd_npmc   += armv7_npmcs;

	return (pmc_mdep);
}

void
pmc_armv7_finalize(struct pmc_mdep *md)
{

}
