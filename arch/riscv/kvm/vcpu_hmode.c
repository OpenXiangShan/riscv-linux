// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>

#include <asm/csr.h>
#include <asm/insn.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_nacl.h>
#include <asm/kvm_tlb.h>
#include <asm/pgtable-bits.h>

#include "sting_config.h"

#define KVM_RISCV_HSTATUS_WRITABLE	(HSTATUS_VTSR | HSTATUS_VTW | \
					 HSTATUS_VTVM | HSTATUS_VGEIN | \
					 HSTATUS_HU | HSTATUS_SPVP | \
					 HSTATUS_SPV | HSTATUS_GVA | \
					 HSTATUS_VSBE)
/* HEDELEG is the VS subset of the architectural delegable exceptions. */
#define KVM_RISCV_HEDELEG_MASK		(BIT(EXC_INST_MISALIGNED) | \
					 BIT(EXC_INST_ACCESS) | \
					 BIT(EXC_INST_ILLEGAL) | \
					 BIT(EXC_BREAKPOINT) | \
					 BIT(EXC_LOAD_MISALIGNED) | \
					 BIT(EXC_LOAD_ACCESS) | \
					 BIT(EXC_STORE_MISALIGNED) | \
					 BIT(EXC_STORE_ACCESS) | BIT(EXC_SYSCALL) | \
					 BIT(EXC_INST_PAGE_FAULT) | \
					 BIT(EXC_LOAD_PAGE_FAULT) | \
					 BIT(EXC_STORE_PAGE_FAULT) | BIT(18) | BIT(19))
#define KVM_RISCV_HIDELEG_MASK		(BIT(IRQ_VS_SOFT) | \
					 BIT(IRQ_VS_TIMER) | \
					 BIT(IRQ_VS_EXT) | \
					 BIT(IRQ_PMU_OVF))
#define KVM_RISCV_SSTATUS_MXR		BIT(19)
#define KVM_RISCV_CSR_HSTATEEN1		0x60d
#define KVM_RISCV_CSR_HSTATEEN2		0x60e
#define KVM_RISCV_CSR_HSTATEEN3		0x60f

static unsigned long hmode_rmw(unsigned long old, unsigned long new_val,
			       unsigned long wr_mask)
{
	return (old & ~wr_mask) | (new_val & wr_mask);
}

static void hmode_save_vs(struct kvm_vcpu_hmode_vs *vs)
{
	vs->vsstatus = ncsr_read(CSR_VSSTATUS);
	vs->vsie = ncsr_read(CSR_VSIE);
	vs->vstvec = ncsr_read(CSR_VSTVEC);
	vs->vsscratch = ncsr_read(CSR_VSSCRATCH);
	vs->vsepc = ncsr_read(CSR_VSEPC);
	vs->vscause = ncsr_read(CSR_VSCAUSE);
	vs->vstval = ncsr_read(CSR_VSTVAL);
	vs->vsatp = ncsr_read(CSR_VSATP);
	vs->vsiselect = ncsr_read(CSR_VSISELECT);
	if (riscv_isa_extension_available(NULL, SSTC))
		vs->vstimecmp = ncsr_read(CSR_VSTIMECMP);
}

static void hmode_load_vs(const struct kvm_vcpu_hmode_vs *vs)
{
	ncsr_write(CSR_VSSTATUS, vs->vsstatus);
	ncsr_write(CSR_VSIE, vs->vsie);
	ncsr_write(CSR_VSTVEC, vs->vstvec);
	ncsr_write(CSR_VSSCRATCH, vs->vsscratch);
	ncsr_write(CSR_VSEPC, vs->vsepc);
	ncsr_write(CSR_VSCAUSE, vs->vscause);
	ncsr_write(CSR_VSTVAL, vs->vstval);
	ncsr_write(CSR_VSATP, vs->vsatp);
	ncsr_write(CSR_VSISELECT, vs->vsiselect);
	if (riscv_isa_extension_available(NULL, SSTC))
		ncsr_write(CSR_VSTIMECMP, vs->vstimecmp);
}

static void hmode_copy_to_guest_csr(struct kvm_vcpu *vcpu,
				    const struct kvm_vcpu_hmode_vs *vs)
{
	struct kvm_vcpu_csr *csr = &vcpu->arch.guest_csr;

	csr->vsstatus = vs->vsstatus;
	csr->vsie = vs->vsie;
	csr->vstvec = vs->vstvec;
	csr->vsscratch = vs->vsscratch;
	csr->vsepc = vs->vsepc;
	csr->vscause = vs->vscause;
	csr->vstval = vs->vstval;
	csr->vsatp = vs->vsatp;
}

static void hmode_sync_controls(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;
	struct kvm_vcpu_config *cfg = &vcpu->arch.cfg;
	unsigned long controls = HSTATUS_VTSR | HSTATUS_VTW | HSTATUS_VTVM;

	if (vcpu->kvm->arch.m_mode) {
		cfg->hedeleg = kvm_riscv_vcpu_mmode_hedeleg(vcpu);
		cfg->hideleg = kvm_riscv_vcpu_mmode_hideleg(vcpu);
		cfg->hcounteren = kvm_riscv_vcpu_mmode_hcounteren(vcpu);
		if (h->active) {
			cfg->hedeleg &= h->hedeleg;
			cfg->hideleg &= h->hideleg;
			cfg->hcounteren &= h->hcounteren;
		}
	} else if (h->active) {
		cfg->hedeleg = h->hedeleg;
		cfg->hideleg = h->hideleg;
		cfg->hcounteren = h->hcounteren;
	} else {
		cfg->hedeleg = KVM_HEDELEG_DEFAULT;
		cfg->hideleg = KVM_HIDELEG_DEFAULT;
	}

	vcpu->arch.guest_context.hstatus &= ~controls;
	if (h->active)
		vcpu->arch.guest_context.hstatus |= h->hstatus & controls;
	else
		vcpu->arch.guest_context.hstatus |= HSTATUS_VTSR;

	ncsr_write(CSR_HEDELEG, cfg->hedeleg);
	ncsr_write(CSR_HIDELEG, cfg->hideleg);
	ncsr_write(CSR_HCOUNTEREN, cfg->hcounteren);
}

static void hmode_switch(struct kvm_vcpu *vcpu, bool active)
{
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;
	struct kvm_vcpu_hmode_vs *from = h->active ? &h->vs : &h->hs;
	struct kvm_vcpu_hmode_vs *to = active ? &h->vs : &h->hs;

	if (h->active == active)
		return;

	hmode_save_vs(from);
	hmode_load_vs(to);
	hmode_copy_to_guest_csr(vcpu, to);
	h->active = active;
	hmode_sync_controls(vcpu);
	kvm_riscv_mmu_update_hgatp(vcpu);
	kvm_riscv_local_hfence_gvma_all();
	kvm_riscv_local_hfence_vvma_all(
		READ_ONCE(vcpu->kvm->arch.vmid.vmid));
}

void kvm_riscv_vcpu_hmode_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;
	pgd_t *pgd = h->pgd;
	phys_addr_t pgd_phys = h->pgd_phys;

	memset(h, 0, sizeof(*h));
	h->pgd = pgd;
	h->pgd_phys = pgd_phys;
	if (!vcpu->kvm->arch.nested)
		return;

#ifdef CONFIG_64BIT
	h->hstatus = 2UL << HSTATUS_VSXL_SHIFT;
#endif
	h->hedeleg = KVM_HEDELEG_DEFAULT;
	h->hideleg = KVM_HIDELEG_DEFAULT;
}

bool kvm_riscv_vcpu_hmode_active(struct kvm_vcpu *vcpu)
{
	return vcpu->kvm->arch.nested && vcpu->arch.hmode.active;
}

void kvm_riscv_vcpu_hmode_set_active(struct kvm_vcpu *vcpu, bool active)
{
	if (!vcpu->kvm->arch.nested)
		return;
	if (vcpu->arch.hmode.active == active)
		hmode_sync_controls(vcpu);
	else
		hmode_switch(vcpu, active);
}

static int hmode_hgatp_write(struct kvm_vcpu *vcpu, unsigned long val)
{
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;
	unsigned long mode = val >> HGATP_MODE_SHIFT;

	switch (mode) {
	case HGATP_MODE_OFF:
#ifdef CONFIG_64BIT
	case HGATP_MODE_SV39X4:
	case HGATP_MODE_SV48X4:
	case HGATP_MODE_SV57X4:
#else
	case HGATP_MODE_SV32X4:
#endif
		break;
	default:
		val = 0;
		break;
	}

	/* Every x4 root is naturally aligned to four base pages. */
	if (mode != HGATP_MODE_OFF)
		val &= ~3UL;
	if (val != h->hgatp)
		kvm_riscv_nested_mmu_flush(vcpu);
	h->hgatp = val;
	return 0;
}

int kvm_riscv_vcpu_hmode_csr_rmw(struct kvm_vcpu *vcpu,
				 unsigned int csr_num,
				 unsigned long *val,
				 unsigned long new_val,
				 unsigned long wr_mask)
{
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;
	struct kvm_vcpu_hmode_vs *vs = &h->vs;
	unsigned long old, mask = ~0UL, *reg = NULL;

	if (!vcpu->kvm->arch.nested || h->active)
		return KVM_INSN_VIRTUAL_TRAP;

	switch (csr_num) {
	case CSR_HSTATUS:
		old = h->hstatus;
		*val = old;
		h->hstatus = hmode_rmw(old, new_val,
					 wr_mask & KVM_RISCV_HSTATUS_WRITABLE);
#ifdef CONFIG_64BIT
		h->hstatus &= ~HSTATUS_VSXL;
		h->hstatus |= 2UL << HSTATUS_VSXL_SHIFT;
#endif
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_HEDELEG:
		reg = &h->hedeleg;
		mask = KVM_RISCV_HEDELEG_MASK;
		break;
	case CSR_HIDELEG:
		reg = &h->hideleg;
		mask = KVM_RISCV_HIDELEG_MASK;
		break;
	case CSR_HIE:
		reg = &h->hie;
		mask = KVM_RISCV_HIDELEG_MASK;
		break;
	case CSR_HVIEN:
		reg = &h->hvien;
		break;
	case CSR_HVICTL:
		reg = &h->hvictl;
		break;
	case CSR_HCOUNTEREN:
		reg = &h->hcounteren;
		break;
	case CSR_HGEIE:
		*val = 0;
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_HENVCFG:
		old = h->henvcfg;
		*val = old;
		/* HENVCFG bits are only writable when MENVCFG enables them. */
		if (vcpu->kvm->arch.m_mode && vcpu->arch.mmode.active)
			wr_mask &= vcpu->arch.mmode.menvcfg;
		h->henvcfg = hmode_rmw(old, new_val, wr_mask);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_HSTATEEN0:
		old = h->hstateen0;
		*val = old;
		h->hstateen0 = hmode_rmw(old, new_val, wr_mask);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case KVM_RISCV_CSR_HSTATEEN1:
		old = h->hstateen1;
		*val = old;
		h->hstateen1 = hmode_rmw(old, new_val, wr_mask);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case KVM_RISCV_CSR_HSTATEEN2:
		old = h->hstateen2;
		*val = old;
		h->hstateen2 = hmode_rmw(old, new_val, wr_mask);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case KVM_RISCV_CSR_HSTATEEN3:
		old = h->hstateen3;
		*val = old;
		h->hstateen3 = hmode_rmw(old, new_val, wr_mask);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_HTIMEDELTA:
		old = h->htimedelta;
		*val = old;
		h->htimedelta = hmode_rmw(old, new_val, wr_mask);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_HTVAL:
		reg = &h->htval;
		break;
	case CSR_HIP:
		*val = h->hvip & KVM_RISCV_HIDELEG_MASK;
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_HVIP:
		reg = &h->hvip;
		mask = KVM_RISCV_HIDELEG_MASK;
		break;
	case CSR_HTINST:
		reg = &h->htinst;
		break;
	case CSR_HGATP:
		old = h->hgatp;
		*val = old;
		if (wr_mask)
			hmode_hgatp_write(vcpu,
				hmode_rmw(old, new_val, wr_mask));
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_HVIPRIO1:
		reg = &h->hviprio1;
		break;
	case CSR_HVIPRIO2:
		reg = &h->hviprio2;
		break;
	case CSR_HGEIP:
		*val = 0;
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_VSSTATUS:
		reg = &vs->vsstatus;
		break;
	case CSR_VSIE:
		reg = &vs->vsie;
		break;
	case CSR_VSTVEC:
		reg = &vs->vstvec;
		break;
	case CSR_VSSCRATCH:
		reg = &vs->vsscratch;
		break;
	case CSR_VSEPC:
		reg = &vs->vsepc;
		break;
	case CSR_VSCAUSE:
		reg = &vs->vscause;
		break;
	case CSR_VSTVAL:
		reg = &vs->vstval;
		break;
	case CSR_VSIP:
		reg = &vs->vsip;
		mask = VSIP_VALID_MASK;
		break;
	case CSR_VSATP:
		reg = &vs->vsatp;
		break;
	case CSR_VSISELECT:
		reg = &vs->vsiselect;
		break;
	case CSR_VSTIMECMP:
		old = vs->vstimecmp;
		*val = old;
		vs->vstimecmp = hmode_rmw(old, new_val, wr_mask);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	default:
		return KVM_INSN_ILLEGAL_TRAP;
	}

	old = *reg;
	*val = old;
	*reg = hmode_rmw(old, new_val, wr_mask & mask);
	if (csr_num == CSR_VSEPC)
		*reg &= ~1UL;
	if (csr_num == CSR_VSTVEC && (*reg & 3) > 1)
		*reg &= ~3UL;
	return KVM_INSN_CONTINUE_NEXT_SEPC;
}

int kvm_riscv_vcpu_hmode_sret(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;
	struct kvm_vcpu_hmode_vs *hs = &h->hs;
	unsigned long target, previous_spp;
	bool return_vs, return_supervisor;

	if (!vcpu->kvm->arch.nested || h->active)
		return KVM_INSN_VIRTUAL_TRAP;

	hmode_save_vs(hs);
	previous_spp = hs->vsstatus & SR_SPP;
	return_vs = h->hstatus & HSTATUS_SPV;
	target = hs->vsepc;
	return_supervisor = previous_spp;

	if (hs->vsstatus & SR_SPIE)
		hs->vsstatus |= SR_SIE;
	else
		hs->vsstatus &= ~SR_SIE;
	hs->vsstatus |= SR_SPIE;
	hs->vsstatus &= ~SR_SPP;
	h->hstatus &= ~(HSTATUS_SPV | HSTATUS_GVA);

	if (return_vs) {
		/* Preserve the architectural sret updates across the bank switch. */
		hmode_load_vs(hs);
		hmode_switch(vcpu, true);
	} else {
		hmode_load_vs(hs);
	}

	if (return_supervisor)
		vcpu->arch.guest_context.sstatus |= SR_SPP;
	else
		vcpu->arch.guest_context.sstatus &= ~SR_SPP;
	vcpu->arch.guest_context.sepc = target;
	return KVM_INSN_CONTINUE_SAME_SEPC;
}

int kvm_riscv_vcpu_hmode_fence(struct kvm_vcpu *vcpu, unsigned long insn)
{
	unsigned int funct7 = insn >> 25;

	if (!vcpu->kvm->arch.nested)
		return KVM_INSN_ILLEGAL_TRAP;
	if (vcpu->arch.hmode.active)
		return KVM_INSN_VIRTUAL_TRAP;

	switch (funct7) {
	case 0x11: /* HFENCE.VVMA */
	case 0x13: /* HINVAL.VVMA */
		break;
	case 0x31: /* HFENCE.GVMA */
	case 0x33: /* HINVAL.GVMA */
		kvm_riscv_nested_mmu_flush(vcpu);
		break;
	default:
		return KVM_INSN_ILLEGAL_TRAP;
	}

	kvm_riscv_local_hfence_gvma_all();
	kvm_riscv_local_hfence_vvma_all(
		READ_ONCE(vcpu->kvm->arch.vmid.vmid));
	return KVM_INSN_CONTINUE_NEXT_SEPC;
}

int kvm_riscv_vcpu_hmode_trap(struct kvm_vcpu *vcpu,
			      struct kvm_cpu_trap *trap)
{
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;
	struct kvm_vcpu_hmode_vs *hs = &h->hs;
	bool previous_supervisor;

	if (!kvm_riscv_vcpu_hmode_active(vcpu) &&
	    !kvm_riscv_vcpu_mmode_mprv_virtual(vcpu))
		return -EOPNOTSUPP;

	previous_supervisor = vcpu->arch.guest_context.sstatus & SR_SPP;
	hmode_switch(vcpu, false);

	hs->vsepc = trap->sepc;
	hs->vscause = trap->scause;
	hs->vstval = trap->stval;
	if (hs->vsstatus & SR_SIE)
		hs->vsstatus |= SR_SPIE;
	else
		hs->vsstatus &= ~SR_SPIE;
	hs->vsstatus &= ~(SR_SIE | SR_SPP);
	if (previous_supervisor)
		hs->vsstatus |= SR_SPP;
	h->htval = trap->htval;
	h->htinst = trap->htinst;
	h->hstatus |= HSTATUS_SPV;
	if (previous_supervisor)
		h->hstatus |= HSTATUS_SPVP;
	else
		h->hstatus &= ~HSTATUS_SPVP;
	if (trap->scause == EXC_INST_GUEST_PAGE_FAULT ||
	    trap->scause == EXC_LOAD_GUEST_PAGE_FAULT ||
	    trap->scause == EXC_STORE_GUEST_PAGE_FAULT)
		h->hstatus |= HSTATUS_GVA;
	else
		h->hstatus &= ~HSTATUS_GVA;

	hmode_load_vs(hs);
	hmode_copy_to_guest_csr(vcpu, hs);
	vcpu->arch.guest_context.sstatus |= SR_SPP;
	vcpu->arch.guest_context.sepc = hs->vstvec & ~3UL;
	return 1;
}

int kvm_riscv_vcpu_hmode_check_interrupt(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;
	struct kvm_cpu_trap trap = {
		.sepc = vcpu->arch.guest_context.sepc,
	};
	unsigned long pending;
	unsigned long hs_ie;
	unsigned long root_hvip;
	unsigned int irq;

	if (!kvm_riscv_vcpu_hmode_active(vcpu))
		return 0;

	/*
	 * The physical VS interrupt state belongs to L1 while the second VS
	 * bank is running L2.  Do not inject an L1 timer/software/external
	 * interrupt into L2: make the emulated HS take it first.  VS interrupt
	 * pending bits are one position above the S-mode causes seen by L1.
	 */
	hs_ie = (h->hs.vsie & VSIP_VALID_MASK) << VSIP_TO_HVIP_SHIFT;
	hs_ie |= h->hs.vsie & ~IRQ_LOCAL_MASK;
	root_hvip = READ_ONCE(vcpu->arch.guest_csr.hvip) |
		    READ_ONCE(vcpu->arch.irqs_pending[0]);
	pending = root_hvip & hs_ie &
		  KVM_RISCV_HIDELEG_MASK;
	if (!pending)
		return 0;

	if (pending & BIT(IRQ_VS_EXT))
		irq = IRQ_VS_EXT;
	else if (pending & BIT(IRQ_VS_SOFT))
		irq = IRQ_VS_SOFT;
	else if (pending & BIT(IRQ_VS_TIMER))
		irq = IRQ_VS_TIMER;
	else
		return 0;

	vcpu->arch.guest_csr.hvip |= BIT(irq);
	trap.scause = CAUSE_IRQ_FLAG | (irq - 1);
	return kvm_riscv_vcpu_hmode_trap(vcpu, &trap);
}

struct hmode_gstage_walk {
	gpa_t source_gpa;
	bool writable;
	bool executable;
	int level;
	gpa_t pte_gpa;
	u64 pte;
};

struct hmode_vsstage_walk {
	gpa_t nested_gpa;
	gpa_t fault_gpa;
};

static int hmode_walk_gstage(struct kvm_vcpu *vcpu, gpa_t gpa,
			     unsigned long scause, unsigned long vsstatus,
			     struct hmode_gstage_walk *walk)
{
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;
	u64 pte, ppn, page_mask;
	gpa_t table;
	unsigned long mode, index, shift;
	int level, levels;

	memset(walk, 0, sizeof(*walk));
	walk->level = -1;
	mode = h->hgatp >> HGATP_MODE_SHIFT;
	if (mode == HGATP_MODE_OFF) {
		walk->source_gpa = gpa;
		walk->writable = true;
		walk->executable = true;
		return 0;
	}

#ifdef CONFIG_64BIT
	switch (mode) {
	case HGATP_MODE_SV39X4:
		levels = 3;
		break;
	case HGATP_MODE_SV48X4:
		levels = 4;
		break;
	case HGATP_MODE_SV57X4:
		levels = 5;
		break;
	default:
		return -EINVAL;
	}
#else
	if (mode != HGATP_MODE_SV32X4)
		return -EINVAL;
	levels = 2;
#endif

	table = (h->hgatp & HGATP_PPN) << PAGE_SHIFT;
	for (level = levels - 1; level >= 0; level--) {
		shift = PAGE_SHIFT + level * kvm_riscv_gstage_index_bits;
		index = (gpa >> shift) &
			((level == levels - 1) ? GENMASK(10, 0) : GENMASK(8, 0));
		walk->level = level;
		walk->pte_gpa = table + index * sizeof(pte);
		walk->pte = 0;
		if (kvm_read_guest(vcpu->kvm, walk->pte_gpa,
				   &pte, sizeof(pte)))
			return -EFAULT;
		walk->pte = pte;
		if (!(pte & _PAGE_PRESENT) ||
		    ((pte & _PAGE_WRITE) && !(pte & _PAGE_READ)))
			return -EFAULT;

		ppn = (pte >> _PAGE_PFN_SHIFT) & HGATP_PPN;
		if (!(pte & _PAGE_LEAF)) {
			if (!level)
				return -EFAULT;
			table = ppn << PAGE_SHIFT;
			continue;
		}

		if (!(pte & _PAGE_ACCESSED) ||
		    (scause == EXC_STORE_GUEST_PAGE_FAULT &&
		     (!(pte & _PAGE_WRITE) || !(pte & _PAGE_DIRTY))) ||
		    (scause == EXC_INST_GUEST_PAGE_FAULT &&
		     !(pte & _PAGE_EXEC)) ||
		    (scause == EXC_LOAD_GUEST_PAGE_FAULT &&
		     !(pte & _PAGE_READ) &&
		     (!(vsstatus & KVM_RISCV_SSTATUS_MXR) ||
		      !(pte & _PAGE_EXEC))))
			return -EACCES;

		page_mask = BIT_ULL(PAGE_SHIFT +
				    level * kvm_riscv_gstage_index_bits) - 1;
		if ((ppn << PAGE_SHIFT) & page_mask)
			return -EFAULT;
		walk->source_gpa = (ppn << PAGE_SHIFT) | (gpa & page_mask);
		walk->writable = pte & _PAGE_WRITE;
		walk->executable = pte & _PAGE_EXEC;
		return 0;
	}

	return -EFAULT;
}

static int hmode_walk_vsstage(struct kvm_vcpu *vcpu, unsigned long gva,
			      unsigned long vsatp,
			      unsigned long vsstatus,
			      bool virtual_supervisor, bool use_nested,
			      bool is_write, bool is_exec,
			      struct hmode_vsstage_walk *walk)
{
	struct hmode_gstage_walk gstage;
	unsigned long mode, index, shift;
	u64 pte, ppn, page_mask;
	gpa_t table;
	int level, levels, ret;

	memset(walk, 0, sizeof(*walk));
	mode = vsatp >> SATP_MODE_SHIFT;
	if (!mode) {
		walk->nested_gpa = gva;
		return 0;
	}

#ifdef CONFIG_64BIT
	switch (mode) {
	case 8:
		levels = 3;
		break;
	case 9:
		levels = 4;
		break;
	case 10:
		levels = 5;
		break;
	default:
		return -EINVAL;
	}
#else
	if (mode != 1)
		return -EINVAL;
	levels = 2;
#endif

	table = (vsatp & SATP_PPN) << PAGE_SHIFT;
	for (level = levels - 1; level >= 0; level--) {
		shift = PAGE_SHIFT + level * kvm_riscv_gstage_index_bits;
		index = (gva >> shift) &
			((1UL << kvm_riscv_gstage_index_bits) - 1);
		walk->fault_gpa = table + index * sizeof(pte);
		if (use_nested)
			ret = hmode_walk_gstage(vcpu, walk->fault_gpa,
					 EXC_LOAD_GUEST_PAGE_FAULT, vsstatus,
					 &gstage);
		else {
			gstage.source_gpa = walk->fault_gpa;
			ret = 0;
		}
		if (ret)
			return -EREMOTE;
		if (kvm_read_guest(vcpu->kvm, gstage.source_gpa,
				   &pte, sizeof(pte)))
			return -EREMOTE;
		if (!(pte & _PAGE_PRESENT) ||
		    ((pte & _PAGE_WRITE) && !(pte & _PAGE_READ)))
			return -EFAULT;

		ppn = (pte >> _PAGE_PFN_SHIFT) & SATP_PPN;
		if (!(pte & _PAGE_LEAF)) {
			if (!level)
				return -EFAULT;
			table = ppn << PAGE_SHIFT;
			continue;
		}

		if (!(pte & _PAGE_ACCESSED) ||
		    (is_write && (!(pte & _PAGE_WRITE) ||
				  !(pte & _PAGE_DIRTY))) ||
		    (is_exec && !(pte & _PAGE_EXEC)) ||
		    (!is_write && !is_exec && !(pte & _PAGE_READ) &&
			     (!(vsstatus & KVM_RISCV_SSTATUS_MXR) ||
			      !(pte & _PAGE_EXEC))))
			return -EACCES;
		if (virtual_supervisor) {
			if ((pte & _PAGE_USER) &&
			    (is_exec || !(vsstatus & SR_SUM)))
				return -EACCES;
		} else if (!(pte & _PAGE_USER)) {
			return -EACCES;
		}

		page_mask = BIT_ULL(PAGE_SHIFT +
				    level * kvm_riscv_gstage_index_bits) - 1;
		if ((ppn << PAGE_SHIFT) & page_mask)
			return -EFAULT;
		walk->nested_gpa = (ppn << PAGE_SHIFT) | (gva & page_mask);
		return 0;
	}

	return -EFAULT;
}

static int hmode_walk_combined(struct kvm_vcpu *vcpu, unsigned long gva,
			       unsigned long vsatp,
			       unsigned long vsstatus,
			       bool virtual_supervisor, bool use_nested,
			       bool is_write, bool is_exec,
			       struct hmode_vsstage_walk *vsstage,
			       struct hmode_gstage_walk *gstage,
			       bool *gstage_fault)
{
	int ret;

	*gstage_fault = false;
	ret = hmode_walk_vsstage(vcpu, gva, vsatp, vsstatus,
				 virtual_supervisor, use_nested,
				 is_write, is_exec, vsstage);
	if (ret)
		return ret;

	*gstage_fault = true;
	if (use_nested)
		return hmode_walk_gstage(vcpu, vsstage->nested_gpa,
			is_write ? EXC_STORE_GUEST_PAGE_FAULT :
			(is_exec ? EXC_INST_GUEST_PAGE_FAULT :
			 EXC_LOAD_GUEST_PAGE_FAULT), vsstatus, gstage);

	gstage->source_gpa = vsstage->nested_gpa;
	gstage->writable = true;
	gstage->executable = true;
	return 0;
}

int kvm_riscv_vcpu_hmode_translate(struct kvm_vcpu *vcpu,
				   unsigned long gva, bool is_write,
				   bool is_exec, gpa_t *source_gpa)
{
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;
	struct hmode_vsstage_walk vsstage;
	struct hmode_gstage_walk gstage;
	unsigned long mstatus = vcpu->arch.mmode.mstatus;
	unsigned long vsstatus = h->vs.vsstatus;
	unsigned long mpp = (mstatus & SR_MPP) >> 11;
	bool gstage_fault;
	int ret;

	if (!kvm_riscv_vcpu_mmode_mprv_virtual(vcpu))
		return -EINVAL;
	vsstatus &= ~(SR_SUM | KVM_RISCV_SSTATUS_MXR);
	vsstatus |= mstatus & (SR_SUM | KVM_RISCV_SSTATUS_MXR);
	ret = hmode_walk_combined(vcpu, gva, h->vs.vsatp, vsstatus,
				  mpp != KVM_RISCV_MODE_U, true,
				  is_write, is_exec, &vsstage, &gstage,
				  &gstage_fault);
	if (!ret)
		*source_gpa = gstage.source_gpa;
	return ret;
}

static int hmode_inject_hs(struct kvm_vcpu *vcpu, unsigned long cause,
			   unsigned long tval, unsigned long htval,
			   unsigned long htinst, bool gva)
{
	struct kvm_cpu_trap trap = {
		.sepc = vcpu->arch.guest_context.sepc,
		.scause = cause,
		.stval = tval,
	};
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;

	h->htval = htval;
	h->htinst = htinst;
	if (gva)
		h->hstatus |= HSTATUS_GVA;
	else
		h->hstatus &= ~HSTATUS_GVA;
	if (vcpu->kvm->arch.m_mode &&
	    !kvm_riscv_vcpu_mmode_exception_delegated(vcpu, cause))
		return kvm_riscv_vcpu_mmode_trap(vcpu, cause, tval);
	kvm_riscv_vcpu_trap_redirect(vcpu, &trap);
	return 1;
}

int kvm_riscv_vcpu_hmode_hlv_hsv(struct kvm_vcpu *vcpu,
				 unsigned long insn)
{
	struct kvm_vcpu_hmode *h = &vcpu->arch.hmode;
	struct hmode_vsstage_walk vsstage;
	struct hmode_gstage_walk gstage;
	struct kvm_cpu_context *ct = &vcpu->arch.guest_context;
	unsigned long addr, value = 0, vsatp, vsstatus;
	bool use_nested, gstage_fault;
	unsigned int funct7, rs2;
	bool is_store, is_exec = false, is_unsigned = false;
	int len, ret;

	if (!vcpu->kvm->arch.nested)
		return KVM_INSN_ILLEGAL_TRAP;
	if (vcpu->arch.hmode.active)
		return KVM_INSN_VIRTUAL_TRAP;

	funct7 = (insn >> 25) & 0x7f;
	rs2 = (insn >> 20) & 0x1f;
	is_store = funct7 & 1;
	switch (funct7) {
	case 48:
		if (rs2 > 1)
			return KVM_INSN_ILLEGAL_TRAP;
		len = 1;
		is_unsigned = rs2;
		break;
	case 50:
		if (rs2 != 0 && rs2 != 1 && rs2 != 3)
			return KVM_INSN_ILLEGAL_TRAP;
		len = 2;
		is_unsigned = rs2 != 0;
		is_exec = rs2 == 3;
		break;
	case 52:
		if (rs2 != 0 && rs2 != 1 && rs2 != 3)
			return KVM_INSN_ILLEGAL_TRAP;
		len = 4;
		is_unsigned = rs2 != 0;
		is_exec = rs2 == 3;
		break;
#ifdef CONFIG_64BIT
	case 54:
		if (rs2)
			return KVM_INSN_ILLEGAL_TRAP;
		len = 8;
		break;
#endif
	case 49:
		len = 1;
		break;
	case 51:
		len = 2;
		break;
	case 53:
		len = 4;
		break;
#ifdef CONFIG_64BIT
	case 55:
		len = 8;
		break;
#endif
	default:
		return KVM_INSN_ILLEGAL_TRAP;
	}

	addr = GET_RS1(insn, ct);
	if (addr & (len - 1))
		return hmode_inject_hs(vcpu,
			is_store ? EXC_STORE_MISALIGNED : EXC_LOAD_MISALIGNED,
			addr, 0, insn, true);
	/* HLV/HSV in HS always uses the architectural nested VS context. */
	use_nested = vcpu->kvm->arch.nested;
	vsatp = h->vs.vsatp;
	vsstatus = h->vs.vsstatus;
	ret = hmode_walk_combined(vcpu, addr, vsatp, vsstatus,
				  h->hstatus & HSTATUS_SPVP, use_nested,
				  is_store, is_exec, &vsstage, &gstage,
				  &gstage_fault);
	if (ret) {
		if (gstage_fault) {
			return hmode_inject_hs(vcpu,
				is_store ? EXC_STORE_GUEST_PAGE_FAULT :
				(is_exec ? EXC_INST_GUEST_PAGE_FAULT :
				 EXC_LOAD_GUEST_PAGE_FAULT),
				addr, vsstage.nested_gpa >> 2, insn, true);
		}
		return hmode_inject_hs(vcpu,
			is_store ? EXC_STORE_PAGE_FAULT :
			(is_exec ? EXC_INST_PAGE_FAULT : EXC_LOAD_PAGE_FAULT),
			addr, ret == -EREMOTE ? vsstage.fault_gpa >> 2 : 0,
			insn, true);
	}

	if (is_store) {
		value = GET_RS2(insn, ct);
		ret = kvm_write_guest(vcpu->kvm, gstage.source_gpa,
				      &value, len);
	} else {
		ret = kvm_read_guest(vcpu->kvm, gstage.source_gpa,
				     &value, len);
	}
	if (ret)
		return hmode_inject_hs(vcpu,
			is_store ? EXC_STORE_ACCESS : EXC_LOAD_ACCESS,
			addr, 0, insn, true);

	if (!is_store) {
		if (!is_unsigned) {
			switch (len) {
			case 1:
				value = (long)(s8)value;
				break;
			case 2:
				value = (long)(s16)value;
				break;
			case 4:
				value = (long)(s32)value;
				break;
			}
		}
		SET_RD(insn, ct, value);
	}
	ct->sepc += INSN_LEN(insn);
	return KVM_INSN_CONTINUE_SAME_SEPC;
}

int kvm_riscv_vcpu_hmode_page_fault(struct kvm_vcpu *vcpu,
				    struct kvm_run *run,
				    struct kvm_cpu_trap *trap)
{
	struct hmode_gstage_walk walk;
	struct kvm_gstage_mapping host_map;
	struct kvm_memory_slot *memslot;
	unsigned long hva;
	gpa_t nested_gpa;
	gfn_t source_gfn;
	bool slot_writable;
	unsigned long vsstatus = vcpu->arch.hmode.vs.vsstatus;
	int ret;

	if (!kvm_riscv_vcpu_hmode_active(vcpu) &&
	    !kvm_riscv_vcpu_mmode_mprv_virtual(vcpu))
		return -EOPNOTSUPP;

	nested_gpa = (trap->htval << 2) | (trap->stval & 3);
	if (kvm_riscv_sting_log_enabled(KVM_RISCV_STING_LOG_NESTED))
		kvm_info("STING_NESTED fault pc=0x%lx cause=0x%lx tval=0x%lx htval=0x%lx htinst=0x%lx nested_gpa=0x%llx l1_hgatp=0x%lx mmode=%d hmode=%d mprv_virtual=%d\n",
			 vcpu->arch.guest_context.sepc, trap->scause,
			 trap->stval, trap->htval, trap->htinst,
			 (unsigned long long)nested_gpa,
			 vcpu->arch.hmode.hgatp, vcpu->arch.mmode.active,
			 kvm_riscv_vcpu_hmode_active(vcpu),
			 kvm_riscv_vcpu_mmode_mprv_virtual(vcpu));
	if (kvm_riscv_vcpu_mmode_mprv_virtual(vcpu)) {
		vsstatus &= ~(SR_SUM | KVM_RISCV_SSTATUS_MXR);
		vsstatus |= vcpu->arch.mmode.mstatus &
			    (SR_SUM | KVM_RISCV_SSTATUS_MXR);
	}
	ret = hmode_walk_gstage(vcpu, nested_gpa, trap->scause, vsstatus,
				&walk);
	if (ret) {
		if (kvm_riscv_sting_log_enabled(KVM_RISCV_STING_LOG_NESTED))
			kvm_info("STING_NESTED walk failed pc=0x%lx cause=0x%lx tval=0x%lx htval=0x%lx nested_gpa=0x%llx l1_hgatp=0x%lx level=%d pte_gpa=0x%llx pte=0x%llx ret=%d action=inject_l1\n",
				 vcpu->arch.guest_context.sepc, trap->scause,
				 trap->stval, trap->htval,
				 (unsigned long long)nested_gpa,
				 vcpu->arch.hmode.hgatp, walk.level,
				 (unsigned long long)walk.pte_gpa,
				 (unsigned long long)walk.pte, ret);
		return kvm_riscv_vcpu_hmode_trap(vcpu, trap);
	}

	source_gfn = walk.source_gpa >> PAGE_SHIFT;
	memslot = gfn_to_memslot(vcpu->kvm, source_gfn);
	hva = gfn_to_hva_memslot_prot(memslot, source_gfn, &slot_writable);
	if (kvm_is_error_hva(hva) ||
	    (trap->scause == EXC_STORE_GUEST_PAGE_FAULT && !slot_writable)) {
		switch (trap->scause) {
		case EXC_INST_GUEST_PAGE_FAULT: {
			struct kvm_cpu_trap access_trap = *trap;

			/* The nested walk succeeded; the source GPA is not memory. */
			if (kvm_riscv_sting_log_enabled(KVM_RISCV_STING_LOG_NESTED))
				kvm_info("STING_NESTED source unmapped pc=0x%lx cause=0x%lx nested_gpa=0x%llx source_gpa=0x%llx action=inject_inst_access\n",
					 vcpu->arch.guest_context.sepc,
					 trap->scause,
					 (unsigned long long)nested_gpa,
					 (unsigned long long)walk.source_gpa);
			access_trap.scause = EXC_INST_ACCESS;
			access_trap.htval = 0;
			access_trap.htinst = 0;
			if (vcpu->kvm->arch.m_mode &&
			    !kvm_riscv_vcpu_mmode_exception_delegated(
						vcpu, EXC_INST_ACCESS))
				return kvm_riscv_vcpu_mmode_trap(
					vcpu, EXC_INST_ACCESS, access_trap.stval);
			return kvm_riscv_vcpu_hmode_trap(vcpu, &access_trap);
		}
		case EXC_LOAD_GUEST_PAGE_FAULT:
			ret = kvm_riscv_vcpu_mmio_load(vcpu, run,
						      walk.source_gpa, trap->htinst);
			break;
		case EXC_STORE_GUEST_PAGE_FAULT:
			ret = kvm_riscv_vcpu_mmio_store(vcpu, run,
						       walk.source_gpa, trap->htinst);
			break;
		default:
			return kvm_riscv_vcpu_hmode_trap(vcpu, trap);
		}
		if (kvm_riscv_sting_log_enabled(KVM_RISCV_STING_LOG_NESTED)) {
			if (ret < 0)
				kvm_info("STING_NESTED path=mmio failed pc=0x%lx cause=0x%lx nested_gpa=0x%llx source_gpa=0x%llx htinst=0x%lx ret=%d\n",
					 vcpu->arch.guest_context.sepc,
					 trap->scause,
					 (unsigned long long)nested_gpa,
					 (unsigned long long)walk.source_gpa,
					 trap->htinst, ret);
			else
				kvm_info("STING_NESTED path=mmio pc=0x%lx cause=0x%lx nested_gpa=0x%llx source_gpa=0x%llx htinst=0x%lx ret=%d exit_reason=%u\n",
					 vcpu->arch.guest_context.sepc,
					 trap->scause,
					 (unsigned long long)nested_gpa,
					 (unsigned long long)walk.source_gpa,
					 trap->htinst, ret, run->exit_reason);
		}
		return ret;
	}

	ret = kvm_riscv_mmu_map_nested(vcpu, memslot, nested_gpa,
				       walk.source_gpa, hva,
				       trap->scause == EXC_STORE_GUEST_PAGE_FAULT,
				       !walk.writable, walk.executable, &host_map);
	if (ret < 0) {
		if (kvm_riscv_sting_log_enabled(KVM_RISCV_STING_LOG_NESTED))
			kvm_info("STING_NESTED shadow failed pc=0x%lx cause=0x%lx nested_gpa=0x%llx source_gpa=0x%llx hva=0x%lx ret=%d\n",
				 vcpu->arch.guest_context.sepc, trap->scause,
				 (unsigned long long)nested_gpa,
				 (unsigned long long)walk.source_gpa, hva, ret);
		return ret;
	}
	if (kvm_riscv_sting_log_enabled(KVM_RISCV_STING_LOG_NESTED))
		kvm_info("STING_NESTED shadow ok pc=0x%lx cause=0x%lx tval=0x%lx htval=0x%lx nested_gpa=0x%llx source_gpa=0x%llx l1_hgatp=0x%lx slot=%d hva=0x%lx pte=0x%lx level=%u writable=%d executable=%d mmode=%d hmode=%d\n",
			 vcpu->arch.guest_context.sepc, trap->scause,
			 trap->stval, trap->htval,
			 (unsigned long long)nested_gpa,
			 (unsigned long long)walk.source_gpa,
			 vcpu->arch.hmode.hgatp, memslot->id, hva,
			 pte_val(host_map.pte), host_map.level,
			 walk.writable, walk.executable,
			 vcpu->arch.mmode.active,
			 kvm_riscv_vcpu_hmode_active(vcpu));
	return 1;
}
