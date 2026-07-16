// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>

#include <asm/csr.h>
#include <asm/kvm_nacl.h>
#include <asm/timex.h>

#define KVM_RISCV_MSTATUS_MPP_SHIFT	11
#define KVM_RISCV_MSTATUS_MPRV		BIT(17)
#define KVM_RISCV_MSTATUS_MPV		BIT(39)
#define KVM_RISCV_CSR_MTINST		0x34a
#define KVM_RISCV_CSR_MTVAL2		0x34b
#define KVM_RISCV_CSR_PMPCFG2		0x3a2
#define KVM_RISCV_CSR_MSTATEEN1		0x30d
#define KVM_RISCV_CSR_MSTATEEN2		0x30e
#define KVM_RISCV_CSR_MSTATEEN3		0x30f
#define KVM_RISCV_CSR_SSTATEEN1		0x10d
#define KVM_RISCV_CSR_SSTATEEN2		0x10e
#define KVM_RISCV_CSR_SSTATEEN3		0x10f
#define KVM_RISCV_MISA_B		BIT('b' - 'a')
#define KVM_RISCV_MISA_G		BIT('g' - 'a')
#define KVM_RISCV_MISA_S		BIT('s' - 'a')
#define KVM_RISCV_MISA_U		BIT('u' - 'a')
#ifdef CONFIG_64BIT
#define KVM_RISCV_MSTATUS_XLEN		(BIT(33) | BIT(35))
#define KVM_RISCV_MISA_MXL		(2UL << 62)
#else
#define KVM_RISCV_MSTATUS_XLEN		0UL
#define KVM_RISCV_MISA_MXL		(1UL << 30)
#endif

#define KVM_RISCV_MIP_S_MASK		(BIT(IRQ_S_SOFT) | \
					 BIT(IRQ_S_TIMER) | BIT(IRQ_S_EXT))
#define KVM_RISCV_MIDELEG_MASK		KVM_RISCV_MIP_S_MASK
#define KVM_RISCV_MEDELEG_MASK		(GENMASK(23, 0) & \
					 ~BIT(9) & ~BIT(11))

static unsigned long mmode_rmw(unsigned long old, unsigned long new_val,
			       unsigned long wr_mask)
{
	return (old & ~wr_mask) | (new_val & wr_mask);
}

static unsigned long mmode_misa(struct kvm_vcpu *vcpu)
{
	const unsigned long *isa = vcpu->arch.isa;
	unsigned long misa = vcpu->arch.isa[0] & GENMASK(25, 0);

	if (riscv_isa_extension_available(isa, ZBA) &&
	    riscv_isa_extension_available(isa, ZBB) &&
	    riscv_isa_extension_available(isa, ZBS))
		misa |= KVM_RISCV_MISA_B;
	if ((misa & (BIT('i' - 'a') | BIT('m' - 'a') |
		     BIT('a' - 'a') | BIT('f' - 'a') |
		     BIT('d' - 'a'))) ==
	    (BIT('i' - 'a') | BIT('m' - 'a') | BIT('a' - 'a') |
	     BIT('f' - 'a') | BIT('d' - 'a')) &&
	    riscv_isa_extension_available(isa, ZICSR) &&
	    riscv_isa_extension_available(isa, ZIFENCEI))
		misa |= KVM_RISCV_MISA_G;

	/* S/U are implicit KVM modes and are not tracked in the ISA bitmap. */
	misa |= KVM_RISCV_MISA_S | KVM_RISCV_MISA_U;
	/* The software M-mode environment does not expose nested H-mode. */
	misa &= ~BIT(RISCV_ISA_EXT_h);
	return misa | KVM_RISCV_MISA_MXL;
}

static unsigned long mmode_supported_envcfg(struct kvm_vcpu *vcpu)
{
	const unsigned long *isa = vcpu->arch.isa;
	unsigned long supported = 0;

	if (riscv_isa_extension_available(isa, SVPBMT))
		supported |= ENVCFG_PBMTE;
	if (riscv_isa_extension_available(isa, SSTC))
		supported |= ENVCFG_STCE;
	if (riscv_isa_extension_available(isa, ZICBOM))
		supported |= ENVCFG_CBIE | ENVCFG_CBCFE;
	if (riscv_isa_extension_available(isa, ZICBOZ))
		supported |= ENVCFG_CBZE;
	if (riscv_isa_extension_available(isa, SVADU) &&
	    !riscv_isa_extension_available(isa, SVADE))
		supported |= ENVCFG_ADUE;

	return supported;
}

static void mmode_sync_delegation(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_config *cfg = &vcpu->arch.cfg;
	struct kvm_vcpu_mmode *m = &vcpu->arch.mmode;
	unsigned long hideleg = 0;

	if (m->active) {
		cfg->hedeleg = 0;
		cfg->hideleg = 0;
	} else {
		cfg->hedeleg = m->medeleg & KVM_RISCV_MEDELEG_MASK;
		/* A VS ecall is an S ecall from the virtual M-mode view. */
		cfg->hedeleg &= ~BIT(EXC_SUPERVISOR_SYSCALL);
		if (m->mideleg & BIT(IRQ_S_SOFT))
			hideleg |= BIT(IRQ_VS_SOFT);
		if (m->mideleg & BIT(IRQ_S_TIMER))
			hideleg |= BIT(IRQ_VS_TIMER);
		if (m->mideleg & BIT(IRQ_S_EXT))
			hideleg |= BIT(IRQ_VS_EXT);
		cfg->hideleg = hideleg;
	}

	ncsr_write(CSR_HEDELEG, cfg->hedeleg);
	ncsr_write(CSR_HIDELEG, cfg->hideleg);
}

static void mmode_sync_counteren(struct kvm_vcpu *vcpu)
{
	vcpu->arch.cfg.hcounteren = vcpu->arch.mmode.active ? 0 :
		(vcpu->arch.mmode.mcounteren & GENMASK(2, 0));
	ncsr_write(CSR_HCOUNTEREN, vcpu->arch.cfg.hcounteren);
}

static void mmode_sync_mprv(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_mmode *m = &vcpu->arch.mmode;

	if (!m->active)
		return;

	/*
	 * Hardware VSATP translates both instruction and data accesses, while
	 * architectural MPRV affects data accesses only.  Keep instruction
	 * fetches Bare and emulate faulting MPRV loads/stores with HLV/HSV.
	 */
	ncsr_write(CSR_VSATP, 0);
}

static void mmode_sync_s_interrupt(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_mmode *m = &vcpu->arch.mmode;
	bool deliver;

	deliver = !m->active && (m->mideleg & BIT(IRQ_S_SOFT)) &&
		  (m->mip & BIT(IRQ_S_SOFT));
	if (deliver)
		kvm_riscv_vcpu_set_interrupt(vcpu, IRQ_VS_SOFT);
	else
		kvm_riscv_vcpu_unset_interrupt(vcpu, IRQ_VS_SOFT);

	deliver = !m->active && (m->mideleg & BIT(IRQ_S_TIMER)) &&
		  (m->mip & BIT(IRQ_S_TIMER));
	if (deliver)
		kvm_riscv_vcpu_set_interrupt(vcpu, IRQ_VS_TIMER);
	else
		kvm_riscv_vcpu_unset_interrupt(vcpu, IRQ_VS_TIMER);

	/* HIDELEG can change before the next KVM_RUN iteration. */
	kvm_riscv_vcpu_flush_interrupts(vcpu);
	ncsr_write(CSR_HVIP, vcpu->arch.guest_csr.hvip);
}

static unsigned long mmode_vs_csr_read(unsigned int csr_num)
{
	switch (csr_num) {
	case CSR_VSSTATUS:
		return ncsr_read(CSR_VSSTATUS);
	case CSR_VSIE:
		return ncsr_read(CSR_VSIE);
	case CSR_VSTVEC:
		return ncsr_read(CSR_VSTVEC);
	case CSR_VSSCRATCH:
		return ncsr_read(CSR_VSSCRATCH);
	case CSR_VSEPC:
		return ncsr_read(CSR_VSEPC);
	case CSR_VSCAUSE:
		return ncsr_read(CSR_VSCAUSE);
	case CSR_VSTVAL:
		return ncsr_read(CSR_VSTVAL);
	case CSR_VSIP:
		return ncsr_read(CSR_VSIP);
	default:
		return 0;
	}
}

static void mmode_vs_csr_write(unsigned int csr_num, unsigned long val)
{
	switch (csr_num) {
	case CSR_VSSTATUS:
		ncsr_write(CSR_VSSTATUS, val);
		break;
	case CSR_VSIE:
		ncsr_write(CSR_VSIE, val);
		break;
	case CSR_VSTVEC:
		ncsr_write(CSR_VSTVEC, val);
		break;
	case CSR_VSSCRATCH:
		ncsr_write(CSR_VSSCRATCH, val);
		break;
	case CSR_VSEPC:
		ncsr_write(CSR_VSEPC, val);
		break;
	case CSR_VSCAUSE:
		ncsr_write(CSR_VSCAUSE, val);
		break;
	case CSR_VSTVAL:
		ncsr_write(CSR_VSTVAL, val);
		break;
	case CSR_VSIP:
		ncsr_write(CSR_VSIP, val & VSIP_VALID_MASK);
		break;
	}
}

void kvm_riscv_vcpu_mmode_set_active(struct kvm_vcpu *vcpu, bool active)
{
	vcpu->arch.mmode.active = active;
	if (active)
		vcpu->arch.guest_context.hstatus |= HSTATUS_VTVM;
	else
		vcpu->arch.guest_context.hstatus &= ~HSTATUS_VTVM;
}

bool kvm_riscv_vcpu_mmode_mprv_active(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_mmode *m = &vcpu->arch.mmode;
	unsigned long mpp;

	if (!vcpu->kvm->arch.m_mode || !m->active ||
	    !(m->mstatus & KVM_RISCV_MSTATUS_MPRV))
		return false;

	mpp = (m->mstatus & SR_MPP) >> KVM_RISCV_MSTATUS_MPP_SHIFT;
	return mpp != KVM_RISCV_MODE_M;
}

void kvm_riscv_vcpu_mmode_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_mmode *m = &vcpu->arch.mmode;

	memset(m, 0, sizeof(*m));
	if (!vcpu->kvm->arch.m_mode)
		return;

	kvm_riscv_vcpu_mmode_set_active(vcpu, true);
	m->mstatus = (KVM_RISCV_MODE_M << KVM_RISCV_MSTATUS_MPP_SHIFT) |
		     KVM_RISCV_MSTATUS_XLEN;
	vcpu->arch.cfg.hcounteren = 0;
	vcpu->arch.cfg.hedeleg = 0;
	vcpu->arch.cfg.hideleg = 0;
}

int kvm_riscv_vcpu_mmode_csr_rmw(struct kvm_vcpu *vcpu,
					 unsigned int csr_num,
					 unsigned long *val,
					 unsigned long new_val,
					 unsigned long wr_mask)
{
	struct kvm_vcpu_config *cfg = &vcpu->arch.cfg;
	struct kvm_vcpu_mmode *m = &vcpu->arch.mmode;
	unsigned long old, supported, *reg = NULL;

	if (!m->active)
		return KVM_INSN_ILLEGAL_TRAP;

	switch (csr_num) {
	case CSR_MSTATUS:
		old = m->mstatus;
		old &= ~(SR_FS | SR_VS);
		old |= ncsr_read(CSR_VSSTATUS) & (SR_FS | SR_VS);
		*val = old;
		m->mstatus = mmode_rmw(old, new_val, wr_mask);
		m->mstatus &= ~KVM_RISCV_MSTATUS_XLEN;
		m->mstatus |= KVM_RISCV_MSTATUS_XLEN;
		if (((old ^ m->mstatus) &
		     (KVM_RISCV_MSTATUS_MPRV | SR_MPP)) &&
		    ((old | m->mstatus) & KVM_RISCV_MSTATUS_MPRV))
			mmode_sync_mprv(vcpu);
		old = ncsr_read(CSR_VSSTATUS) & ~(SR_FS | SR_VS);
		ncsr_write(CSR_VSSTATUS, old | (m->mstatus & (SR_FS | SR_VS)));
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MISA:
		*val = mmode_misa(vcpu);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MVENDORID:
		*val = vcpu->arch.mvendorid;
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MARCHID:
		*val = vcpu->arch.marchid;
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MIMPID:
		*val = vcpu->arch.mimpid;
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MHARTID:
		*val = vcpu->vcpu_id;
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MCONFIGPTR:
	case CSR_MSECCFG:
		*val = 0;
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MENVCFG:
		supported = mmode_supported_envcfg(vcpu);
		*val = m->menvcfg;
		m->menvcfg = mmode_rmw(m->menvcfg, new_val, wr_mask) & supported;
		cfg->henvcfg = m->menvcfg;
		ncsr_write(CSR_HENVCFG, cfg->henvcfg);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MCOUNTEREN:
		*val = m->mcounteren;
		m->mcounteren = mmode_rmw(m->mcounteren, new_val, wr_mask) &
				 GENMASK(2, 0);
		mmode_sync_counteren(vcpu);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MSTATEEN0:
		*val = m->mstateen0;
		m->mstateen0 = mmode_rmw(m->mstateen0, new_val, wr_mask) |
				   cfg->hstateen0;
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case KVM_RISCV_CSR_MSTATEEN1:
		reg = &m->mstateen1;
		break;
	case KVM_RISCV_CSR_MSTATEEN2:
		reg = &m->mstateen2;
		break;
	case KVM_RISCV_CSR_MSTATEEN3:
		reg = &m->mstateen3;
		break;
	case CSR_MCOUNTINHIBIT:
		reg = &m->mcountinhibit;
		break;
	case KVM_RISCV_CSR_MTINST:
		reg = &m->mtinst;
		break;
	case KVM_RISCV_CSR_MTVAL2:
		reg = &m->mtval2;
		break;
	case CSR_HSTATUS:
		reg = &m->hstatus;
		break;
	case CSR_HCOUNTEREN:
		reg = &m->hcounteren;
		break;
	case CSR_HEDELEG:
		reg = &m->hedeleg;
		break;
	case CSR_HIDELEG:
		reg = &m->hideleg;
		break;
	case CSR_HIE:
		reg = &m->hie;
		break;
	case CSR_HGATP:
		reg = &m->hgatp;
		break;
	case CSR_HTVAL:
		reg = &m->htval;
		break;
	case CSR_HTINST:
		reg = &m->htinst;
		break;
	case CSR_HTIMEDELTA:
		reg = &m->htimedelta;
		break;
	case CSR_HVIP:
		reg = &m->hvip;
		break;
	case CSR_STIMECMP:
		reg = &m->stimecmp;
		break;
	case CSR_VSTIMECMP:
		reg = &m->vstimecmp;
		break;
	case CSR_SATP:
		/*
		 * HSTATUS.VTVM traps the virtual M-mode payload's SATP access.
		 * Keep the requested value in the software M-mode context while
		 * hardware VSATP remains Bare for M-mode instruction fetches.  The
		 * shadow is installed only by mret to S/U (or temporarily by MPRV).
		 */
		old = m->vsatp;
		*val = old;
		if (wr_mask) {
			m->vsatp = mmode_rmw(old, new_val, wr_mask);
			m->vsatp_valid = true;
			mmode_sync_mprv(vcpu);
		}
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_SSTATUS:
	case CSR_SIE:
	case CSR_STVEC:
	case CSR_SSCRATCH:
	case CSR_SEPC:
	case CSR_SCAUSE:
	case CSR_STVAL:
	case CSR_SIP:
		csr_num += 0x100;
		old = mmode_vs_csr_read(csr_num);
		*val = old;
		supported = mmode_rmw(old, new_val, wr_mask);
		if (csr_num == CSR_VSEPC)
			supported &= ~1UL;
		if (csr_num == CSR_VSTVEC && (supported & 0x3) > 1)
			supported &= ~0x3UL;
		mmode_vs_csr_write(csr_num, supported);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_SCOUNTEREN:
		reg = &m->scounteren;
		break;
	case CSR_SENVCFG:
		reg = &m->senvcfg;
		break;
	case CSR_SSTATEEN0:
		reg = &m->sstateen0;
		break;
	case KVM_RISCV_CSR_SSTATEEN1:
		reg = &m->sstateen1;
		break;
	case KVM_RISCV_CSR_SSTATEEN2:
		reg = &m->sstateen2;
		break;
	case KVM_RISCV_CSR_SSTATEEN3:
		reg = &m->sstateen3;
		break;
	case CSR_VSATP:
		reg = &m->vsatp;
		m->vsatp_valid = true;
		break;
	case CSR_MCYCLE:
	case CSR_CYCLE:
	case CSR_TIME:
		*val = get_cycles();
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MINSTRET:
	case CSR_INSTRET:
		*val = get_cycles();
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MEPC:
		reg = &m->mepc;
		break;
	case CSR_MTVEC:
		reg = &m->mtvec;
		break;
	case CSR_MSCRATCH:
		reg = &m->mscratch;
		break;
	case CSR_MCAUSE:
		reg = &m->mcause;
		break;
	case CSR_MTVAL:
		reg = &m->mtval;
		break;
	case CSR_MEDELEG:
		*val = m->medeleg;
		m->medeleg = mmode_rmw(m->medeleg, new_val, wr_mask) &
			     KVM_RISCV_MEDELEG_MASK;
		mmode_sync_delegation(vcpu);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MIDELEG:
		*val = m->mideleg;
		m->mideleg = mmode_rmw(m->mideleg, new_val, wr_mask) &
			     KVM_RISCV_MIDELEG_MASK;
		mmode_sync_delegation(vcpu);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_MIE:
		reg = &m->mie;
		break;
	case CSR_MIP:
		old = m->mip;
		*val = old;
		m->mip = mmode_rmw(old, new_val, wr_mask & KVM_RISCV_MIP_S_MASK);
		mmode_sync_s_interrupt(vcpu);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_VSSTATUS:
	case CSR_VSIE:
	case CSR_VSTVEC:
	case CSR_VSSCRATCH:
	case CSR_VSEPC:
	case CSR_VSCAUSE:
	case CSR_VSTVAL:
		old = mmode_vs_csr_read(csr_num);
		*val = old;
		supported = mmode_rmw(old, new_val, wr_mask);
		if (csr_num == CSR_VSEPC)
			supported &= ~1UL;
		if (csr_num == CSR_VSTVEC && (supported & 0x3) > 1)
			supported &= ~0x3UL;
		mmode_vs_csr_write(csr_num, supported);
		return KVM_INSN_CONTINUE_NEXT_SEPC;
	case CSR_PMPCFG0:
		reg = &m->pmpcfg0;
		break;
	case KVM_RISCV_CSR_PMPCFG2:
		reg = &m->pmpcfg2;
		break;
	case CSR_PMPADDR0 ... CSR_PMPADDR0 + 15:
		reg = &m->pmpaddr[csr_num - CSR_PMPADDR0];
		break;
	default:
		return KVM_INSN_ILLEGAL_TRAP;
	}

	*val = *reg;
	*reg = mmode_rmw(*reg, new_val, wr_mask);
	if (csr_num == CSR_MEPC)
		m->mepc &= ~1UL;
	if (csr_num == CSR_MTVEC && (m->mtvec & 0x3) > 1)
		m->mtvec &= ~0x3UL;
	return KVM_INSN_CONTINUE_NEXT_SEPC;
}

int kvm_riscv_vcpu_mmode_mret(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *cntx = &vcpu->arch.guest_context;
	struct kvm_vcpu_mmode *m = &vcpu->arch.mmode;
	unsigned long next_mode;

	if (!vcpu->kvm->arch.m_mode || !m->active)
		return KVM_INSN_ILLEGAL_TRAP;

	next_mode = (m->mstatus & SR_MPP) >> KVM_RISCV_MSTATUS_MPP_SHIFT;
	if (next_mode != KVM_RISCV_MODE_M &&
	    next_mode != KVM_RISCV_MODE_S &&
	    next_mode != KVM_RISCV_MODE_U)
		return KVM_INSN_ILLEGAL_TRAP;

	if (m->mstatus & SR_MPIE)
		m->mstatus |= SR_MIE;
	else
		m->mstatus &= ~SR_MIE;
	m->mstatus |= SR_MPIE;
	m->mstatus &= ~SR_MPP;
	m->mstatus &= ~KVM_RISCV_MSTATUS_MPV;
	if (next_mode != KVM_RISCV_MODE_M)
		m->mstatus &= ~KVM_RISCV_MSTATUS_MPRV;

	kvm_riscv_vcpu_mmode_set_active(vcpu,
					next_mode == KVM_RISCV_MODE_M);
	if (!m->active) {
		ncsr_write(CSR_VSATP, m->vsatp_valid ? m->vsatp : 0);
	} else {
		mmode_sync_mprv(vcpu);
	}
	if (next_mode == KVM_RISCV_MODE_U)
		cntx->sstatus &= ~SR_SPP;
	else
		cntx->sstatus |= SR_SPP;
	cntx->sepc = m->mepc;
	mmode_sync_delegation(vcpu);
	mmode_sync_counteren(vcpu);
	mmode_sync_s_interrupt(vcpu);

	return KVM_INSN_CONTINUE_SAME_SEPC;
}

int kvm_riscv_vcpu_mmode_trap(struct kvm_vcpu *vcpu,
				      unsigned long cause,
				      unsigned long tval)
{
	struct kvm_vcpu_mmode *m = &vcpu->arch.mmode;
	unsigned long previous_mode, vector = 0;

	if (!vcpu->kvm->arch.m_mode)
		return -EOPNOTSUPP;

	previous_mode = m->active ? KVM_RISCV_MODE_M :
		((vcpu->arch.guest_context.sstatus & SR_SPP) ?
		 KVM_RISCV_MODE_S : KVM_RISCV_MODE_U);
	if (!m->active) {
		m->vsatp = ncsr_read(CSR_VSATP);
		m->vsatp_valid = true;
		ncsr_write(CSR_VSATP, 0);
	}
	m->mepc = vcpu->arch.guest_context.sepc;
	m->mcause = cause;
	m->mtval = tval;
	if (m->mstatus & SR_MIE)
		m->mstatus |= SR_MPIE;
	else
		m->mstatus &= ~SR_MPIE;
	m->mstatus &= ~(SR_MPP | SR_MIE);
	m->mstatus |= previous_mode << KVM_RISCV_MSTATUS_MPP_SHIFT;
	kvm_riscv_vcpu_mmode_set_active(vcpu, true);
	vcpu->arch.guest_context.sstatus |= SR_SPP;
	if ((cause & CAUSE_IRQ_FLAG) && (m->mtvec & 0x3) == 1)
		vector = 4 * (cause & ~CAUSE_IRQ_FLAG);
	vcpu->arch.guest_context.sepc = (m->mtvec & ~0x3UL) + vector;
	mmode_sync_s_interrupt(vcpu);
	mmode_sync_delegation(vcpu);
	mmode_sync_counteren(vcpu);
	return 1;
}

int kvm_riscv_vcpu_mmode_check_interrupt(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_mmode *m = &vcpu->arch.mmode;
	unsigned long pending;
	unsigned int irq;

	if (!vcpu->kvm->arch.m_mode)
		return 0;

	pending = m->mip & m->mie & KVM_RISCV_MMODE_IRQ_MASK;
	if (!pending || (m->active && !(m->mstatus & SR_MIE)))
		return 0;

	if (pending & BIT(IRQ_M_EXT))
		irq = IRQ_M_EXT;
	else if (pending & BIT(IRQ_M_SOFT))
		irq = IRQ_M_SOFT;
	else
		irq = IRQ_M_TIMER;
	return kvm_riscv_vcpu_mmode_trap(vcpu, CAUSE_IRQ_FLAG | irq, 0);
}
