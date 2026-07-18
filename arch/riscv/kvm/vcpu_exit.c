// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *     Anup Patel <anup.patel@wdc.com>
 */

#include <linux/kvm_host.h>
#include <asm/csr.h>
#include <asm/insn-def.h>
#include <asm/insn.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_nacl.h>
#include <asm/kvm_tlb.h>

#define KVM_RISCV_MSTATUS_MXR	BIT(19)

static int gstage_page_fault(struct kvm_vcpu *vcpu, struct kvm_run *run,
			     struct kvm_cpu_trap *trap)
{
	struct kvm_gstage_mapping host_map;
	struct kvm_memory_slot *memslot;
	unsigned long hva, fault_addr;
	bool writable;
	gfn_t gfn;
	int ret;

	fault_addr = (trap->htval << 2) | (trap->stval & 0x3);
	gfn = fault_addr >> PAGE_SHIFT;
	memslot = gfn_to_memslot(vcpu->kvm, gfn);
	hva = gfn_to_hva_memslot_prot(memslot, gfn, &writable);

	if (kvm_is_error_hva(hva) ||
	    (trap->scause == EXC_STORE_GUEST_PAGE_FAULT && !writable)) {
		switch (trap->scause) {
		case EXC_LOAD_GUEST_PAGE_FAULT:
			ret = kvm_riscv_vcpu_mmio_load(vcpu, run, fault_addr,
						       trap->htinst);
			break;
		case EXC_STORE_GUEST_PAGE_FAULT:
			ret = kvm_riscv_vcpu_mmio_store(vcpu, run, fault_addr,
							trap->htinst);
			break;
		default:
			return -EOPNOTSUPP;
		};
		return ret;
	}

	ret = kvm_riscv_mmu_map(vcpu, memslot, fault_addr, hva,
				(trap->scause == EXC_STORE_GUEST_PAGE_FAULT) ? true : false,
				&host_map);
	if (ret < 0)
		return ret;

	return 1;
}

/**
 * kvm_riscv_vcpu_unpriv_read -- Read machine word from Guest memory
 *
 * @vcpu: The VCPU pointer
 * @read_insn: Flag representing whether we are reading instruction
 * @guest_addr: Guest address to read
 * @trap: Output pointer to trap details
 */
unsigned long kvm_riscv_vcpu_unpriv_read(struct kvm_vcpu *vcpu,
					 bool read_insn,
					 unsigned long guest_addr,
					 struct kvm_cpu_trap *trap)
{
	register unsigned long taddr asm("a0");
	register unsigned long ttmp asm("a1");
	unsigned long flags, val, tmp, old_stvec, old_hstatus;

	local_irq_save(flags);

	old_hstatus = csr_swap(CSR_HSTATUS, vcpu->arch.guest_context.hstatus);
	old_stvec = csr_swap(CSR_STVEC, (ulong)&__kvm_riscv_unpriv_trap);

	if (read_insn) {
		/*
		 * HLVX.HU instruction
		 * 0110010 00011 rs1 100 rd 1110011
		 */
		asm volatile ("\n"
			".option push\n"
			".option norvc\n"
			"add %[taddr], %[trap], 0\n"
			"add %[ttmp], %[taddr], 0\n"
			HLVX_HU(%[val], %[addr])
			"andi %[tmp], %[val], 3\n"
			"addi %[tmp], %[tmp], -3\n"
			"bne %[tmp], zero, 2f\n"
			"addi %[addr], %[addr], 2\n"
			HLVX_HU(%[tmp], %[addr])
			"sll %[tmp], %[tmp], 16\n"
			"add %[val], %[val], %[tmp]\n"
			"2:\n"
			".option pop"
		: [val] "=&r" (val), [tmp] "=&r" (tmp),
		  [taddr] "=&r" (taddr), [ttmp] "=&r" (ttmp),
		  [addr] "+&r" (guest_addr)
		: [trap] "r" (trap) : "memory");

		if (trap->scause == EXC_LOAD_PAGE_FAULT)
			trap->scause = EXC_INST_PAGE_FAULT;
	} else {
		/*
		 * HLV.D instruction
		 * 0110110 00000 rs1 100 rd 1110011
		 *
		 * HLV.W instruction
		 * 0110100 00000 rs1 100 rd 1110011
		 */
		asm volatile ("\n"
			".option push\n"
			".option norvc\n"
			"add %[taddr], %[trap], 0\n"
			"add %[ttmp], %[taddr], 0\n"
#ifdef CONFIG_64BIT
			HLV_D(%[val], %[addr])
#else
			HLV_W(%[val], %[addr])
#endif
			".option pop"
		: [val] "=&r" (val),
		  [taddr] "=&r" (taddr), [ttmp] "=&r" (ttmp)
		: [trap] "r" (trap), [addr] "r" (guest_addr)
		: "memory");
	}

	csr_write(CSR_STVEC, old_stvec);
	csr_write(CSR_HSTATUS, old_hstatus);

	local_irq_restore(flags);

	return val;
}

static unsigned long mmode_mprv_hstatus(struct kvm_vcpu *vcpu)
{
	unsigned long hstatus = vcpu->arch.guest_context.hstatus;
	unsigned long mpp = (vcpu->arch.mmode.mstatus & SR_MPP) >> 11;

	if (mpp == KVM_RISCV_MODE_U)
		hstatus &= ~HSTATUS_SPVP;
	else
		hstatus |= HSTATUS_SPVP;
	return hstatus;
}

static unsigned long mmode_mprv_vsatp(struct kvm_vcpu *vcpu)
{
	if (kvm_riscv_vcpu_mmode_mprv_virtual(vcpu))
		return vcpu->arch.hmode.vs.vsatp;
	return vcpu->arch.mmode.vsatp;
}

static unsigned long mmode_mprv_hgatp_swap(struct kvm_vcpu *vcpu)
{
	unsigned long hgatp;

	if (!kvm_riscv_vcpu_mmode_mprv_virtual(vcpu))
		return 0;
	hgatp = csr_swap(CSR_HGATP,
		kvm_riscv_mmu_hgatp_value(vcpu, true));
	kvm_riscv_local_hfence_gvma_all();
	return hgatp;
}

static void mmode_mprv_hgatp_restore(struct kvm_vcpu *vcpu,
					     unsigned long hgatp)
{
	if (!kvm_riscv_vcpu_mmode_mprv_virtual(vcpu))
		return;
	csr_write(CSR_HGATP, hgatp);
	kvm_riscv_local_hfence_gvma_all();
}

static unsigned long mmode_mprv_read(struct kvm_vcpu *vcpu,
				     unsigned long guest_addr, int len,
				     bool sign_extend,
				     struct kvm_cpu_trap *trap)
{
	register unsigned long taddr asm("a0");
	register unsigned long ttmp asm("a1");
	unsigned long flags, val = 0, vsstatus;
	unsigned long old_stvec, old_hstatus, old_vsatp, old_vsstatus, old_hgatp;

	local_irq_save(flags);
	memset(trap, 0, sizeof(*trap));
	old_hgatp = mmode_mprv_hgatp_swap(vcpu);
	old_hstatus = csr_swap(CSR_HSTATUS, mmode_mprv_hstatus(vcpu));
	old_vsatp = csr_swap(CSR_VSATP, mmode_mprv_vsatp(vcpu));
	vsstatus = csr_read(CSR_VSSTATUS) &
		   ~(SR_SUM | KVM_RISCV_MSTATUS_MXR);
	vsstatus |= vcpu->arch.mmode.mstatus &
		    (SR_SUM | KVM_RISCV_MSTATUS_MXR);
	old_vsstatus = csr_swap(CSR_VSSTATUS, vsstatus);
	old_stvec = csr_swap(CSR_STVEC, (ulong)&__kvm_riscv_unpriv_trap);

#define MMODE_MPRV_HLV(_insn) \
	asm volatile ("add %[taddr], %[trap], 0\n" \
		      "add %[ttmp], %[taddr], 0\n" \
		      _insn(%[val], %[addr]) \
		      : [val] "=&r" (val), [taddr] "=&r" (taddr), \
			[ttmp] "=&r" (ttmp) \
		      : [trap] "r" (trap), [addr] "r" (guest_addr) \
		      : "memory")

	switch (len) {
	case 1:
		if (sign_extend)
			MMODE_MPRV_HLV(HLV_B);
		else
			MMODE_MPRV_HLV(HLV_BU);
		break;
	case 2:
		if (sign_extend)
			MMODE_MPRV_HLV(HLV_H);
		else
			MMODE_MPRV_HLV(HLV_HU);
		break;
	case 4:
		if (sign_extend)
			MMODE_MPRV_HLV(HLV_W);
		else
			MMODE_MPRV_HLV(HLV_WU);
		break;
#ifdef CONFIG_64BIT
	case 8:
		MMODE_MPRV_HLV(HLV_D);
		break;
#endif
	}

#undef MMODE_MPRV_HLV

	csr_write(CSR_STVEC, old_stvec);
	csr_write(CSR_VSSTATUS, old_vsstatus);
	csr_write(CSR_VSATP, old_vsatp);
	csr_write(CSR_HSTATUS, old_hstatus);
	mmode_mprv_hgatp_restore(vcpu, old_hgatp);
	local_irq_restore(flags);
	return val;
}

static void mmode_mprv_write(struct kvm_vcpu *vcpu,
			     unsigned long guest_addr, int len,
			     unsigned long val, struct kvm_cpu_trap *trap)
{
	register unsigned long taddr asm("a0");
	register unsigned long ttmp asm("a1");
	unsigned long flags, vsstatus;
	unsigned long old_stvec, old_hstatus, old_vsatp, old_vsstatus, old_hgatp;

	local_irq_save(flags);
	memset(trap, 0, sizeof(*trap));
	old_hgatp = mmode_mprv_hgatp_swap(vcpu);
	old_hstatus = csr_swap(CSR_HSTATUS, mmode_mprv_hstatus(vcpu));
	old_vsatp = csr_swap(CSR_VSATP, mmode_mprv_vsatp(vcpu));
	vsstatus = csr_read(CSR_VSSTATUS) &
		   ~(SR_SUM | KVM_RISCV_MSTATUS_MXR);
	vsstatus |= vcpu->arch.mmode.mstatus &
		    (SR_SUM | KVM_RISCV_MSTATUS_MXR);
	old_vsstatus = csr_swap(CSR_VSSTATUS, vsstatus);
	old_stvec = csr_swap(CSR_STVEC, (ulong)&__kvm_riscv_unpriv_trap);

#define MMODE_MPRV_HSV(_insn) \
	asm volatile ("add %[taddr], %[trap], 0\n" \
		      "add %[ttmp], %[taddr], 0\n" \
		      _insn(%[val], %[addr]) \
		      : [taddr] "=&r" (taddr), [ttmp] "=&r" (ttmp) \
		      : [trap] "r" (trap), [val] "r" (val), \
			[addr] "r" (guest_addr) \
		      : "memory")

	switch (len) {
	case 1:
		MMODE_MPRV_HSV(HSV_B);
		break;
	case 2:
		MMODE_MPRV_HSV(HSV_H);
		break;
	case 4:
		MMODE_MPRV_HSV(HSV_W);
		break;
#ifdef CONFIG_64BIT
	case 8:
		MMODE_MPRV_HSV(HSV_D);
		break;
#endif
	}

#undef MMODE_MPRV_HSV

	csr_write(CSR_STVEC, old_stvec);
	csr_write(CSR_VSSTATUS, old_vsstatus);
	csr_write(CSR_VSATP, old_vsatp);
	csr_write(CSR_HSTATUS, old_hstatus);
	mmode_mprv_hgatp_restore(vcpu, old_hgatp);
	local_irq_restore(flags);
}

/* PMP applies after all effective MPRV address-translation stages. */
static int mmode_mprv_translate(struct kvm_vcpu *vcpu,
				unsigned long gva, u8 access,
				unsigned long *gpa)
{
	unsigned long satp = mmode_mprv_vsatp(vcpu), mode, table, pte, ppn;
	unsigned long page_mask;
	gpa_t source_gpa;
	unsigned int levels, level;
	int ret;

	if (kvm_riscv_vcpu_mmode_mprv_virtual(vcpu)) {
		ret = kvm_riscv_vcpu_hmode_translate(vcpu, gva,
						      access == PMP_W, false,
						      &source_gpa);
		if (!ret)
			*gpa = source_gpa;
		return ret;
	}

	mode = satp >> SATP_MODE_SHIFT;
	if (!mode) {
		*gpa = gva;
		return 0;
	}

	switch (mode) {
	case 8: /* Sv39 */
		levels = 3;
		break;
	case 9: /* Sv48 */
		levels = 4;
		break;
	case 10: /* Sv57 */
		levels = 5;
		break;
	default:
		return -EINVAL;
	}

	table = (satp & SATP_PPN) << PAGE_SHIFT;
	for (level = levels; level-- > 0;) {
		unsigned long shift = PAGE_SHIFT + level * 9;
		unsigned long index = (gva >> shift) & 0x1ff;

		if (kvm_read_guest(vcpu->kvm, table + index * sizeof(pte),
				   &pte, sizeof(pte)))
			return -EFAULT;
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
		page_mask = BIT_ULL(shift) - 1;
		if ((ppn << PAGE_SHIFT) & page_mask)
			return -EFAULT;
		*gpa = (ppn << PAGE_SHIFT) | (gva & page_mask);
		return 0;
	}

	return -EFAULT;
}

static bool mmode_mprv_pmp_check(struct kvm_vcpu *vcpu,
					 unsigned long addr, unsigned long size,
					 u8 access)
{
	unsigned long last, first_gpa, last_gpa;

	if (!size || addr + size - 1 < addr)
		return false;
	last = addr + size - 1;
	/* Let HLV/HSV report an architectural translation or access fault. */
	if (mmode_mprv_translate(vcpu, addr, access, &first_gpa) ||
	    mmode_mprv_translate(vcpu, last, access, &last_gpa))
		return true;
	if (last_gpa < first_gpa || last_gpa - first_gpa != last - addr)
		return false;
	return kvm_riscv_vcpu_mmode_pmp_check(vcpu, first_gpa, size, access);
}

static int mmode_mprv_fault(struct kvm_vcpu *vcpu, struct kvm_run *run,
			    struct kvm_cpu_trap *trap)
{
	struct kvm_cpu_context *ct = &vcpu->arch.guest_context;
	struct kvm_cpu_trap utrap = { 0 }, access_trap = { 0 };
	unsigned long fault_addr, insn, val = 0;
	bool load = false, sign_extend = false, emulate;
	int len = 0, insn_len;

	emulate = kvm_riscv_vcpu_mmode_mprv_active(vcpu);

	fault_addr = (trap->htval << 2) | (trap->stval & 0x3);
	if (trap->htinst & INSN_16BIT_MASK) {
		/* Use the transformed faulting instruction when hardware supplied it. */
		insn = trap->htinst | INSN_16BIT_MASK;
	} else {
		insn = kvm_riscv_vcpu_unpriv_read(vcpu, true, ct->sepc, &utrap);
		if (utrap.scause) {
			if (utrap.scause == EXC_INST_GUEST_PAGE_FAULT)
				return gstage_page_fault(vcpu, run, &utrap);
			return kvm_riscv_vcpu_mmode_trap(vcpu, utrap.scause,
							   utrap.stval);
		}
	}
	insn_len = INSN_LEN(insn);

	if ((insn & INSN_MASK_LB) == INSN_MATCH_LB) {
		load = sign_extend = true;
		len = 1;
	} else if ((insn & INSN_MASK_LBU) == INSN_MATCH_LBU) {
		load = true;
		len = 1;
	} else if ((insn & INSN_MASK_LH) == INSN_MATCH_LH) {
		load = sign_extend = true;
		len = 2;
	} else if ((insn & INSN_MASK_LHU) == INSN_MATCH_LHU) {
		load = true;
		len = 2;
	} else if ((insn & INSN_MASK_LW) == INSN_MATCH_LW) {
		load = sign_extend = true;
		len = 4;
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_LWU) == INSN_MATCH_LWU) {
		load = true;
		len = 4;
	} else if ((insn & INSN_MASK_LD) == INSN_MATCH_LD) {
		load = sign_extend = true;
		len = 8;
#endif
	} else if ((insn & INSN_MASK_SB) == INSN_MATCH_SB) {
		len = 1;
	} else if ((insn & INSN_MASK_SH) == INSN_MATCH_SH) {
		len = 2;
	} else if ((insn & INSN_MASK_SW) == INSN_MATCH_SW) {
		len = 4;
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_SD) == INSN_MATCH_SD) {
		len = 8;
	} else if ((insn & INSN_MASK_C_LD) == INSN_MATCH_C_LD) {
		load = sign_extend = true;
		len = 8;
		insn = RVC_RS2S(insn) << SH_RD;
	} else if ((insn & INSN_MASK_C_LDSP) == INSN_MATCH_C_LDSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		load = sign_extend = true;
		len = 8;
#endif
	} else if ((insn & INSN_MASK_C_LW) == INSN_MATCH_C_LW) {
		load = sign_extend = true;
		len = 4;
		insn = RVC_RS2S(insn) << SH_RD;
	} else if ((insn & INSN_MASK_C_LWSP) == INSN_MATCH_C_LWSP &&
		   ((insn >> SH_RD) & 0x1f)) {
		load = sign_extend = true;
		len = 4;
#ifdef CONFIG_64BIT
	} else if ((insn & INSN_MASK_C_SD) == INSN_MATCH_C_SD) {
		len = 8;
		val = GET_RS2S(insn, ct);
	} else if ((insn & INSN_MASK_C_SDSP) == INSN_MATCH_C_SDSP) {
		len = 8;
		val = GET_RS2C(insn, ct);
#endif
	} else if ((insn & INSN_MASK_C_SW) == INSN_MATCH_C_SW) {
		len = 4;
		val = GET_RS2S(insn, ct);
	} else if ((insn & INSN_MASK_C_SWSP) == INSN_MATCH_C_SWSP) {
		len = 4;
		val = GET_RS2C(insn, ct);
	}
	if (!len) {
		load = trap->scause == EXC_LOAD_GUEST_PAGE_FAULT;
		if (!(emulate ? mmode_mprv_pmp_check(vcpu, fault_addr, 1,
						     load ? PMP_R : PMP_W) :
			      kvm_riscv_vcpu_mmode_pmp_check(vcpu, fault_addr, 1,
							 load ? PMP_R : PMP_W)))
			return kvm_riscv_vcpu_mmode_trap(vcpu,
				load ? EXC_LOAD_ACCESS : EXC_STORE_ACCESS,
				fault_addr);
		return gstage_page_fault(vcpu, run, trap);
	}
	if (!(emulate ? mmode_mprv_pmp_check(vcpu, fault_addr, len,
						    load ? PMP_R : PMP_W) :
		      kvm_riscv_vcpu_mmode_pmp_check(vcpu, fault_addr, len,
						       load ? PMP_R : PMP_W)))
		return kvm_riscv_vcpu_mmode_trap(vcpu,
			load ? EXC_LOAD_ACCESS : EXC_STORE_ACCESS, fault_addr);
	if (!emulate)
		return gstage_page_fault(vcpu, run, trap);
	if (load) {
		val = mmode_mprv_read(vcpu, fault_addr, len, sign_extend,
				      &access_trap);
	} else {
		if (insn_len == 4)
			val = GET_RS2(insn, ct);
		mmode_mprv_write(vcpu, fault_addr, len, val, &access_trap);
	}

	if (access_trap.scause) {
		if (access_trap.scause == EXC_LOAD_GUEST_PAGE_FAULT ||
		    access_trap.scause == EXC_STORE_GUEST_PAGE_FAULT) {
			if (kvm_riscv_vcpu_mmode_mprv_virtual(vcpu))
				return kvm_riscv_vcpu_hmode_page_fault(vcpu, run,
								 &access_trap);
			/* HLV/HSV may fault while walking the guest page table. */
			access_trap.htinst = insn;
			return gstage_page_fault(vcpu, run, &access_trap);
		}
		return kvm_riscv_vcpu_mmode_trap(vcpu, access_trap.scause,
						   access_trap.stval);
	}
	if (load)
		SET_RD(insn, ct, val);
	ct->sepc += insn_len;
	return 1;
}

/**
 * kvm_riscv_vcpu_trap_redirect -- Redirect trap to Guest
 *
 * @vcpu: The VCPU pointer
 * @trap: Trap details
 */
void kvm_riscv_vcpu_trap_redirect(struct kvm_vcpu *vcpu,
				  struct kvm_cpu_trap *trap)
{
	unsigned long vsstatus = ncsr_read(CSR_VSSTATUS);

	/* Change Guest SSTATUS.SPP bit */
	vsstatus &= ~SR_SPP;
	if (vcpu->arch.guest_context.sstatus & SR_SPP)
		vsstatus |= SR_SPP;

	/* Change Guest SSTATUS.SPIE bit */
	vsstatus &= ~SR_SPIE;
	if (vsstatus & SR_SIE)
		vsstatus |= SR_SPIE;

	/* Clear Guest SSTATUS.SIE bit */
	vsstatus &= ~SR_SIE;

	/* Update Guest SSTATUS */
	ncsr_write(CSR_VSSTATUS, vsstatus);

	/* Update Guest SCAUSE, STVAL, and SEPC */
	ncsr_write(CSR_VSCAUSE, trap->scause);
	ncsr_write(CSR_VSTVAL, trap->stval);
	ncsr_write(CSR_VSEPC, trap->sepc);

	/* Set Guest PC to Guest exception vector */
	vcpu->arch.guest_context.sepc = ncsr_read(CSR_VSTVEC) & ~3UL;

	/* Set Guest privilege mode to supervisor */
	vcpu->arch.guest_context.sstatus |= SR_SPP;
}

static inline int vcpu_redirect(struct kvm_vcpu *vcpu, struct kvm_cpu_trap *trap)
{
	int ret = -EFAULT;

	if (vcpu->kvm->arch.m_mode &&
	    !kvm_riscv_vcpu_mmode_exception_delegated(vcpu, trap->scause))
		return kvm_riscv_vcpu_mmode_trap(vcpu, trap->scause,
						  trap->stval);

	if (kvm_riscv_vcpu_hmode_active(vcpu))
		return kvm_riscv_vcpu_hmode_trap(vcpu, trap);

	if (vcpu->arch.guest_context.hstatus & HSTATUS_SPV) {
		kvm_riscv_vcpu_trap_redirect(vcpu, trap);
		ret = 1;
	}
	return ret;
}

/*
 * Return > 0 to return to guest, < 0 on error, 0 (and set exit_reason) on
 * proper exit to userspace.
 */
int kvm_riscv_vcpu_exit(struct kvm_vcpu *vcpu, struct kvm_run *run,
			struct kvm_cpu_trap *trap)
{
	unsigned int irq;
	int ret;

	/* If we got host interrupt then do nothing. */
	if (trap->scause & CAUSE_IRQ_FLAG) {
		irq = trap->scause & ~CAUSE_IRQ_FLAG;
		if (vcpu->kvm->arch.m_mode && vcpu->arch.mmode.active &&
		    (irq == IRQ_VS_SOFT || irq == IRQ_VS_TIMER)) {
			kvm_riscv_vcpu_unset_interrupt(vcpu, irq);
			vcpu->arch.guest_csr.hvip &= ~BIT(irq);
			ncsr_write(CSR_HVIP, vcpu->arch.guest_csr.hvip);
		}
		return 1;
	}

	/* Handle guest traps */
	ret = -EFAULT;
	run->exit_reason = KVM_EXIT_UNKNOWN;
	switch (trap->scause) {
	case EXC_INST_ILLEGAL:
		kvm_riscv_vcpu_pmu_incr_fw(vcpu, SBI_PMU_FW_ILLEGAL_INSN);
		vcpu->stat.instr_illegal_exits++;
		if (vcpu->kvm->arch.m_mode)
			ret = kvm_riscv_vcpu_illegal_insn(vcpu, run, trap);
		else
			ret = vcpu_redirect(vcpu, trap);
		break;
	case EXC_LOAD_MISALIGNED:
		kvm_riscv_vcpu_pmu_incr_fw(vcpu, SBI_PMU_FW_MISALIGNED_LOAD);
		vcpu->stat.load_misaligned_exits++;
		ret = vcpu_redirect(vcpu, trap);
		break;
	case EXC_STORE_MISALIGNED:
		kvm_riscv_vcpu_pmu_incr_fw(vcpu, SBI_PMU_FW_MISALIGNED_STORE);
		vcpu->stat.store_misaligned_exits++;
		ret = vcpu_redirect(vcpu, trap);
		break;
	case EXC_LOAD_ACCESS:
		kvm_riscv_vcpu_pmu_incr_fw(vcpu, SBI_PMU_FW_ACCESS_LOAD);
		vcpu->stat.load_access_exits++;
		ret = vcpu_redirect(vcpu, trap);
		break;
	case EXC_STORE_ACCESS:
		kvm_riscv_vcpu_pmu_incr_fw(vcpu, SBI_PMU_FW_ACCESS_STORE);
		vcpu->stat.store_access_exits++;
		ret = vcpu_redirect(vcpu, trap);
		break;
	case EXC_INST_ACCESS:
		ret = vcpu_redirect(vcpu, trap);
		break;
	case EXC_INST_PAGE_FAULT:
	case EXC_LOAD_PAGE_FAULT:
	case EXC_STORE_PAGE_FAULT:
		ret = vcpu_redirect(vcpu, trap);
		break;
	case EXC_VIRTUAL_INST_FAULT:
		if (kvm_riscv_vcpu_hmode_active(vcpu))
			ret = kvm_riscv_vcpu_hmode_trap(vcpu, trap);
		else if (vcpu->arch.guest_context.hstatus & HSTATUS_SPV)
			ret = kvm_riscv_vcpu_virtual_insn(vcpu, run, trap);
		break;
	case EXC_INST_GUEST_PAGE_FAULT:
	case EXC_LOAD_GUEST_PAGE_FAULT:
	case EXC_STORE_GUEST_PAGE_FAULT:
		if (kvm_riscv_vcpu_hmode_active(vcpu))
			ret = kvm_riscv_vcpu_hmode_page_fault(vcpu, run, trap);
		else if (trap->scause != EXC_INST_GUEST_PAGE_FAULT &&
		    kvm_riscv_vcpu_mmode_mprv_active(vcpu))
			ret = mmode_mprv_fault(vcpu, run, trap);
		else if (vcpu->arch.guest_context.hstatus & HSTATUS_SPV)
			ret = gstage_page_fault(vcpu, run, trap);
		break;
	case EXC_SUPERVISOR_SYSCALL:
		if (vcpu->kvm->arch.m_mode &&
		    !kvm_riscv_vcpu_hmode_active(vcpu))
			ret = kvm_riscv_vcpu_mmode_trap(vcpu,
					vcpu->arch.mmode.active ? 11 : 9, 0);
		else if (vcpu->kvm->arch.m_mode &&
			 !kvm_riscv_vcpu_mmode_exception_delegated(
						vcpu, trap->scause))
			ret = kvm_riscv_vcpu_mmode_trap(vcpu,
						      trap->scause, 0);
		else if (kvm_riscv_vcpu_hmode_active(vcpu))
			ret = kvm_riscv_vcpu_hmode_trap(vcpu, trap);
		else if (vcpu->arch.guest_context.hstatus & HSTATUS_SPV)
			ret = kvm_riscv_vcpu_sbi_ecall(vcpu, run);
		break;
	case EXC_SYSCALL:
		ret = vcpu_redirect(vcpu, trap);
		break;
	case EXC_BREAKPOINT:
		if (kvm_riscv_vcpu_hmode_active(vcpu))
			ret = kvm_riscv_vcpu_hmode_trap(vcpu, trap);
		else if (vcpu->kvm->arch.m_mode && !vcpu->guest_debug)
			ret = kvm_riscv_vcpu_mmode_trap(vcpu,
							  EXC_BREAKPOINT, trap->stval);
		else {
			run->exit_reason = KVM_EXIT_DEBUG;
			ret = 0;
		}
		break;
	default:
		break;
	}

	/* Print details in-case of error */
	if (ret < 0) {
		kvm_err("VCPU exit error %d\n", ret);
		kvm_err("SEPC=0x%lx SSTATUS=0x%lx HSTATUS=0x%lx\n",
			vcpu->arch.guest_context.sepc,
			vcpu->arch.guest_context.sstatus,
			vcpu->arch.guest_context.hstatus);
		kvm_err("SCAUSE=0x%lx STVAL=0x%lx HTVAL=0x%lx HTINST=0x%lx\n",
			trap->scause, trap->stval, trap->htval, trap->htinst);
	}

	return ret;
}
