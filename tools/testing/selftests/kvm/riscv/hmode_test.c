// SPDX-License-Identifier: GPL-2.0-only
/* Test the software-emulated RISC-V H extension with an HS-to-VS sret. */
#include <errno.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include "ucall_common.h"

#define CSR_VSSTATUS	0x200
#define CSR_HSTATUS	0x600
#define CSR_HEDELEG	0x602
#define CSR_HGATP	0x680
#define CSR_VSATP	0x280
static unsigned long l2_marker;
static unsigned long hs_scause;
static unsigned long hs_htval;
static char guest_stack[4 * 4096] __aligned(4096);

extern void hs_trap_vector(void);
extern void l2_entry(void);

static void __attribute__((used, __noinline__)) hs_trap_done(void)
{
	GUEST_DONE();
}

asm(
".pushsection .text\n"
".balign 4\n"
".global hs_trap_vector\n"
"hs_trap_vector:\n"
"  csrr t0, scause\n"
"  la t1, hs_scause\n"
"  sd t0, 0(t1)\n"
"  csrr t0, 0x643\n"
"  la t1, hs_htval\n"
"  sd t0, 0(t1)\n"
"  call hs_trap_done\n"
"1: wfi\n"
"  j 1b\n"
"\n"
".balign 4\n"
".global l2_entry\n"
"l2_entry:\n"
"  li t0, 0x4e535456\n"
"  la t1, l2_marker\n"
"  sd t0, 0(t1)\n"
"  ebreak\n"
"2: wfi\n"
"  j 2b\n"
".popsection\n"
);

static void guest_code(void)
{
	unsigned long hstatus;

	csr_write(CSR_STVEC, (unsigned long)hs_trap_vector);
	csr_write(CSR_HEDELEG, 0);
	csr_write(CSR_HGATP, 0);
	csr_write(CSR_VSSTATUS, SR_SPP | SR_SPIE);
	csr_write(CSR_VSATP, csr_read(CSR_SATP));
	csr_write(CSR_SEPC, (unsigned long)l2_entry);
	csr_set(CSR_SSTATUS, SR_SPP);
	hstatus = csr_read(CSR_HSTATUS);
	hstatus |= HSTATUS_SPV | HSTATUS_SPVP;
	csr_write(CSR_HSTATUS, hstatus);
	asm volatile("sret" ::: "memory");
	__builtin_unreachable();
}

int main(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int ret;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_RISCV_NESTED));
	vm = vm_create(1);
	ret = __vm_enable_cap(vm, KVM_CAP_RISCV_NESTED, 1);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "nonzero nested capability argument was not rejected");
	vm_enable_cap(vm, KVM_CAP_RISCV_NESTED, 0);
	vcpu = vm_vcpu_add(vm, 0, guest_code);
	vcpu_set_reg(vcpu, RISCV_CORE_REG(regs.sp),
			     (unsigned long)guest_stack + sizeof(guest_stack));
	ret = __vm_enable_cap(vm, KVM_CAP_RISCV_NESTED, 0);
	TEST_ASSERT(ret == -1 && errno == EBUSY,
		    "nested capability enable after vCPU creation was not rejected");

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, UCALL_EXIT_REASON);
	TEST_ASSERT_EQ(get_ucall(vcpu, NULL), UCALL_DONE);
	sync_global_from_guest(vm, l2_marker);
	sync_global_from_guest(vm, hs_scause);
	sync_global_from_guest(vm, hs_htval);
	TEST_ASSERT_EQ(l2_marker, 0x4e535456);
	TEST_ASSERT_EQ(hs_scause, EXC_BREAKPOINT);
	TEST_ASSERT_EQ(hs_htval, 0);

	kvm_vm_free(vm);
	return 0;
}
