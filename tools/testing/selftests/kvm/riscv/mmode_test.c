// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test KVM RISC-V software-emulated M-mode.
 */
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

#define MCAUSE_S_ECALL	9
#define GUEST_STACK_SIZE	(4 * 4096)
#define GUEST_PAGE_SHIFT	12

enum test_stage {
	STAGE_CSR = 1,
	STAGE_S_TRAPS,
	STAGE_M_SOFT_READY,
	STAGE_M_SOFT_DONE,
	STAGE_M_TIMER_READY,
	STAGE_M_TIMER_DONE,
	STAGE_M_EXT_READY,
	STAGE_M_EXT_DONE,
	STAGE_COMPLETE,
};

unsigned long guest_stage;
unsigned long guest_failure;
unsigned long guest_last_cause;
unsigned long guest_last_tval;
unsigned long guest_last_mstatus;
unsigned long guest_exception_count;
unsigned long guest_interrupt_count;
unsigned long guest_illegal_cause;
unsigned long guest_ecall_cause;
unsigned long guest_csr_old;
unsigned long guest_csr_new;
unsigned long guest_misa;
unsigned long guest_menvcfg;
static char guest_stack[GUEST_STACK_SIZE] __aligned(4096);
static char guest_empty_root[4096] __aligned(4096);

extern char __executable_start;
extern char _end;

extern void guest_m_trap_vector(void);
extern void guest_s_mode(void);

asm(
".pushsection .text\n"
".balign 4\n"
".global guest_m_trap_vector\n"
"guest_m_trap_vector:\n"
"  addi sp, sp, -48\n"
"  sd t0, 0(sp)\n"
"  sd t1, 8(sp)\n"
"  sd t2, 16(sp)\n"
"  sd t3, 24(sp)\n"
"  csrr t0, mcause\n"
"  la t1, guest_last_cause\n"
"  sd t0, 0(t1)\n"
"  csrr t2, mtval\n"
"  la t1, guest_last_tval\n"
"  sd t2, 0(t1)\n"
"  csrr t2, mstatus\n"
"  la t1, guest_last_mstatus\n"
"  sd t2, 0(t1)\n"
"  bltz t0, 1f\n"
"  la t1, guest_exception_count\n"
"  ld t2, 0(t1)\n"
"  addi t2, t2, 1\n"
"  sd t2, 0(t1)\n"
"  csrr t2, mepc\n"
"  addi t2, t2, 4\n"
"  csrw mepc, t2\n"
"  li t2, 9\n"
"  bne t0, t2, 2f\n"
"  csrr t2, mstatus\n"
"  li t3, 0x1800\n"
"  or t2, t2, t3\n"
"  csrw mstatus, t2\n"
"  j 2f\n"
"1:\n"
"  andi t2, t0, 0x3f\n"
"  li t3, 1\n"
"  sll t3, t3, t2\n"
"  csrc mie, t3\n"
"  la t1, guest_interrupt_count\n"
"  ld t2, 0(t1)\n"
"  addi t2, t2, 1\n"
"  sd t2, 0(t1)\n"
"2:\n"
"  ld t0, 0(sp)\n"
"  ld t1, 8(sp)\n"
"  ld t2, 16(sp)\n"
"  ld t3, 24(sp)\n"
"  addi sp, sp, 48\n"
"  mret\n"
".popsection\n"
);

static void guest_break(void)
{
	asm volatile(
		".option push\n"
		".option norvc\n"
		"ebreak\n"
		".option pop\n" ::: "memory");
}

static void guest_wait_for_irq(unsigned int irq, enum test_stage ready,
			       enum test_stage done)
{
	csr_write(CSR_MIE, BIT(irq));
	csr_set(CSR_MSTATUS, SR_MIE);
	guest_stage = ready;
	guest_break();

	asm volatile("wfi" ::: "memory");
	guest_failure |= guest_last_cause != (CAUSE_IRQ_FLAG | irq);
	guest_stage = done;
	guest_break();
}

void guest_s_mode(void)
{
	unsigned long ignored;
	unsigned long exceptions;

	if (guest_menvcfg & ENVCFG_STCE) {
		exceptions = guest_exception_count;
		csr_write(CSR_STIMECMP, -1UL);
		guest_failure |= guest_exception_count != exceptions;
	}

	asm volatile(
		".option push\n"
		".option norvc\n"
		"csrr %0, mstatus\n"
		".option pop\n" : "=r" (ignored) : : "memory");
	guest_illegal_cause = guest_last_cause;
	guest_failure |= guest_illegal_cause != EXC_INST_ILLEGAL;
	guest_failure |= (guest_last_mstatus & SR_MPP) !=
			 (KVM_RISCV_MODE_S << 11);

	asm volatile("ecall" ::: "memory");
	guest_ecall_cause = guest_last_cause;
	guest_failure |= guest_ecall_cause != MCAUSE_S_ECALL;

	/* The M trap handler returns this ecall to M-mode. */
	guest_stage = STAGE_S_TRAPS;
	guest_break();

	guest_wait_for_irq(IRQ_M_SOFT, STAGE_M_SOFT_READY,
			   STAGE_M_SOFT_DONE);
	guest_wait_for_irq(IRQ_M_TIMER, STAGE_M_TIMER_READY,
			   STAGE_M_TIMER_DONE);
	guest_wait_for_irq(IRQ_M_EXT, STAGE_M_EXT_READY, STAGE_M_EXT_DONE);

	guest_stage = STAGE_COMPLETE;
	guest_break();
	for (;;)
		asm volatile("wfi");
}

static void guest_code(void)
{
	unsigned long value = 0x12340000;
	unsigned long mask = 0x55;
	unsigned long test_satp;
	unsigned long status;

	csr_write(CSR_MTVEC, (unsigned long)guest_m_trap_vector);
	csr_write(CSR_MSCRATCH, value);
	asm volatile("csrrs %0, mscratch, %1"
		     : "=r" (guest_csr_old) : "r" (mask) : "memory");
	guest_csr_new = csr_read(CSR_MSCRATCH);
	guest_failure |= guest_csr_old != value;
	guest_failure |= guest_csr_new != (value | mask);
	guest_misa = csr_read(CSR_MISA);
	guest_failure |= !(guest_misa & BIT('s' - 'a'));
	guest_failure |= !(guest_misa & BIT('u' - 'a'));
	guest_failure |= !!(guest_misa & BIT('h' - 'a'));
	guest_menvcfg = csr_read(CSR_MENVCFG);
	csr_write(CSR_MENVCFG, guest_menvcfg | ENVCFG_STCE);
	guest_menvcfg = csr_read(CSR_MENVCFG);
	csr_set(CSR_MCOUNTEREN, BIT(1));

	/*
	 * The empty root does not map the current PC.  A real M-mode SATP
	 * write must therefore leave the following M-mode instructions
	 * executable; KVM keeps the value shadowed until mret to S/U.
	 */
#if __riscv_xlen == 64
	test_satp = SATP_MODE_39 |
		((unsigned long)guest_empty_root >> GUEST_PAGE_SHIFT);
#else
	test_satp = SATP_MODE_32 |
		((unsigned long)guest_empty_root >> GUEST_PAGE_SHIFT);
#endif
	csr_write(CSR_SATP, test_satp);
	guest_failure |= csr_read(CSR_SATP) != test_satp;
	asm volatile("sfence.vma" ::: "memory");
	csr_write(CSR_SATP, 0);

	guest_stage = STAGE_CSR;
	guest_break();

	status = csr_read(CSR_MSTATUS);
	status &= ~SR_MPP;
	status |= KVM_RISCV_MODE_S << 11;
	csr_write(CSR_MSTATUS, status);
	csr_write(CSR_MEPC, (unsigned long)guest_s_mode);
	asm volatile("mret");
	__builtin_unreachable();
}

static void run_to_break(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
			 enum test_stage expected)
{
	unsigned long pc;

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_DEBUG);
	sync_global_from_guest(vm, guest_stage);
	sync_global_from_guest(vm, guest_failure);
	TEST_ASSERT_EQ(guest_stage, expected);
	TEST_ASSERT_EQ(guest_failure, 0);

	pc = vcpu_get_reg(vcpu, RISCV_CORE_REG(regs.pc));
	vcpu_set_reg(vcpu, RISCV_CORE_REG(regs.pc), pc + 4);
}

struct inject_args {
	struct kvm_vcpu *vcpu;
	unsigned int irq;
};

static void set_m_irq(struct kvm_vcpu *vcpu, unsigned int irq, bool level)
{
	struct kvm_interrupt interrupt = {
		.irq = level ? KVM_RISCV_INTERRUPT_SET(irq) :
			       KVM_RISCV_INTERRUPT_UNSET(irq),
	};
	int ret;

	ret = ioctl(vcpu->fd, KVM_INTERRUPT, &interrupt);
	TEST_ASSERT(!ret, "KVM_INTERRUPT irq %u level %u failed, errno %d",
		    irq, level, errno);
}

static void *inject_m_irq(void *data)
{
	struct inject_args *args = data;

	usleep(10000);
	set_m_irq(args->vcpu, args->irq, true);
	return NULL;
}

static void test_m_irq(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
		       unsigned int irq, enum test_stage ready,
		       enum test_stage done)
{
	struct inject_args args = { .vcpu = vcpu, .irq = irq };
	pthread_t thread;

	run_to_break(vm, vcpu, ready);
	TEST_ASSERT(!pthread_create(&thread, NULL, inject_m_irq, &args),
		    "pthread_create failed");
	run_to_break(vm, vcpu, done);
	TEST_ASSERT(!pthread_join(thread, NULL), "pthread_join failed");
	set_m_irq(vcpu, irq, false);
}

static void setup_bare_mmode_vm(struct kvm_vm *vm, struct kvm_vcpu *vcpu)
{
	unsigned long start = align_down((unsigned long)&__executable_start,
					 vm->page_size);
	unsigned long end = align_up((unsigned long)&_end, vm->page_size);
	unsigned long addr;
	void *image;

	/*
	 * The generic RISC-V selftest setup uses non-identity Sv48 mappings.
	 * Software M-mode intentionally runs with VSATP cleared, just as real
	 * M-mode ignores satp, so give the bare guest identity-mapped code,
	 * data, and stack before disabling translation.
	 */
	image = malloc(end - start);
	TEST_ASSERT(image, "Failed to allocate bare guest image");
	for (addr = start; addr < end; addr += vm->page_size)
		memcpy(image + addr - start, addr_gva2hva(vm, addr),
		       vm->page_size);
	for (addr = start; addr < end; addr += vm->page_size) {
		memcpy(addr_gpa2hva(vm, addr), image + addr - start,
		       vm->page_size);
		virt_pg_map(vm, addr, addr);
	}
	free(image);

	vcpu_set_reg(vcpu, RISCV_GENERAL_CSR_REG(satp), 0);
	vcpu_set_reg(vcpu, RISCV_CORE_REG(regs.pc),
		     (unsigned long)guest_code);
	vcpu_set_reg(vcpu, RISCV_CORE_REG(regs.sp),
		     (unsigned long)guest_stack + sizeof(guest_stack));
}

static void test_capability_lifecycle(void)
{
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE,
	};
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int ret;

	vm = vm_create(1);
	ret = __vm_enable_cap(vm, KVM_CAP_RISCV_M_MODE, 1);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "nonzero capability argument was not rejected");
	vm_enable_cap(vm, KVM_CAP_RISCV_M_MODE, 0);
	vcpu = vm_vcpu_add(vm, 0, guest_code);
	setup_bare_mmode_vm(vm, vcpu);
	vcpu_guest_debug_set(vcpu, &debug);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpu, RISCV_CORE_REG(mode)),
		       KVM_RISCV_MODE_M);
	ret = __vm_enable_cap(vm, KVM_CAP_RISCV_M_MODE, 0);
	TEST_ASSERT(ret == -1 && errno == EBUSY,
		    "capability enable after vCPU creation was not rejected");

	run_to_break(vm, vcpu, STAGE_CSR);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpu, RISCV_CORE_REG(mode)),
		       KVM_RISCV_MODE_M);
	run_to_break(vm, vcpu, STAGE_S_TRAPS);
	TEST_ASSERT_EQ(vcpu_get_reg(vcpu, RISCV_CORE_REG(mode)),
		       KVM_RISCV_MODE_M);

	test_m_irq(vm, vcpu, IRQ_M_SOFT, STAGE_M_SOFT_READY,
		   STAGE_M_SOFT_DONE);
	test_m_irq(vm, vcpu, IRQ_M_TIMER, STAGE_M_TIMER_READY,
		   STAGE_M_TIMER_DONE);
	test_m_irq(vm, vcpu, IRQ_M_EXT, STAGE_M_EXT_READY, STAGE_M_EXT_DONE);
	run_to_break(vm, vcpu, STAGE_COMPLETE);

	sync_global_from_guest(vm, guest_exception_count);
	sync_global_from_guest(vm, guest_interrupt_count);
	sync_global_from_guest(vm, guest_illegal_cause);
	sync_global_from_guest(vm, guest_ecall_cause);
	TEST_ASSERT_EQ(guest_exception_count, 2);
	TEST_ASSERT_EQ(guest_interrupt_count, 3);
	TEST_ASSERT_EQ(guest_illegal_cause, EXC_INST_ILLEGAL);
	TEST_ASSERT_EQ(guest_ecall_cause, MCAUSE_S_ECALL);

	kvm_vm_free(vm);
}

int main(void)
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_RISCV_M_MODE));
	test_capability_lifecycle();
	return 0;
}
