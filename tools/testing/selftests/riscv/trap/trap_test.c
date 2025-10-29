#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

// 对于内存保护测试
#if defined(__unix__) || defined(__linux__)
#include <sys/mman.h>
#endif

// 全局跳转缓冲区
static jmp_buf env_ill, env_segv, env_bus, env_trap, env_fpe;

// 测试结果计数器
static int tests_passed = 0;
static int tests_failed = 0;
static int current_test = 0;

// 更安全的信号处理函数
void signal_handler(int sig)
{
	printf("   ✓ Caught signal %d in test %d\n", sig, current_test);

	switch (sig) {
	case SIGILL:
		siglongjmp(env_ill, 1);
		break;
	case SIGSEGV:
		siglongjmp(env_segv, 1);
		break;
	case SIGBUS:
		siglongjmp(env_bus, 1);
		break;
	case SIGTRAP:
		siglongjmp(env_trap, 1);
		break;
	case SIGFPE:
		siglongjmp(env_fpe, 1);
		break;
	default:
		// 未知信号，退出程序
		printf("   ✗ Unknown signal %d, exiting\n", sig);
		exit(1);
	}
}

// 设置信号处理器
void setup_signal_handlers(void)
{
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NODEFER; // 允许信号处理期间接收相同信号

	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGTRAP, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
}

// 测试结果记录
void record_test_result(int passed, const char *test_name)
{
	if (passed) {
		printf("✅ %s: TEST DONE\n", test_name);
		tests_passed++;
	} else {
		printf("❌ %s: TEST FAIL\n", test_name);
		tests_failed++;
	}
}

// 1. 测试指令地址错误（Instruction address misaligned）
void test_instruction_address_misaligned(void)
{
	current_test = 1;
	printf("\n1. Testing Instruction Address Misaligned...\n");

	// 使用更安全的方法 - 分配可执行内存
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *exec_mem = mmap(NULL, page_size,
	                      PROT_READ | PROT_WRITE | PROT_EXEC,
	                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (exec_mem == MAP_FAILED) {
		perror("   mmap failed");
		record_test_result(0, "Instruction Address Misaligned");
		return;
	}

	// 在 RISC-V 中，我们需要填充有效的 RISC-V 指令
	// 使用简单的 nop 指令（ADDI x0, x0, 0）编码为 0x00000013
	unsigned int nop_instruction = 0x00000013;

	// 填充多个 nop 指令，确保无论从哪里开始执行都能找到完整指令
	for (int i = 0; i < page_size / sizeof(nop_instruction); i++) {
		((unsigned int *)exec_mem)[i] = nop_instruction;
	}

	// 在末尾添加 ret 指令（JALR x0, 0(x1)）编码为 0x00008067
	((unsigned int *)exec_mem)[(page_size / sizeof(nop_instruction)) - 1] = 0x00008067;

	printf("   Allocated executable memory at %p\n", exec_mem);

	// 尝试多个不同的非对齐偏移
	int found_exception = 0;
	for (int offset = 1; offset < 4; offset++) {
		if (sigsetjmp(env_ill, 1) == 0 && sigsetjmp(env_segv, 1) == 0) {
			void (*func)(void);
			// 创建非对齐的函数指针
			func = (void (*)(void))((char *)exec_mem + offset);
			printf("   Attempting to execute at misaligned address %p (offset %d)...\n",
			       (void *)func, offset);
			func();

			// 如果到达这里，说明没有异常
			printf("   No exception at offset %d\n", offset);
		} else {
			// 捕获到了异常
			printf("   ✓ Exception caught at offset %d\n", offset);
			found_exception = 1;
			break;
		}
	}

	munmap(exec_mem, page_size);

	if (found_exception) {
		record_test_result(1, "Instruction Address Misaligned");
	} else {
		printf("   ⚠️ No misaligned instruction exception detected\n");
		record_test_result(0, "Instruction Address Misaligned");
	}
}

// 2. 测试指令访问错误（Instruction access fault）
void test_instruction_access_fault(void)
{
	current_test = 2;
	printf("\n2. Testing Instruction Access Fault...\n");

	if (sigsetjmp(env_segv, 1) == 0) {
		// 使用一个明显无效但不会立即崩溃的地址
		volatile char *invalid_addr = (volatile char *)0x1000; // 低地址，通常受保护

		// 尝试作为函数调用
		void (*func)(void) = (void (*)(void))invalid_addr;
		func(); // 这应该触发 SIGSEGV

		record_test_result(0, "Instruction Access Fault");
	} else {
		record_test_result(1, "Instruction Access Fault");
	}
}

// 3. 测试非法指令（Illegal instruction）
void test_illegal_instruction(void)
{
	current_test = 3;
	printf("\n3. Testing Illegal Instruction...\n");

	if (sigsetjmp(env_ill, 1) == 0) {
		// 更安全的方法：在可执行内存中放置非法指令
		void *exec_mem = mmap(NULL, sysconf(_SC_PAGESIZE),
		                      PROT_READ | PROT_WRITE | PROT_EXEC,
		                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (exec_mem != MAP_FAILED) {
			// 填充全零，非法指令
			memset(exec_mem, 0, 16);

			void (*func)(void) = (void (*)(void))exec_mem;
			func();

			munmap(exec_mem, sysconf(_SC_PAGESIZE));
		}
		record_test_result(0, "Illegal Instruction");
	} else {
		record_test_result(1, "Illegal Instruction");
	}
}

// 4. 测试断点（Breakpoint）
void test_breakpoint(void)
{
	current_test = 4;
	printf("\n4. Testing Breakpoint...\n");

	if (sigsetjmp(env_trap, 1) == 0) {
		__asm__ __volatile__("ebreak"); // RISC-V 断点指令

		record_test_result(0, "Breakpoint");
	} else {
		record_test_result(1, "Breakpoint");
	}
}

// 5. 测试环境调用/系统调用（ECALL）
void test_ecall_syscall(void)
{
	current_test = 5;
	printf("\n5. Testing ECALL/System Call...\n");

	// 系统调用应该正常完成，不触发异常
	long result = syscall(SYS_getpid);
	if (result > 0) {
		printf("   System call returned PID: %ld\n", result);
		record_test_result(1, "ECALL/System Call");
	} else {
		record_test_result(0, "ECALL/System Call");
	}
}

// 6. 测试加载/存储地址错误（Load/Store address misaligned）
// 6. 测试加载/存储地址错误（Load/Store address misaligned）
void test_load_store_misaligned(void)
{
	current_test = 6;
	printf("\n6. Testing Load/Store Address Misaligned...\n");

	void *aligned_buffer;
	if (posix_memalign(&aligned_buffer, 64, 64) != 0) {
		perror("   posix_memalign failed");
		record_test_result(0, "Load/Store Address Misaligned");
		return;
	}
	char *buffer = (char *)aligned_buffer;

	// 创建非对齐的指针
	volatile int *misaligned_ptr = (volatile int *)(buffer + 1);

	int exception_caught = 0;
	int value_written = 0x12345678;
	int value_read;

	// 测试非对齐存储
	if (sigsetjmp(env_bus, 1) == 0) {
		*misaligned_ptr = value_written;
	} else {
		exception_caught = 1;
	}

	// 测试非对齐加载
	if (!exception_caught && sigsetjmp(env_bus, 1) == 0) {
		value_read = *misaligned_ptr;
	} else {
		exception_caught = 1;
	}

	free(aligned_buffer);

	if (exception_caught) {
		printf("   ✓ Exception caught - misaligned access not supported\n");
		record_test_result(1, "Load/Store Address Misaligned");
	} else {
		// 检查非对齐访问是否被正确模拟
		if (value_read == value_written) {
			printf("   No exception, but misaligned access correctly simulated by kernel\n");
			record_test_result(1, "Load/Store Address Misaligned (kernel simulated)");
		} else {
			printf("   No exception, but misaligned access failed: wrote 0x%x, read 0x%x\n", value_written, value_read);
			record_test_result(0, "Load/Store Address Misaligned");
		}
	}
}

// 7. 测试内存保护违规（Access Fault）
void test_memory_protection_fault(void)
{
	current_test = 7;
	printf("\n7. Testing Memory Protection Fault...\n");

	if (sigsetjmp(env_segv, 1) == 0) {
		// 使用 mmap 创建只读内存区域
		size_t page_size = sysconf(_SC_PAGESIZE);
		void *readonly_mem = mmap(NULL, page_size,
		                          PROT_READ, // 只读权限
		                          MAP_PRIVATE | MAP_ANONYMOUS,
		                          -1, 0);

		if (readonly_mem == MAP_FAILED) {
			perror("   mmap failed for readonly memory");
			record_test_result(0, "Memory Protection Fault (setup failed)");
			return;
		}

		printf("   Created readonly memory at %p, attempting write...\n", readonly_mem);

		// 尝试写入只读内存 - 这应该触发真正的访问错误
		volatile char *ptr = (volatile char *)readonly_mem;
		*ptr = 'A'; // 写入只读内存

		// 如果到达这里，测试失败
		munmap(readonly_mem, page_size);
		record_test_result(0, "Memory Protection Fault");
	} else {
		record_test_result(1, "Memory Protection Fault");
	}
}

// 8. 测试除零异常
void test_division_by_zero(void)
{
	current_test = 8;
	printf("\n8. Testing Division by Zero...\n");

	// 在 RISC-V 中，我们需要测试浮点除零，因为整数除零不会触发异常
	int exception_caught = 0;

	// 测试1: 整数除零（在RISC-V中通常不会触发异常）
	printf("   Testing integer division by zero... ");
	if (sigsetjmp(env_fpe, 1) == 0 && sigsetjmp(env_ill, 1) == 0) {
		volatile int a = 1, b = 0;
		volatile int c = a / b; 
		printf("No exception c=%d \n", c);
	} else {
		printf("Exception caught (unexpected for integer division in RISC-V)\n");
		exception_caught = 1;
	}

	// 测试2: 浮点除零（这应该触发异常）
	printf("   Testing floating point division by zero... ");
	if (sigsetjmp(env_fpe, 1) == 0 && sigsetjmp(env_ill, 1) == 0) {
		volatile double x = 1.0, y = 0.0;
		volatile double z = x / y; // 这应该触发 SIGFPE
		printf("No exception z =%f\n", z);
		record_test_result(0, "Division by Zero");
	} else {
		printf("Exception caught ✓\n");
		record_test_result(1, "Division by Zero");
		exception_caught = 1;
	}

	// 如果两种测试都没有捕获异常，但浮点除零应该触发，则标记为失败
	if (!exception_caught) {
		record_test_result(0, "Division by Zero");
	}
}

// 9. 测试缺页异常（Page Fault）
void test_page_fault(void)
{
	current_test = 9;
	printf("\n9. Testing Page Fault...\n");

	int tests_passed = 0;
	int tests_total = 0;

	size_t page_size = sysconf(_SC_PAGESIZE);

	// 测试1: 读取未映射的内存
	tests_total++;
	printf("   [%d] Read from unmapped memory... ", tests_total);
	if (sigsetjmp(env_segv, 1) == 0) {
		// 映射一页内存，然后立即取消映射
		void *addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (addr == MAP_FAILED) {
			perror("      mmap failed");
			printf("SKIPPED\n");
			tests_total--; // 这个测试没执行，所以总数减1
		} else {
			// 立即取消映射
			munmap(addr, page_size);

			// 现在尝试读取已取消映射的内存
			volatile int value = *(volatile int *)addr;
			(void)value;

			printf("No page fault (unexpected)\n");
			// 如果到达这里，说明没有触发缺页异常，测试失败
		}
	} else {
		printf("Page fault caught ✓\n");
		tests_passed++;
	}

	// 测试2: 写入未映射的内存
	tests_total++;
	printf("   [%d] Write to unmapped memory... ", tests_total);
	if (sigsetjmp(env_segv, 1) == 0) {
		void *addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (addr == MAP_FAILED) {
			perror("      mmap failed");
			printf("SKIPPED\n");
			tests_total--;
		} else {
			munmap(addr, page_size);

			// 尝试写入已取消映射的内存
			*(volatile int *)addr = 0x12345678;

			printf("No page fault (unexpected)\n");
		}
	} else {
		printf("Page fault caught ✓\n");
		tests_passed++;
	}

	// 测试3: 执行未映射的内存
	tests_total++;
	printf("   [%d] Execute from unmapped memory... ", tests_total);
	if (sigsetjmp(env_segv, 1) == 0) {
		void *addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
		                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (addr == MAP_FAILED) {
			perror("      mmap failed");
			printf("SKIPPED\n");
			tests_total--;
		} else {
			// 填充一些指令（在RISC-V中是nop）
			*(unsigned int *)addr = 0x00000013; // nop指令

			munmap(addr, page_size);

			// 尝试执行已取消映射的内存
			void (*func)(void) = (void (*)(void))addr;
			func();

			printf("No page fault (unexpected)\n");
		}
	} else {
		printf("Page fault caught ✓\n");
		tests_passed++;
	}

	// 测试4: 读取没有读取权限的内存
	tests_total++;
	printf("   [%d] Read from no-read memory... ", tests_total);
	void *addr = NULL;
	if (sigsetjmp(env_segv, 1) == 0) {
		addr = mmap(NULL, page_size, PROT_NONE, // 只有写权限，没有读权限
		            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (addr == MAP_FAILED) {
			perror("      mmap failed");
			printf("SKIPPED\n");
			tests_total--;
		} else {
			// 尝试读取没有读取权限的内存
			volatile int value = *(volatile int *)addr;
			printf("value = %d\n", value);

			munmap(addr, page_size);
			printf("No page fault (unexpected)\n");
		}
	} else {
		printf("Page fault caught ✓\n");
		tests_passed++;
		if (addr != NULL && addr != MAP_FAILED) {
			munmap(addr, page_size);
		}
	}

	// 测试5: 写入没有写入权限的内存
	tests_total++;
	printf("   [%d] Write to no-write memory... ", tests_total);
	void *readonly_addr = NULL;
	if (sigsetjmp(env_segv, 1) == 0) {
		readonly_addr = mmap(NULL, page_size, PROT_READ, // 只有读权限，没有写权限
		                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (readonly_addr == MAP_FAILED) {
			perror("      mmap failed");
			printf("SKIPPED\n");
			tests_total--;
		} else {
			// 尝试写入没有写入权限的内存
			*(volatile int *)readonly_addr = 0x12345678;

			printf("No page fault (unexpected)\n");
		}
	} else {
		printf("Page fault caught ✓\n");
		tests_passed++;
	}

	// 清理只读映射
	if (readonly_addr != NULL && readonly_addr != MAP_FAILED) {
		munmap(readonly_addr, page_size);
	}

	// 测试6: 执行没有执行权限的内存
	tests_total++;
	printf("   [%d] Execute from no-exec memory... ", tests_total);
	void *noexec_addr = NULL;
	if (sigsetjmp(env_segv, 1) == 0) {
		noexec_addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, // 没有执行权限
		                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (noexec_addr == MAP_FAILED) {
			perror("      mmap failed");
			printf("SKIPPED\n");
			tests_total--;
		} else {
			// 填充一些指令
			*(unsigned int *)noexec_addr = 0x00000013; // nop指令

			// 尝试执行没有执行权限的内存
			void (*func)(void) = (void (*)(void))noexec_addr;
			func();

			printf("No page fault (unexpected)\n");
		}
	} else {
		printf("Page fault caught ✓\n");
		tests_passed++;
	}

	// 清理无执行权限映射
	if (noexec_addr != NULL && noexec_addr != MAP_FAILED) {
		munmap(noexec_addr, page_size);
	}

	printf("   Page fault tests: %d/%d passed\n", tests_passed, tests_total);

	if (tests_total == 0) {
		record_test_result(0, "Page Fault (no tests executed)");
	} else if (tests_passed == tests_total) {
		record_test_result(1, "Page Fault");
	} else {
		record_test_result(0, "Page Fault");
	}
}

void print_test_summary(void)
{
	printf("\n══════════════════════════════════════════════════\n");
	printf("📊 TEST SUMMARY\n");
	printf("══════════════════════════════════════════════════\n");
	printf("✅ Tests PASSED: %d\n", tests_passed);
	printf("❌ Tests FAILED: %d\n", tests_failed);

	int total = tests_passed + tests_failed;
	if (total > 0) {
		printf("📈 Success Rate: %.1f%%\n", (float)tests_passed / total * 100);
	}

	if (tests_failed == 0 && total > 0) {
		printf("\n🎉 All tests passed!\n");
	} else if (total > 0) {
		printf("\n⚠️  Some tests failed. This may be architecture-dependent.\n");
	}
}

int main(void)
{
	printf("🚀 Starting RISC-V/Linux Exception Tests\n");
	printf("══════════════════════════════════════════════════\n");

	// 设置信号处理器
	setup_signal_handlers();

	// 运行所有测试
	test_instruction_address_misaligned();
	test_instruction_access_fault();
	test_illegal_instruction();
	test_breakpoint();
	test_ecall_syscall();
	test_load_store_misaligned();
	test_memory_protection_fault();
	test_division_by_zero();
	test_page_fault();
	// 显示测试结果摘要
	print_test_summary();

	return (tests_failed == 0) ? 0 : 1;
}
