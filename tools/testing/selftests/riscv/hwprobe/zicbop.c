#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <signal.h>
#include <assert.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <asm/ucontext.h>

#include "hwprobe.h"
#include "../../kselftest.h"

#define     SIZE      32

static bool illegal_insn;
static int test_array[SIZE];

static inline void prefetch_i(const void *addr)
{
    asm volatile ("prefetch.i 0(a0)");
}

static inline void prefetch_r(const void *addr)
{
    asm volatile ("prefetch.r 0(a0)");
}

static inline void prefetch_w(const void *addr)
{
    asm volatile ("prefetch.w 0(a0)");
}

static void sigill_handler(int sig, siginfo_t *info, void *context)
{
	unsigned long *regs = (unsigned long *)&((ucontext_t *)context)->uc_mcontext;
	uint32_t insn = *(uint32_t *)regs[0];

	illegal_insn = true;
	regs[0] += 4;
}

static void array_init() {
    for (int i = 0; i < SIZE; i++) {
        test_array[i] = i;
    }
}

int main(int argc, char **argv)
{
    int i,j;

	struct sigaction act = {
		.sa_sigaction = &sigill_handler,
		.sa_flags = SA_SIGINFO,
	};
    long rc;

    ksft_print_header();

    /* prefetch.i test */
    illegal_insn = false;
    prefetch_i(array_init);
    array_init();

    if (illegal_insn) {
        printf("prefetch_i failed");
        printf("TEST FAIL\n");
        return -1;
	} else
        printf("prefetch_i ok!\n");

    /* prefetch.r test */
    for (i = 0; i < SIZE; i += 16) {
        prefetch_r(&test_array[i]);
        for (j = 0; j < 16; j++)
            if (test_array[i + j] != (i + j)) {
                printf("test_array[%d]=%d\n", i + j, test_array[i + j]);
                printf("prefetch.r failed\n");
                printf("TEST FAIL\n");
                return -1;
            }
    }
    if (illegal_insn) {
        printf("prefetch_r failed");
        printf("TEST FAIL\n");
        return -1;
	} else
        printf("prefetch_r ok!\n");

    /* prefetch.w test */
    for (i = 0; i < SIZE; i += 16) {
        prefetch_w(&test_array[i]);
        for (j = 0; j < 16; j++)
            test_array[i + j] = 1;
    }
    if (illegal_insn) {
        printf("prefetch_w failed");
        printf("TEST FAIL\n");
        return -1;
	} else {
        printf("prefetch_w ok!\n");
        printf("TEST PASS\n");
    }

    return 0;
}
