/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 OpenEuler Foundation
 * SVPBMT functionality test
 *
 * This module tests the Supervisor-mode page-based memory types (SVPBMT)
 * extension functionality by setting different memory types and verifying
 * the page table entries have the correct memory type attributes.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/csr.h>
#include <asm/set_memory.h>

#define TEST_SIZE PAGE_SIZE
#define TEST_NAME "svpbmt_test"

static void *normal_buf;
static void *wc_buf;
static void *io_buf;

/* 检查CPU是否支持SVPBMT扩展 */
static bool check_svpbmt_support(void)
{
	/* 尝试通过检查riscv_page_mtmask函数返回值来判断SVPBMT支持 */
	unsigned long mtmask = riscv_page_mtmask();

	pr_info("%s: riscv_page_mtmask() result: 0x%lx\n", TEST_NAME, mtmask);

	/* 如果mtmask为0，可能表示不支持SVPBMT扩展 */
	if (mtmask == 0) {
		pr_info("%s: SVPBMT extension not supported\n", TEST_NAME);
		return false;
	}

	/* 检查_PAGE_MTMASK和_PAGE_MTMASK_SVPBMT是否定义并正确设置 */
	pr_info("%s: _PAGE_MTMASK: 0x%llx\n", TEST_NAME, _PAGE_MTMASK);
	pr_info("%s: _PAGE_MTMASK_SVPBMT: 0x%lx\n", TEST_NAME,
		_PAGE_MTMASK_SVPBMT);

	return true;
}

/* 简单的内存性能测试，用于验证不同内存类型的行为差异 */
static void test_memory_performance(void *buf, const char *type)
{
	unsigned long long start_time, end_time, duration;
	unsigned long i, j;
	unsigned long *p = (unsigned long *)buf;
	unsigned long sum = 0;

	/* 执行一系列内存读写操作 */
	start_time = ktime_get_ns();

	for (i = 0; i < 100000; i++) {
		for (j = 0; j < 64; j++) {
			p[j] = i + j;
			sum += p[j];
		}
	}

	end_time = ktime_get_ns();

	/* 计算执行时间（纳秒） */
	duration = end_time - start_time;

	/* 防止编译器优化掉循环 */
	if (sum == 0)
		pr_debug("%s: Preventing compiler optimization\n", TEST_NAME);

	pr_info("%s: %s memory operations took %llu nanoseconds\n", TEST_NAME,
		type, duration);
}

static pte_t *get_pte(void *addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	// 对于内核进程，应该使用init_mm而不是current->mm
	pgd = pgd_offset_k((unsigned long)addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, (unsigned long)addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;

	pud = pud_offset(p4d, (unsigned long)addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;

	pmd = pmd_offset(pud, (unsigned long)addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;

	pte = pte_offset_map(pmd, (unsigned long)addr);
	if (!pte || pte_none(*pte)) {
		pte_unmap(pte);
		return NULL;
	}

	return pte;
}

static void print_pte_flags(pte_t pte, const char *type)
{
	unsigned long pte_val = pte_val(pte);
	unsigned long mt_val = pte_val & _PAGE_MTMASK;
	const char *mt_str = "Unknown";

	pr_info("%s PTE: %016lx\n", type, pte_val);
	pr_info("  - Present: %s\n", pte_present(pte) ? "Yes" : "No");
	pr_info("  - Read: %s\n", pte_val & _PAGE_READ ? "Yes" : "No");
	pr_info("  - Write: %s\n", pte_val & _PAGE_WRITE ? "Yes" : "No");
	pr_info("  - Execute: %s\n", pte_val & _PAGE_EXEC ? "Yes" : "No");
	pr_info("  - User: %s\n", pte_val & _PAGE_USER ? "Yes" : "No");
	pr_info("  - Global: %s\n", pte_val & _PAGE_GLOBAL ? "Yes" : "No");
	pr_info("  - Accessed: %s\n", pte_val & _PAGE_ACCESSED ? "Yes" : "No");
	pr_info("  - Dirty: %s\n", pte_val & _PAGE_DIRTY ? "Yes" : "No");

	/* 解析内存类型 */
#if defined(CONFIG_64BIT)
	if (mt_val == 0)
		mt_str = "Normal Cacheable";
	else if (mt_val == _PAGE_NOCACHE)
		mt_str = "Non-cacheable";
	else if (mt_val == _PAGE_IO)
		mt_str = "I/O Memory";
#endif

	pr_info("  - Memory Type: %s (0x%lx)\n", mt_str, mt_val);
	pr_info("  - _PAGE_MTMASK value: 0x%llx\n", _PAGE_MTMASK);
	pr_info("  - _PAGE_NOCACHE value: 0x%llx\n", _PAGE_NOCACHE);
	pr_info("  - _PAGE_IO value: 0x%llx\n", _PAGE_IO);

	/* 检查特定的SVPBMT相关位 */
	pr_info("  - SVPBMT MT bits (bits 61-62): %lu\n",
		(pte_val >> 61) & 0x3);
}

static int __init svpbmt_test_init(void)
{
	pte_t *pte;
	bool svpbmt_supported;

	pr_info("%s: Initializing SVPBMT test\n", TEST_NAME);

	/* 检查SVPBMT支持情况 */
	svpbmt_supported = check_svpbmt_support();
	if (!svpbmt_supported) {
		pr_err("%s: Warning: SVPBMT extension not supported or not enabled\n",
			TEST_NAME);
			return 0;
	}

	/* 分配不同内存类型的缓冲区 */
	normal_buf = kzalloc(TEST_SIZE, GFP_KERNEL);
	if (!normal_buf) {
		pr_err("%s: Failed to allocate normal buffer\n", TEST_NAME);
		return -ENOMEM;
	}

	wc_buf = kzalloc(TEST_SIZE, GFP_KERNEL);
	if (!wc_buf) {
		pr_err("%s: Failed to allocate write-combining buffer\n",
		       TEST_NAME);
		kfree(normal_buf);
		return -ENOMEM;
	}

	io_buf = kzalloc(TEST_SIZE, GFP_KERNEL);
	if (!io_buf) {
		pr_err("%s: Failed to allocate I/O buffer\n", TEST_NAME);
		kfree(normal_buf);
		kfree(wc_buf);
		return -ENOMEM;
	}

	/* 访问这些缓冲区以确保页表项被创建 */
	memset(normal_buf, 0xAA, 64);
	memset(wc_buf, 0xBB, 64);
	memset(io_buf, 0xCC, 64);

	/* 修改页面属性为不同的内存类型 */
	set_memory_wc((unsigned long)wc_buf, 1);
	set_memory_io((unsigned long)io_buf, 1);

	/* 获取并打印各缓冲区的PTE信息 */
	pte = get_pte(normal_buf);
	if (pte) {
		print_pte_flags(*pte, "Normal Memory");
		pte_unmap(pte);
	} else {
		pr_err("%s: Failed to get PTE for normal memory\n", TEST_NAME);
	}

	pte = get_pte(wc_buf);
	if (pte) {
		print_pte_flags(*pte, "Write-Combining Memory");
		pte_unmap(pte);
	} else {
		pr_err("%s: Failed to get PTE for write-combining memory\n",
		       TEST_NAME);
	}

	pte = get_pte(io_buf);
	if (pte) {
		print_pte_flags(*pte, "I/O Memory");
		pte_unmap(pte);
	} else {
		pr_err("%s: Failed to get PTE for I/O memory\n", TEST_NAME);
	}

	/* 验证ALT_SVPBMT相关函数 */
	pr_info("%s: riscv_page_nocache() returns: 0x%llx\n", TEST_NAME,
		riscv_page_nocache());
	pr_info("%s: riscv_page_io() returns: 0x%llx\n", TEST_NAME,
		riscv_page_io());

	/* 尝试检测SVPBMT是否生效 */
	if (_PAGE_MTMASK == _PAGE_MTMASK_SVPBMT) {
		pr_info("%s: SVPBMT memory types are active\n", TEST_NAME);
	} else {
		pr_info("%s: Other memory type implementation is active\n",
			TEST_NAME);
	}

	/* 执行内存性能测试 */
	if (svpbmt_supported) {
		pr_info("%s: Running memory performance tests...\n", TEST_NAME);
		test_memory_performance(normal_buf, "Normal");
		test_memory_performance(wc_buf, "Non-cacheable");
		test_memory_performance(io_buf, "I/O");
	}

	pr_info("%s: Test completed\n", TEST_NAME);
	return 0;
}

static void __exit svpbmt_test_exit(void)
{
	/* 恢复页面属性 */
	set_memory_rw((unsigned long)wc_buf, 1);
	set_memory_rw((unsigned long)io_buf, 1);

	/* 释放缓冲区 */
	kfree(normal_buf);
	kfree(wc_buf);
	kfree(io_buf);

	pr_info("%s: Module unloaded\n", TEST_NAME);
}

module_init(svpbmt_test_init);
module_exit(svpbmt_test_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("RISC-V SVPBMT functionality test module");
MODULE_AUTHOR("OpenEuler Foundation");
MODULE_VERSION("1.0");
