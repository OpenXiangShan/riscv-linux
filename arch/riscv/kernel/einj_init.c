#include <linux/mm.h>
#include <linux/io.h>

/* Symbols exported by einj_workspace.S */
extern char einj_workspace_start[];
extern char einj_workspace_end[];

#define EINJ_WORKSPACE_TARGET_PA    0x87000000UL
#define EINJ_WORKSPACE_SIZE         0x2000 
#define EINJ_TRIGGER_ADDR_OFFSET    0x18

static int __init einj_workspace_load(void)
{
    unsigned long size = einj_workspace_end - einj_workspace_start;
    
    if (size > EINJ_WORKSPACE_SIZE) {
        pr_err("EINJ: workspace too big\n");
        return -ENOMEM;
    }

    // 替换 memremap 为 ioremap
	void __iomem *target_virt = ioremap(EINJ_WORKSPACE_TARGET_PA, EINJ_WORKSPACE_SIZE);
		if (!target_virt) {
    		pr_err("EINJ: ioremap failed\n");
    		return -ENOMEM;
	}
// ioremap_wc
// 使用 memcpy_toio（针对 I/O 内存）
	memcpy_toio(target_virt, einj_workspace_start, size);

	// 读回验证（使用 readq/readl）
	u64 trigger_val = readq(target_virt + EINJ_TRIGGER_ADDR_OFFSET);
	pr_info("EINJ: zzk trigger_addr = 0x%llx\n", trigger_val);

	iounmap(target_virt);

    	return 0;
}

/* 必须在内存子系统初始化后 */
device_initcall(einj_workspace_load);
