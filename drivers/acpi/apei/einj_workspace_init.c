#include <linux/init.h>
#include <linux/io.h>

#define ERROR_STATUS_BLOCK_ADDR  0x87001200UL
#define ERROR_STATUS_BLOCK_SIZE  0x1000

#define ERST_WORKSPACE_ADDR       0x87003000UL
#define ERST_WORKSPACE_SIZE       0x1000
#define ERST_REG_WINDOW_SIZE      0x30

#define ERST_LOG_ADDR             0x87004000UL
#define ERST_LOG_SIZE             0x2000

static int __init einj_workspace_clear(void)
{
    void __iomem *vaddr;

    pr_info("Clearing Error Status Block zzk  at 0x%lx\n", ERROR_STATUS_BLOCK_ADDR);

    // 直接使用 ioremap - treats as device memory
    vaddr = ioremap(ERROR_STATUS_BLOCK_ADDR, ERROR_STATUS_BLOCK_SIZE);
    if (!vaddr) {
        pr_err("Failed to ioremap Error Status Block!\n");
        return -ENOMEM;
    }

    memset_io(vaddr, 0, ERROR_STATUS_BLOCK_SIZE);
    iounmap(vaddr);

    return 0;
}
early_initcall(einj_workspace_clear);


static int __init erst_init_registers(void)
{
    void __iomem *base = ioremap(ERST_WORKSPACE_ADDR, ERST_REG_WINDOW_SIZE);
    if (!base)
        return -ENOMEM;

    writel(ERST_LOG_ADDR, base); // base address
    writel(ERST_LOG_SIZE,     base + 0x08); // size
    writel(0,          base + 0x04);				    			 
    writel(0,          base + 0x20); //  attributes = 0 (NOT NVRAM!)
    writel(0,          base + 0x04); 
    writeq(0, 	       base + 0x28);
    pr_err("erst_init_registers read04=0x%lx !\n", readl(base + 0x04));
    iounmap(base);

    base = ioremap(ERST_LOG_ADDR, ERST_LOG_SIZE);
    memset_io(base, 0, ERST_LOG_SIZE);
    iounmap(base);

    return 0;
}
early_initcall(erst_init_registers);
