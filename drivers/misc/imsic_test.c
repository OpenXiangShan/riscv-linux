#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/msi.h>
#include <linux/of_device.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <asm/irq.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/mod_devicetable.h>
#include <linux/irqchip/riscv-imsic.h>

#define IMSIC_TEST_MAX_CPU_NUM 64

struct imsic_test_debug_intf {
	const char name[64];
	struct dentry *d;
	struct dentry * parent;
	const struct file_operations *ops;
};

struct msi_info {
	void *addr;
	int virq;
	int cpu;
	unsigned long pa;
	unsigned int data;
	int times[IMSIC_TEST_MAX_CPU_NUM];
	int times_which;
};

struct imsic_test {
	struct msi_info *msi;
	int count;
	struct platform_device *pdev;
	struct dentry * parent;
};

static struct imsic_test imsic_test = { 0 };

static int imsic_get_cpu(unsigned long addr)
{
	const struct imsic_global_config *global = imsic_get_global_config();
	struct imsic_local_config *l;
	int cpu;

	for_each_online_cpu(cpu) {
		l = per_cpu_ptr(global->local, cpu);
		if (addr == l->msi_pa)
			return cpu;
	}

	return -1;
}

static struct msi_info *get_msi_info(int virq)
{
	int i;

	for (i = 0; i < imsic_test.count; i++) {
		if (virq == imsic_test.msi[i].virq)
			return &imsic_test.msi[i];
	}

	for (i = 0; i < imsic_test.count; i++) {
		if (imsic_test.msi[i].virq == -1)
			return &imsic_test.msi[i];
	}

	return NULL;
}

static void imsic_test_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	struct msi_info *msi;

	msi = get_msi_info(desc->irq);
	if (!msi) {
		printk("No free msi info!!\n");
		return;
	}

	msi->pa = msg->address_lo;
	msi->data = msg->data;
	msi->cpu = imsic_get_cpu(msi->pa);
}

static irqreturn_t imsic_irq_handler(int irq, void *data)
{
	struct msi_info *msi = (struct msi_info *)data;
	int cpu = smp_processor_id();

	printk("#################### %s -- virq:%d hwirq:%d cpu:%d\n",
			__FUNCTION__, irq, msi->data, cpu);

	if (cpu >= IMSIC_TEST_MAX_CPU_NUM) {
		printk("Can not record more than %d cpus irq info\n", IMSIC_TEST_MAX_CPU_NUM);
		return IRQ_HANDLED;
	}

	msi->times[cpu]++;

	return IRQ_HANDLED;
}

static int imsic_test_affinity_set(void *data, u64 val)
{
	struct msi_info *msi = (struct msi_info *)data;
	const struct imsic_global_config *global;
	struct imsic_local_config *l;

	if (!msi) {
		printk("Can not find msi_info\n");
		return 0;
	}

	irq_force_affinity(msi->virq, cpumask_of(val));

	global = imsic_get_global_config();
	l = per_cpu_ptr(global->local, val);

	iounmap(msi->addr);
	msi->pa = l->msi_pa;
	msi->addr = ioremap(msi->pa, 4);

	return 0;
}

static int imsic_test_affinity_get(void *data, u64 *val)
{
	struct msi_info *msi = (struct msi_info *)data;

	if (!msi) {
		printk("Can not find msi_info\n");
		return 0;
	}

	*val = msi->cpu;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(imsic_test_affinity_fops, imsic_test_affinity_get,
			 imsic_test_affinity_set, "%llu\n");

static int imsic_test_trigger_set(void *data, u64 val)
{
	struct msi_info *msi = (struct msi_info *)data;

	if (!msi) {
		printk("Can not find msi_info\n");
		return 0;
	}

	printk("#################### write %d to 0x%lx\n",
	       msi->data, msi->pa);
	writel(msi->data, (void *)msi->addr);

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(imsic_test_trigger_fops, NULL,
			 imsic_test_trigger_set, "%llu\n");

static int imsic_test_virq_get(void *data, u64 *val)
{
	struct msi_info *msi = (struct msi_info *)data;

	if (!msi) {
		printk("Can not find msi_info\n");
		return 0;
	}

	*val = msi->virq;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(imsic_test_virq_fops, imsic_test_virq_get,
			 NULL, "%llu\n");

static int imsic_test_hwirq_get(void *data, u64 *val)
{
	struct msi_info *msi = (struct msi_info *)data;

	if (!msi) {
		printk("Can not find msi_info\n");
		return 0;
	}

	*val = msi->data;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(imsic_test_hwirq_fops, imsic_test_hwirq_get,
			 NULL, "%llu\n");

static int imsic_test_times_get(void *data, u64 *val)
{
	struct msi_info *msi = (struct msi_info *)data;
	int i;

	if (!msi) {
		printk("Can not find msi_info\n");
		return 0;
	}

	if (msi->times_which == -1) {
		int total = 0;

		for (i = 0; i < IMSIC_TEST_MAX_CPU_NUM; i++)
			total += msi->times[i];

		*val = total;

		return 0;
	}

	*val = msi->times[msi->times_which];

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(imsic_test_times_fops, imsic_test_times_get,
			 NULL, "%llu\n");
static struct imsic_test_debug_intf debug_intf_irq[] = {
	{ "affinity", NULL, NULL, &imsic_test_affinity_fops },
	{ "trigger", NULL, NULL, &imsic_test_trigger_fops },
	{ "virq", NULL, NULL, &imsic_test_virq_fops },
	{ "hwirq", NULL, NULL, &imsic_test_hwirq_fops },
	{ "times", NULL, NULL, &imsic_test_times_fops },
};
#define IMSIC_TEST_DEBUG_IRQ_ATTR_COUNT (sizeof(debug_intf_irq) / sizeof(debug_intf_irq[0]))

static void imsic_test_create_per_irq_debug_intr(void)
{
	int i, j;
	struct dentry *parent_dir;

	for (i = 0; i < imsic_test.count; i++) {
		char name[8];
		struct msi_info *msi = &imsic_test.msi[i];
		sprintf(name, "%d", i);
		parent_dir = debugfs_create_dir(name, imsic_test.parent);
		for (j = 0; j < IMSIC_TEST_DEBUG_IRQ_ATTR_COUNT; j++) {
			debug_intf_irq[j].d = debugfs_create_file(debug_intf_irq[j].name,
								  S_IRUGO | S_IWUSR,
								  parent_dir,
								  msi,
								  debug_intf_irq[j].ops);
		}
	}
}

static int imsic_test_count_set(void *data, u64 val)
{
	int ret = 0, i;
	struct platform_device *pdev = imsic_test.pdev;

	if (imsic_test.count != 0) {
		printk("Please reset first!!\n");
		return 0;
	}

	printk("set count = %d\n", (int)val);
	imsic_test.count = val;

	if (!imsic_test.msi) {
		imsic_test.msi = kzalloc(imsic_test.count * sizeof(struct msi_info),
					 GFP_KERNEL);
		if (!imsic_test.msi)
			goto ret2;
	}

	for (i = 0; i < imsic_test.count; i++)
		imsic_test.msi[i].virq = -1;

	ret =
	    platform_device_msi_init_and_alloc_irqs(&pdev->dev, imsic_test.count,
						    imsic_test_write_msi_msg);
	if (ret) {
		printk("%s -- alloc msi irqs failed... ret:%d\n", __FUNCTION__,
		       ret);
		goto ret1;
	}

	for (i = 0; i < imsic_test.count; i++) {
		imsic_test.msi[i].virq = msi_get_virq(&pdev->dev, i);
		if (request_irq(imsic_test.msi[i].virq,
				imsic_irq_handler,
				0, "imsci_test",
				(void *)&imsic_test.msi[i])) {
			printk("%s -- request irq failed\n", __FUNCTION__);
			goto ret1;
		}
		imsic_test.msi[i].times_which = -1;
	}

	for (i = 0; i < imsic_test.count; i++)
		imsic_test.msi[i].addr = ioremap(imsic_test.msi[i].pa, 4);

	imsic_test_create_per_irq_debug_intr();

	return 0;

ret1:
	platform_device_msi_free_irqs_all(&pdev->dev);
	kfree(imsic_test.msi);
ret2:
	imsic_test.count = 0;
	return 0;
}

static int imsic_test_count_get(void *data, u64 *val)
{
	*val = imsic_test.count;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(imsic_test_count_fops, imsic_test_count_get,
			 imsic_test_count_set, "%llu\n");

static int imsic_test_reset_set(void *data, u64 val)
{
	imsic_test.msi = NULL;
	imsic_test.count = 0;

//	platform_device_msi_free_irqs_all(&imsic_test.pdev->dev);
	memset(imsic_test.msi, 0, imsic_test.count * sizeof(struct msi_info));

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(imsic_test_reset_fops, NULL,
			 imsic_test_reset_set, "%llu\n");

static int imsic_test_dump_all_get(void *data, u64 *val)
{
	int i;
	struct msi_info *msi;

	printk("##################### dump imsic_test info #####################\n");
	for (i = 0; i < imsic_test.count; i++) {
		int total = 0, cpu;

		msi = &imsic_test.msi[i];
		printk("%d:\n", i);
		printk("    virq: %d\n", (int)msi->virq);
		printk("    hwirq: %d\n", (int)msi->data);
		printk("    affinity_cpu: %d\n", msi->cpu);
		printk("    msi_addr: 0x%lx\n", msi->pa);
		printk("    trigger_times:\n");
		for_each_online_cpu(cpu) {
			total += msi->times[cpu];
			printk("        cpu%d:%dtimes\n", cpu, msi->times[cpu]);
		}
		printk("        total_trigger_times:%d\n", total);
	}

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(imsic_test_dump_all_fops, imsic_test_dump_all_get,
			 NULL, "%llu\n");

static struct imsic_test_debug_intf debug_intf[] = {
	{ "reset", NULL, NULL, &imsic_test_reset_fops },
	{ "count", NULL, NULL, &imsic_test_count_fops },
	{ "dump_all", NULL, NULL, &imsic_test_dump_all_fops },
};
#define IMSIC_TEST_DEBUG_ATTR_COUNT (sizeof(debug_intf) / sizeof(debug_intf[0]))

static int imsic_test_platform_probe(struct platform_device *pdev)
{
	pdev->dev.msi.domain = imsic_get_irqdomain();
	imsic_test.pdev = pdev;

	return 0;
}

static void imsic_test_platform_remove(struct platform_device *pdev)
{
	int i;

	for (i = 0; i < imsic_test.count; i++)
		iounmap(imsic_test.msi[i].addr);

	platform_device_msi_free_irqs_all(&imsic_test.pdev->dev);
	kfree(imsic_test.msi);

}

static struct platform_device imsic_test_platform_device = {
	.name = "imsic_test_platform_device",
	.id = -1,
};

static int __init imsic_test_init(void)
{
	struct dentry *parent_dir;
	int i;

	platform_device_register(&imsic_test_platform_device);

	parent_dir = debugfs_create_dir("imsic_test", NULL);
	if (IS_ERR(parent_dir)) {
		printk("create imsic_test fail\n");
		return -1;
	}

	for (i = 0; i < IMSIC_TEST_DEBUG_ATTR_COUNT; i++) {
		debug_intf[i].parent = parent_dir;
		debug_intf[i].d = debugfs_create_file(debug_intf[i].name,
						      S_IRUGO | S_IWUSR,
						      debug_intf[i].parent,
						      NULL,
						      debug_intf[i].ops);
	}

	imsic_test.parent = parent_dir;

	return 0;
}

late_initcall(imsic_test_init);

static const struct of_device_id imsic_platform_match[] = {
	{.compatible = "imsic,test" },
	{}
};

static struct platform_driver imsic_test_platform_driver = {
	.probe = imsic_test_platform_probe,
	.remove = imsic_test_platform_remove,
	.driver = {
		   .name = "imsic_test_platform_device",
		   .of_match_table = imsic_platform_match,
		    }
};

module_platform_driver(imsic_test_platform_driver);
MODULE_LICENSE("GPL v2");
