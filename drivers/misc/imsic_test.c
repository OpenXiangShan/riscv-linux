#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/msi.h>
#include <linux/of_device.h>
#include <asm/irq.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/mod_devicetable.h>

#define IMSIC_TEST_IRQ_NUM 3

struct msi_info {
	void *addr;
	unsigned long pa;
	unsigned int data;
};

struct imsic_test {
	struct msi_info msi[IMSIC_TEST_IRQ_NUM];
	struct miscdevice miscdev;
};

static struct imsic_test imsic_test;

static void imsic_test_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	static int nn = 0;
	//printk("#################### %s msg->addr_lo:0x%x, msg->addr_hi:0x%x, msg->data:0x%x\n",
	//      __FUNCTION__, msg->address_lo, msg->address_hi, msg->data);

	if (nn >= IMSIC_TEST_IRQ_NUM)
		return;

	imsic_test.msi[nn].pa = msg->address_lo;
	imsic_test.msi[nn].data = msg->data;

	nn++;
}

static irqreturn_t imsic_irq_handler(int irq, void *data)
{
	printk("#################### %s -- virq:%d\n", __FUNCTION__, irq);
	printk("####################, test pass!\n");

	return IRQ_HANDLED;
}

static int imsic_test_platform_probe(struct platform_device *pdev)
{
	int ret = 0, i, virq;

	ret =
	    platform_device_msi_init_and_alloc_irqs(&pdev->dev, IMSIC_TEST_IRQ_NUM,
					   imsic_test_write_msi_msg);
	if (ret) {
		printk("%s -- alloc msi irqs failed... ret:%d\n", __FUNCTION__,
		       __LINE__);
		return ret;
	}

	for (i = 0; i < IMSIC_TEST_IRQ_NUM; i++) {
		virq = msi_get_virq(&pdev->dev, i);
		if (request_irq
		    (virq, imsic_irq_handler, 0, "imsci_test",
		     (void *)&imsic_test)) {
			printk("%s -- request irq failed\n", __FUNCTION__);
			return -1;
		}
	}

	for (i = 0; i < IMSIC_TEST_IRQ_NUM; i++)
		imsic_test.msi[i].addr = ioremap(imsic_test.msi[i].pa, 4);

	printk("#################### %s success\n", __FUNCTION__);

	//printk("#################### write %d to 0x%lx\n", imsic_test.msi[0].data, imsic_test.msi[0].pa);
	//writel(imsic_test.msi[0].data, (void *)imsic_test.msi[0].addr);       

	return 0;
}

static ssize_t imsic_test_write(struct file *file, const char __user * buf,
				size_t count, loff_t * ppos)
{
	uint8_t tmp_buf[128];
	int index = 0;

	if (copy_from_user(tmp_buf, buf, count)) {
		printk("%s -- copy from user failed\n", __FUNCTION__);
		return -1;
	}

	index = tmp_buf[0] - '0';

	if (index >= IMSIC_TEST_IRQ_NUM) {
		printk("invalid index: %d\n", index);
		return count;
	}

	printk("index:%d\n", index);

	printk("#################### write %d to 0x%lx\n",
	       imsic_test.msi[index].data, imsic_test.msi[index].pa);
	writel(imsic_test.msi[index].data, (void *)imsic_test.msi[index].addr);

	return count;
}

static int imsic_test_platform_remove(struct platform_device *pdev)
{
	int i;

	for (i = 0; i < IMSIC_TEST_IRQ_NUM; i++)
		iounmap(imsic_test.msi[i].addr);

	return 0;
}

static const struct file_operations imsic_test_ops = {
	.owner = THIS_MODULE,
	.write = imsic_test_write,
};

static int __init imsic_test_init(void)
{
	struct dentry *d;

	d = debugfs_create_file("imsic_test", S_IRUGO | S_IWUSR, NULL, NULL,
				&imsic_test_ops);
	if (!d) {
		printk("%s -- create debugfs fail\n", __FUNCTION__);
		return -1;
	}

	return 0;
}

late_initcall(imsic_test_init);

static const struct of_device_id imsic_platform_match[] = {
	{.compatible = "imsic,test" },
};

static struct platform_driver imsic_test_platform_driver = {
	.probe = imsic_test_platform_probe,
	.remove = imsic_test_platform_remove,
	.driver = {
		   .name = "imsic_test_plarform",
		   .of_match_table = imsic_platform_match,
		    }
};

module_platform_driver(imsic_test_platform_driver);
MODULE_LICENSE("GPL v2");
