// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 RISC-V PLIC Test Driver
 *
 * This driver demonstrates how to request and handle PLIC interrupts based on DTS configuration.
 */
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/irqchip/chained_irq.h>

#define PLIC_TEST_MAX_PORTS 256
#define DRIVER_NAME "sifive-plic-test"

/* 存储已申请的中断号和相关信息 */
struct registered_irqs{
	struct device *dev;
	int virq[PLIC_TEST_MAX_PORTS];
	int hwirq[PLIC_TEST_MAX_PORTS];
	int hwirq_com[PLIC_TEST_MAX_PORTS];
	int trigger_type;
} ;

/**
 * plic_test_irq_handler - irq handler for 1~256
 * @irq: sw irq
 * @dev_id: void resource
 */
static irqreturn_t plic_test_irq_handler(int irq, void *dev_id)
{
	struct registered_irqs *port = dev_id;

	if (!port->hwirq_com[irq]) {
		pr_info("!!!!! Received interrupt hwirq %d\n", port->hwirq[irq]);
		port->hwirq_com[irq] = 1;
	}

	return IRQ_HANDLED;
}


extern struct irq_desc *irq_to_desc(unsigned int irq);

/**
 * plic_test_probe - probed by platform. matched using compatible
 * @pdev: platform device
 */
static int plic_test_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct registered_irqs *port;
	struct pci_host_bridge *bridge;
	struct device_node *np = pdev->dev.of_node;
	int ret = 0, num_irqs, i;
	struct irq_desc *irq_desc;
	char index_name[20] = "", sys_name[32] = "";
	int err;


	err = of_property_count_strings(np, "interrupt-names");
	pr_info("!!! Got %d interrupt-names\n", err);

	bridge = devm_pci_alloc_host_bridge(dev, sizeof(*port));
	if (!bridge)
		return -ENODEV;
	port = pci_host_bridge_priv(bridge);
	port->dev = dev;

	num_irqs = of_property_count_u32_elems(np, "interrupts");
	if (num_irqs > PLIC_TEST_MAX_PORTS) {
		dev_err(dev, "Too many interrupts defined %d\n", num_irqs);
		return -EINVAL;
	}

	for (i = 1; i <= num_irqs; i++ ) {
		sprintf(index_name, "%d", i);
		if (i == 40)
			continue;
		memset(sys_name, 0, sizeof(sys_name));
		sprintf(sys_name, "plic_%d", i);
		port->virq[i] = platform_get_irq_byname(pdev, index_name);
		err = devm_request_irq(dev, port->virq[i],
						plic_test_irq_handler,
						IRQF_SHARED | IRQF_NO_THREAD,
						sys_name, port);
		if (err) {
			dev_err(dev, "unable to request plic IRQ line %d\n",
				port->virq[i]);
			return err;
		}
		enable_irq(port->virq[i]);

		irq_desc = irq_to_desc(port->virq[i]);
		port->hwirq[port->virq[i]] = irq_desc->irq_data.hwirq;
		pr_info("Registered interrupt %d: virq=%d hwirq %d\n", i, port->virq[i], port->hwirq[port->virq[i]]);
	}

	return ret;
}

/**
 * plic_test_remove
 * @pdev: platform device
 *
 */
static int plic_test_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id plic_test_of_match[] = {
	{ .compatible = "sifive,plic-test" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, plic_test_of_match);

static struct platform_driver plic_test_driver = {
    .probe = plic_test_probe,
    .remove = plic_test_remove,
    .driver = {
        .name = DRIVER_NAME,
        .of_match_table = plic_test_of_match,
    },
};

module_platform_driver(plic_test_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("SIFIVE PLIC Test Driver");
MODULE_AUTHOR("BOSC Developer");
MODULE_ALIAS("platform:" DRIVER_NAME);
