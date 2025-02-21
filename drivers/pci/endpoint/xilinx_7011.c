// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 Beijing Institute of Open Source Chip (BOSC)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/phy.h>
#include <linux/in.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>


u64 dma_phy_addr;
ulong dma_size = PAGE_SIZE;
volatile u32 *bar0;
static u32 golden_val = 0xdeadbeef;
struct task_struct *loop_task;
volatile void *dma_addr;

static int loopaddr(void *dma_addr)
{
	u32 data = *(u32 *)dma_addr;

	while(1) {
		pr_info("%s %d  data %#X \n", __func__, __LINE__, *(u32 *)dma_addr);
		msleep(1000);
		if (data != golden_val)
			break;
	}

	return 0;
}

static int xilinx7011_init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{

	u32 ret;
	resource_size_t start;


	dma_addr = dma_alloc_coherent(&pdev->dev, dma_size,
		&dma_phy_addr, GFP_KERNEL);

	*(u32 *)dma_addr  = golden_val;
	pr_info("%s %d  phy addr %#llx data %#x \n", __func__, __LINE__, dma_phy_addr, *(u32 *)dma_addr);
	ret = pci_enable_device(pdev);
	dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	pci_set_master(pdev);

	start = pci_resource_start(pdev, 0);

	bar0 = ioremap(start, pci_resource_len(pdev, 0));
	writel(dma_phy_addr, bar0);


	loop_task = kthread_run(loopaddr, (void *)dma_addr, "loop dma addr");

	return 0;
}

static void xilinx7011_remove_one(struct pci_dev *pdev)
{
	kthread_stop(loop_task);
	iounmap(bar0);
	dma_free_coherent(&pdev->dev, dma_size, (void *)dma_addr, dma_phy_addr);
	pci_disable_device(pdev);
}

static const struct pci_device_id xilinx_7011_device[] = {
	{ PCI_DEVICE(0x10ee, 0x7011) },
	{}
};

MODULE_DEVICE_TABLE(pci, xilinx_7011_device);



static struct pci_driver xilinx_7011 = {
	.name		= KBUILD_MODNAME,
	.id_table	= xilinx_7011_device,
	.probe		= xilinx7011_init_one,
	.remove		= xilinx7011_remove_one,
};

module_pci_driver(xilinx_7011);
