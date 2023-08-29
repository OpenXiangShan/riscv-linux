#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/acpi.h>
#include <linux/irqchip.h>
#include <linux/pci-ecam.h>
#include <linux/pci-acpi.h>

/* Register definitions */
#define XILINX_PCIE_REG_VSEC		0x0000012c
#define XILINX_PCIE_REG_BIR		0x00000130
#define XILINX_PCIE_REG_IDR		0x00000138
#define XILINX_PCIE_REG_IMR		0x0000013c
#define XILINX_PCIE_REG_PSCR		0x00000144
#define XILINX_PCIE_REG_RPSC		0x00000148
#define XILINX_PCIE_REG_MSIBASE1	0x0000014c
#define XILINX_PCIE_REG_MSIBASE2	0x00000150
#define XILINX_PCIE_REG_RPEFR		0x00000154
#define XILINX_PCIE_REG_RPIFR1		0x00000158
#define XILINX_PCIE_REG_RPIFR2		0x0000015c
#define XILINX_PCIE_REG_IDRN            0x00000160
#define XILINX_PCIE_REG_IDRN_MASK       0x00000164
#define XILINX_PCIE_REG_MSI_LOW		0x00000170
#define XILINX_PCIE_REG_MSI_HI		0x00000174
#define XILINX_PCIE_REG_MSI_LOW_MASK	0x00000178
#define XILINX_PCIE_REG_MSI_HI_MASK	0x0000017c

/* Interrupt registers definitions */
#define XILINX_PCIE_INTR_LINK_DOWN	BIT(0)
#define XILINX_PCIE_INTR_HOT_RESET	BIT(3)
#define XILINX_PCIE_INTR_CFG_TIMEOUT	BIT(8)
#define XILINX_PCIE_INTR_CORRECTABLE	BIT(9)
#define XILINX_PCIE_INTR_NONFATAL	BIT(10)
#define XILINX_PCIE_INTR_FATAL		BIT(11)
#define XILINX_PCIE_INTR_INTX		BIT(16)
#define XILINX_PCIE_INTR_MSI		BIT(17)
#define XILINX_PCIE_INTR_SLV_UNSUPP	BIT(20)
#define XILINX_PCIE_INTR_SLV_UNEXP	BIT(21)
#define XILINX_PCIE_INTR_SLV_COMPL	BIT(22)
#define XILINX_PCIE_INTR_SLV_ERRP	BIT(23)
#define XILINX_PCIE_INTR_SLV_CMPABT	BIT(24)
#define XILINX_PCIE_INTR_SLV_ILLBUR	BIT(25)
#define XILINX_PCIE_INTR_MST_DECERR	BIT(26)
#define XILINX_PCIE_INTR_MST_SLVERR	BIT(27)
#define XILINX_PCIE_IMR_ALL_MASK	0x0FF30FE9
#define XILINX_PCIE_IDR_ALL_MASK	0xFFFFFFFF
#define XILINX_PCIE_IDRN_MASK           GENMASK(19, 16)

/* Root Port Error FIFO Read Register definitions */
#define XILINX_PCIE_RPEFR_ERR_VALID	BIT(18)
#define XILINX_PCIE_RPEFR_REQ_ID	GENMASK(15, 0)
#define XILINX_PCIE_RPEFR_ALL_MASK	0xFFFFFFFF

/* Root Port Interrupt FIFO Read Register 1 definitions */
#define XILINX_PCIE_RPIFR1_INTR_VALID	BIT(31)
#define XILINX_PCIE_RPIFR1_MSI_INTR	BIT(30)
#define XILINX_PCIE_RPIFR1_INTR_MASK	GENMASK(28, 27)
#define XILINX_PCIE_RPIFR1_ALL_MASK	0xFFFFFFFF
#define XILINX_PCIE_RPIFR1_INTR_SHIFT	27
#define XILINX_PCIE_IDRN_SHIFT          16
#define XILINX_PCIE_VSEC_REV_MASK	GENMASK(19, 16)
#define XILINX_PCIE_VSEC_REV_SHIFT	16
#define XILINX_PCIE_FIFO_SHIFT		5

/* Bridge Info Register definitions */
#define XILINX_PCIE_BIR_ECAM_SZ_MASK	GENMASK(18, 16)
#define XILINX_PCIE_BIR_ECAM_SZ_SHIFT	16

/* Root Port Interrupt FIFO Read Register 2 definitions */
#define XILINX_PCIE_RPIFR2_MSG_DATA	GENMASK(15, 0)

/* Root Port Status/control Register definitions */
#define XILINX_PCIE_REG_RPSC_BEN	BIT(0)

/* Phy Status/Control Register definitions */
#define XILINX_PCIE_REG_PSCR_LNKUP	BIT(11)

/* ECAM definitions */
#define ECAM_BUS_NUM_SHIFT		20
#define ECAM_DEV_NUM_SHIFT		12

/* Number of MSI IRQs */
#define XILINX_NUM_MSI_IRQS		64
#define INTX_NUM                        4

#define DMA_BRIDGE_BASE_OFF		0xCD8

enum msi_mode {
	MSI_DECD_MODE = 1,
	MSI_FIFO_MODE,
};

enum xdma_config {
	XDMA_ZYNQMP_PL = 1,
	XDMA_VERSAL_PL,
};

#ifdef CONFIG_ACPI
#pragma pack(1)
struct acpi_xdma_msi {
	uint8_t type;
	uint8_t length;
	uint32_t reference;
	uint32_t base_address;
	uint32_t mmio_size;
	uint8_t gsi_misc;
	uint8_t gsi_l;
	uint8_t gsi_h;
};

struct xdma_msi_acpi_info {
	uint32_t base;
	uint32_t size;
	struct fwnode_handle *parent;
	uint8_t interrupt_misc;
	uint8_t interrupt_low;
	uint8_t interrupt_high;
	struct acpi_madt_node *madt_node;
};

#pragma pack()
#endif

struct xdma_msi {
	struct irq_domain *msi_domain;
	unsigned long *bitmap;
	struct irq_domain *dev_domain;
	struct mutex lock;		/* protect bitmap variable */
	unsigned long msi_pages;
	int irq_msi0;
	int irq_msi1;
};

struct xdma_msi_priv {
	void __iomem *regs;
	u8 msi_mode;
	u8 xdma_config;
	int irq_misc;
	struct xdma_msi msi;
};

static inline u32 pcie_xdma_read(struct xdma_msi_priv *priv, u32 reg)
{
	void __iomem *addr = (void __iomem *)((u64)priv->regs + reg);

	return readl(addr);
}

static inline void pcie_xdma_write(struct xdma_msi_priv *priv, u32 val, u32 reg)
{
	void __iomem *addr = (void __iomem *)((u64)priv->regs + reg);

	writel(val, addr);
}

static __init struct fwnode_handle *xdma_acpi_msi_get_fwnode(struct device *dev)
{
	struct pci_bus *bus = to_pci_bus(dev);
	struct pci_host_bridge *host_bridge;
	struct acpi_device *adev;
	struct acpi_handle *handle;
	struct pci_config_window *cfg;

	host_bridge = to_pci_host_bridge(bus->bridge);

	cfg = (struct pci_config_window *)host_bridge->sysdata;
	if (!cfg) {
		pr_err("%s get pci_config_window failed.\n", __FUNCTION__);
		return NULL;
	}

	adev = container_of(cfg->parent, struct acpi_device, dev);
	handle = acpi_device_handle(adev);
	if (!handle) {
		pr_err("%s get pci_config_window failed.\n", __FUNCTION__);
		return NULL;
	}

	return acpi_madt_get_irq_domain(handle, 0);
}

static struct irq_domain *xdma_acpi_msi_get_irq_domain(struct fwnode_handle *fwnode)
{
	return irq_find_matching_fwnode(fwnode, DOMAIN_BUS_PCI_MSI);
}

static void xdma_acpi_pcie_handle_msi_irq(struct xdma_msi_priv *priv,
				       u32 status_reg)
{
	unsigned long status;
	u32 bit;
	u32 virq;
	struct xdma_msi *msi = &priv->msi;
	struct irq_domain *dev_domain;

	if (!priv) {
		pr_err("%s -- invalid xdma_msi_priv.\n",
			__FUNCTION__);
		return;
	}
	dev_domain = msi->dev_domain;

	while ((status = pcie_xdma_read(priv, status_reg)) != 0) {
		for_each_set_bit(bit, &status, 32) {
			pcie_xdma_write(priv, 1 << bit, status_reg);
			if (status_reg == XILINX_PCIE_REG_MSI_HI)
				bit = bit + 32;
			virq = irq_find_mapping(dev_domain, bit);
			if (virq)
				generic_handle_irq(virq);
		}
	}
}

static void xilinx_acpi_pcie_msi_handler_high(struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct xdma_msi_priv *priv = irq_desc_get_handler_data(desc);

	chained_irq_enter(chip, desc);
	xdma_acpi_pcie_handle_msi_irq(priv, XILINX_PCIE_REG_MSI_HI);
	chained_irq_exit(chip, desc);
}

static void xilinx_acpi_pcie_msi_handler_low(struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct xdma_msi_priv *priv = irq_desc_get_handler_data(desc);

	chained_irq_enter(chip, desc);
	xdma_acpi_pcie_handle_msi_irq(priv, XILINX_PCIE_REG_MSI_LOW);
	chained_irq_exit(chip, desc);
}

static void xilinx_pcie_clear_err_interrupts(struct xdma_msi_priv *priv)
{
	unsigned long val = pcie_xdma_read(priv, XILINX_PCIE_REG_RPEFR);

	if (val & XILINX_PCIE_RPEFR_ERR_VALID) {
		pr_info("Requester ID %lu\n",
			val & XILINX_PCIE_RPEFR_REQ_ID);
		pcie_xdma_write(priv, XILINX_PCIE_RPEFR_ALL_MASK,
			   XILINX_PCIE_REG_RPEFR);
	}
}

static void xdma_acpi_pcie_intr_handler(struct irq_desc* desc)
{
	struct xdma_msi_priv *priv = irq_desc_get_handler_data(desc);
	u32 val, status, mask;

	val = pcie_xdma_read(priv, XILINX_PCIE_REG_IDR);
	mask = pcie_xdma_read(priv, XILINX_PCIE_REG_IMR);

	status = val & mask;
	if (!status)
		return;

	if (status & XILINX_PCIE_INTR_LINK_DOWN)
		pr_warn("Link Down\n");

	if (status & XILINX_PCIE_INTR_HOT_RESET)
		pr_info("Hot reset\n");

	if (status & XILINX_PCIE_INTR_CFG_TIMEOUT)
		pr_warn("ECAM access timeout\n");

	if (status & XILINX_PCIE_INTR_CORRECTABLE) {
		pr_warn("Correctable error message\n");
		xilinx_pcie_clear_err_interrupts(priv);
	}

	if (status & XILINX_PCIE_INTR_NONFATAL) {
		pr_warn("Non fatal error message\n");
		xilinx_pcie_clear_err_interrupts(priv);
	}

	if (status & XILINX_PCIE_INTR_FATAL) {
		pr_warn("Fatal error message\n");
		xilinx_pcie_clear_err_interrupts(priv);
	}

	if (status & XILINX_PCIE_INTR_INTX) {
		pr_warn("Do not support intx now...\n");
	}

	if (status & XILINX_PCIE_INTR_SLV_UNSUPP)
		pr_warn("Slave unsupported request\n");

	if (status & XILINX_PCIE_INTR_SLV_UNEXP)
		pr_warn("Slave unexpected completion\n");

	if (status & XILINX_PCIE_INTR_SLV_COMPL)
		pr_warn("Slave completion timeout\n");

	if (status & XILINX_PCIE_INTR_SLV_ERRP)
		pr_warn("Slave Error Poison\n");

	if (status & XILINX_PCIE_INTR_SLV_CMPABT)
		pr_warn("Slave Completer Abort\n");

	if (status & XILINX_PCIE_INTR_SLV_ILLBUR)
		pr_warn("Slave Illegal Burst\n");

	if (status & XILINX_PCIE_INTR_MST_DECERR)
		pr_warn("Master decode error\n");

	if (status & XILINX_PCIE_INTR_MST_SLVERR)
		pr_warn("Master slave error\n");

	/* Clear the Interrupt Decode register */
	pcie_xdma_write(priv, status, XILINX_PCIE_REG_IDR);

	return;
}

static int xdma_acpi_request_msi_irq(struct fwnode_handle *parent,
				int msi0, int msi1, struct xdma_msi_priv* msi_priv)
{
	struct irq_fwspec fwspec;
	struct xdma_msi *msi = &msi_priv->msi;

	fwspec.fwnode = parent;
	fwspec.param[0] = msi0;
	fwspec.param[1] = acpi_dev_get_irq_type(
				ACPI_LEVEL_SENSITIVE, ACPI_ACTIVE_HIGH);
	fwspec.param_count = 2;
	msi->irq_msi0 = irq_create_fwspec_mapping(&fwspec);
	if (msi->irq_msi0 < 0) {
		pr_err("%s -- request msi0 irq fail.\n", __FUNCTION__);
		return -EIO;
	}

	irq_set_chained_handler_and_data(msi->irq_msi0,
					 xilinx_acpi_pcie_msi_handler_low,
					 msi_priv);

	fwspec.fwnode = parent;
	fwspec.param[0] = msi1;
	fwspec.param[1] = acpi_dev_get_irq_type(
				ACPI_LEVEL_SENSITIVE, ACPI_ACTIVE_HIGH);
	fwspec.param_count = 2;
	msi->irq_msi1 = irq_create_fwspec_mapping(&fwspec);
	if (msi->irq_msi1 < 0) {
		pr_err("%s -- request msi0 irq fail.\n", __FUNCTION__);
		return -EIO;
	}

	irq_set_chained_handler_and_data(msi->irq_msi1,
					 xilinx_acpi_pcie_msi_handler_high,
					 msi_priv);
	return 0;
}

static int xdma_acpi_request_misc_irq(struct fwnode_handle *parent,
				int hwirq, struct xdma_msi_priv* msi_priv)
{
	struct irq_fwspec fwspec;

	fwspec.fwnode = parent;
	fwspec.param[0] = hwirq;
	fwspec.param[1] = acpi_dev_get_irq_type(
				ACPI_LEVEL_SENSITIVE, ACPI_ACTIVE_HIGH);
	fwspec.param_count = 2;

	msi_priv->irq_misc = irq_create_fwspec_mapping(&fwspec);
	if (msi_priv->irq_misc < 0) {
		pr_err("%s -- request irq fail\n", __FUNCTION__);
		return -EIO;
	}

	irq_set_chained_handler_and_data(msi_priv->irq_misc,
					 xdma_acpi_pcie_intr_handler,
					 msi_priv);

	return 0;
}

static void xdma_pcie_enable_msi(struct xdma_msi_priv *priv)
{
	struct xdma_msi *msi = &priv->msi;
	phys_addr_t msg_addr;

	msi->msi_pages = __get_free_pages(GFP_KERNEL, 0);
	msg_addr = virt_to_phys((void *)msi->msi_pages);
	pcie_xdma_write(priv, upper_32_bits(msg_addr), XILINX_PCIE_REG_MSIBASE1);
	pcie_xdma_write(priv, lower_32_bits(msg_addr), XILINX_PCIE_REG_MSIBASE2);
}

static struct irq_chip xdma_msi_irq_chip = {
	.name = "xilinx_pcie:msi",
	.irq_enable = pci_msi_unmask_irq,
	.irq_disable = pci_msi_mask_irq,
	.irq_mask = pci_msi_mask_irq,
	.irq_unmask = pci_msi_unmask_irq,
};

static struct msi_domain_info xdma_msi_domain_info = {
	.flags = (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
		MSI_FLAG_MULTI_PCI_MSI),
	.chip = &xdma_msi_irq_chip,
};

static void xdma_compose_msi_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct xdma_msi_priv *priv = irq_data_get_irq_chip_data(data);
	struct xdma_msi *msi = &priv->msi;
	phys_addr_t msi_addr;

	msi_addr = virt_to_phys((void *)msi->msi_pages);
	msg->address_lo = lower_32_bits(msi_addr);
	msg->address_hi = upper_32_bits(msi_addr);
	msg->data = data->hwirq;
}

static int xdma_msi_set_affinity(struct irq_data *irq_data,
				   const struct cpumask *mask, bool force)
{
	return -EINVAL;
}

static struct irq_chip xilinx_irq_chip = {
	.name = "Xdma MSI",
	.irq_compose_msi_msg = xdma_compose_msi_msg,
	.irq_set_affinity = xdma_msi_set_affinity,
};

static int xdma_irq_domain_alloc(struct irq_domain *domain, unsigned int virq,
				   unsigned int nr_irqs, void *args)
{
	struct xdma_msi_priv *priv = domain->host_data;
	struct xdma_msi *msi = &priv->msi;
	int bit;
	int i;

	mutex_lock(&msi->lock);
	bit = bitmap_find_free_region(msi->bitmap, XILINX_NUM_MSI_IRQS,
				      get_count_order(nr_irqs));
	if (bit < 0) {
		mutex_unlock(&msi->lock);
		return -ENOSPC;
	}

	for (i = 0; i < nr_irqs; i++) {
		irq_domain_set_info(domain, virq + i, bit + i, &xilinx_irq_chip,
				    domain->host_data, handle_simple_irq,
				    NULL, NULL);
	}
	mutex_unlock(&msi->lock);

	return 0;
}

static void xdma_irq_domain_free(struct irq_domain *domain, unsigned int virq,
				   unsigned int nr_irqs)
{
	struct irq_data *data = irq_domain_get_irq_data(domain, virq);
	struct xdma_msi_priv *priv = irq_data_get_irq_chip_data(data);
	struct xdma_msi *msi = &priv->msi;

	mutex_lock(&msi->lock);
	bitmap_release_region(msi->bitmap, data->hwirq,
			      get_count_order(nr_irqs));
	mutex_unlock(&msi->lock);
}


static const struct irq_domain_ops dev_msi_domain_ops = {
	.alloc  = xdma_irq_domain_alloc,
	.free   = xdma_irq_domain_free,
};

static int xdma_acpi_pcie_init_msi_irq_domain(struct xdma_msi_priv *priv)
{
	struct fwnode_handle *fwnode;
	struct xdma_msi *msi = &priv->msi;
	int size = BITS_TO_LONGS(XILINX_NUM_MSI_IRQS) * sizeof(long);

	msi->dev_domain = irq_domain_add_linear(NULL, XILINX_NUM_MSI_IRQS,
						&dev_msi_domain_ops, priv);

	fwnode = irq_domain_alloc_named_fwnode("XDMA-MSI");
	if (!fwnode) {
		pr_err("%s -- Unable to alloc xdma msi irq domain fwnode\n",
			__FUNCTION__);
		return -ENOMEM;
	}

	msi->msi_domain = pci_msi_create_irq_domain(fwnode,
						    &xdma_msi_domain_info,
						    msi->dev_domain);
	if (!msi->msi_domain) {
		pr_err("%s -- failed to create msi IRQ domain\n",
			__FUNCTION__);
		irq_domain_remove(msi->dev_domain);
		return -ENOMEM;
	}

	mutex_init(&msi->lock);
	msi->bitmap = kzalloc(size, GFP_KERNEL);
	if (!msi->bitmap)
		return -ENOMEM;

	return 0;
}

static void xdma_acpi_pcie_init(struct xdma_msi_priv *priv)
{
	/* Disable all interrupts */
	pcie_xdma_write(priv, ~XILINX_PCIE_IDR_ALL_MASK,
		   XILINX_PCIE_REG_IMR);

	/* Clear pending interrupts */
	pcie_xdma_write(priv, pcie_xdma_read(priv, XILINX_PCIE_REG_IDR) &
			 XILINX_PCIE_IMR_ALL_MASK,
		   XILINX_PCIE_REG_IDR);

	/* Enable all interrupts */
	pcie_xdma_write(priv, XILINX_PCIE_IMR_ALL_MASK, XILINX_PCIE_REG_IMR);
	pcie_xdma_write(priv, XILINX_PCIE_IDRN_MASK, XILINX_PCIE_REG_IDRN_MASK);
	if (priv->msi_mode == MSI_DECD_MODE) {
		pcie_xdma_write(priv, XILINX_PCIE_IDR_ALL_MASK,
			   XILINX_PCIE_REG_MSI_LOW_MASK);
		pcie_xdma_write(priv, XILINX_PCIE_IDR_ALL_MASK,
			   XILINX_PCIE_REG_MSI_HI_MASK);
	}
	/* Enable the Bridge enable bit */
	pcie_xdma_write(priv, 1,
		   XILINX_PCIE_REG_RPSC);
}

static int xdma_msi_acpi_init_common(struct xdma_msi_acpi_info *info)
{
	int ret = 0;
	struct xdma_msi_priv *priv;
	int mode_val, val;

	priv = (struct xdma_msi_priv *)kzalloc(
			sizeof(struct xdma_msi_priv), GFP_KERNEL
			);
	if (!priv) {
		pr_err("%s -- alloc xdma_msi_priv failed.\n",
			__FUNCTION__);
		return -ENOMEM;
	}

	priv->regs = ioremap(info->base, info->size);
	if (WARN_ON(!priv->regs)) {
		ret = -EIO;
		goto fail_free_priv;
	}

	mb();
	pr_info("priv->regs: 0x%px\n", priv->regs);

	if (info->interrupt_low < 0 ||
	    info->interrupt_high < 0 ||
	    info->interrupt_misc < 0) {
		pr_err("%s -- Invalid hwirq number.\n",
			__FUNCTION__);
		ret = -EINVAL;
		goto fail_ioummap;
	}

	val = pcie_xdma_read(priv, XILINX_PCIE_REG_BIR);
	val = (val >> XILINX_PCIE_FIFO_SHIFT) & MSI_DECD_MODE;
	mode_val = pcie_xdma_read(priv, XILINX_PCIE_REG_VSEC) &
			XILINX_PCIE_VSEC_REV_MASK;
	mode_val = mode_val >> XILINX_PCIE_VSEC_REV_SHIFT;
	if (mode_val && !val) {
		priv->msi_mode = MSI_DECD_MODE;
		pr_info("Using MSI Decode mode\n");
	} else {
		priv->msi_mode = MSI_FIFO_MODE;
		pr_info("Using MSI FIFO mode\n");
	}

	if (priv->msi_mode == MSI_DECD_MODE) {
		ret = xdma_acpi_request_misc_irq(info->parent,
					         info->interrupt_misc,
					         priv);
		if (ret)
			goto fail_free_priv;
		
		ret = xdma_acpi_request_msi_irq(info->parent,
					        info->interrupt_low,
					        info->interrupt_high,
					        priv);
		if(ret)
			goto fail_free_priv;
	}
	else {
		pr_err("%s -- Do not support MSI_FIFO_MODE now.\n",
			__FUNCTION__);
		ret = -EIO;
		goto fail_free_priv;
	}

	ret = xdma_acpi_pcie_init_msi_irq_domain(priv);
	if (ret)
		goto fail_free_priv;

	acpi_madt_set_fwnode(
		acpi_get_table_phy(info->madt_node, sizeof(*(info->madt_node))),
		priv->msi.msi_domain->fwnode
		);

	pci_msi_register_fwnode_provider(&xdma_acpi_msi_get_fwnode);

	return 0;
fail_free_priv:
	kfree(priv);
fail_ioummap:
	iounmap(priv->regs);

	return ret;
}

static int xdma_pcie_init(struct pci_config_window *cfg)
{
	struct acpi_device *adev;
	struct acpi_handle *handle;
	struct fwnode_handle *fwnode;
	struct irq_domain *domain;
	struct xdma_msi_priv *priv;

	adev = container_of(cfg->parent, struct acpi_device, dev);
	handle = acpi_device_handle(adev);
	if (!handle)
		return -EIO;

	fwnode = acpi_madt_get_irq_domain(handle, 0);
	if (!fwnode) {
		pr_err("%s -- get fwnode handle failed.\n",
			__FUNCTION__);
		return -EIO;
	}

	domain = xdma_acpi_msi_get_irq_domain(fwnode);
	if (!domain) {
		pr_err("%s -- get msi irq domain failed.\n",
			__FUNCTION__);
		return -EIO;
	}

	priv = domain->parent->host_data;
	if (!priv) {
		pr_err("%s -- get msi priv failed.\n",
		__FUNCTION__);
		return -EIO;
	}

	xdma_pcie_enable_msi(priv);

	xdma_acpi_pcie_init(priv);

	return 0;
}

#ifdef CONFIG_ACPI

const struct pci_ecam_ops xdma_pcie_ops = {
	.init    = xdma_pcie_init,
	.pci_ops = {
		.map_bus = pci_ecam_map_bus,
		.read    = pci_generic_config_read,
		.write   = pci_generic_config_write,
	}
};

static int __init xdma_msi_acpi_init(union acpi_subtable_headers *header,
				       const unsigned long end)
{
	struct acpi_xdma_msi *msi = (struct acpi_xdma_msi *)header;
	struct acpi_madt_node *node = (struct acpi_madt_node *)header;
	struct xdma_msi_acpi_info info;

	info.base = msi->base_address;
	info.size = msi->mmio_size;
	if (!info.base || info.size <= 0) {
		pr_err("%s -- Invalid mmio info\n",
			__FUNCTION__);
		return -EINVAL;
	}

	info.madt_node = node;
	info.parent = acpi_madt_get_parent(info.madt_node);
	info.interrupt_low = msi->gsi_l;
	info.interrupt_high = msi->gsi_h;
	info.interrupt_misc = msi->gsi_misc;

	pr_info("interrupt_misc:%d interrupt_low:%d interrupt_high:%d base:0x%x size:0x%x parent:0x%llx",
		info.interrupt_misc, info.interrupt_low,
		info.interrupt_high, info.base, info.size,
		(uint64_t)info.parent);

	return xdma_msi_acpi_init_common(&info);
}

IRQCHIP_ACPI_DECLARE(xdma_msi_irq, ACPI_MADT_TYPE_XDMA_MSI, NULL,
		     1, xdma_msi_acpi_init);

#endif
