#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/kvm_host.h>
#include <linux/kernel.h>
#include <linux/of_platform.h>
#include <linux/list.h>
#include <linux/bitfield.h>
#include <linux/pfn.h>
#include <asm/insn-def.h>
#include <kvm/iodev.h>
#include <linux/my_debug_print.h>

static int print_prefix = 1;

static int my_debug_print_mmio_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			  gpa_t addr, int len, void *val)
{
	return 0;
}

static int my_debug_print_mmio_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			   gpa_t addr, int len, const void *val)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_debug_print *debug_print = &kvm->arch.debug_print;
	int offset = addr - debug_print->addr;

	if (offset == 0) {
		if (print_prefix)
			my_debug_print("[This vm debug print] ");

		my_debug_print("%c", *(char *)val);

		if (*(char *)val == '\n')
			print_prefix = 1;
		else
			print_prefix = 0;
	}

	return 0;
}

static struct kvm_io_device_ops my_debug_print_iodoev_ops = {
	.read = my_debug_print_mmio_read,
	.write = my_debug_print_mmio_write,
};

static int my_debug_print_create(struct kvm_device *dev, u32 type)
{
	return 0;
}

static void my_debug_print_destroy(struct kvm_device *dev)
{

}

static int my_debug_print_addr(struct kvm *kvm, unsigned long *addr, bool write)
{
	struct kvm_debug_print *debug_print = &kvm->arch.debug_print;

	if (write)
		debug_print->addr = *addr;
	else
		*addr = debug_print->addr;

	return 0;
}

static int my_debug_print_addr_size(struct kvm *kvm, unsigned long *size, bool write)
{
	struct kvm_debug_print *debug_print = &kvm->arch.debug_print;

	if (write)
		debug_print->size = *size;
	else
		*size = debug_print->size;

	return 0;
}

static int my_debug_print_init(struct kvm_device *dev)
{
	struct kvm *kvm = dev->kvm;
	struct kvm_debug_print *debug_print = &kvm->arch.debug_print;
	int ret;

	kvm_iodevice_init(&debug_print->iodev, &my_debug_print_iodoev_ops);

	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS,
				      debug_print->addr,
				      debug_print->size,
				      &debug_print->iodev);
	mutex_unlock(&kvm->slots_lock);

	return 0;
}

static int my_debug_print_set_attr(struct kvm_device *dev, struct kvm_device_attr *attr)
{
	unsigned long type = (unsigned long)attr->attr;
	void __user *uaddr = (void __user *)(long)attr->addr;

	switch (attr->group) {
	case KVM_DEV_RISCV_DEBUG_PRINT_GRP_ADDR:
		unsigned long addr;

		if (copy_from_user(&addr, uaddr, sizeof(addr)))
			return -EFAULT;

		mutex_lock(&dev->kvm->lock);
		my_debug_print_addr(dev->kvm, &addr, true);
		mutex_unlock(&dev->kvm->lock);

		break;

	case KVM_DEV_RISCV_DEBUG_PRINT_GRP_ADDR_SIZE:
		unsigned long size;

		if (copy_from_user(&size, uaddr, sizeof(size)))
			return -EFAULT;

		mutex_lock(&dev->kvm->lock);
		my_debug_print_addr_size(dev->kvm, &size, true);
		mutex_unlock(&dev->kvm->lock);

		break;

	case KVM_DEV_RISCV_DEBUG_PRINT_GRP_CTRL:
		switch (type) {
		case KVM_DEV_RISCV_DEBUG_PRINT_CTRL_INIT:
			my_debug_print_init(dev);
			break;
		}
		break;
	}

	return 0;
}

static int my_debug_print_get_attr(struct kvm_device *dev, struct kvm_device_attr *attr)
{
	return 0;
}

struct kvm_device_ops kvm_my_debug_print_device_ops = {
	.name = "kvm-my-debug-print",
	.create = my_debug_print_create,
	.destroy = my_debug_print_destroy,
	.set_attr = my_debug_print_set_attr,
	.get_attr = my_debug_print_get_attr,
};

int kvm_my_print_debug_init(void)
{
	int rc;

	rc = kvm_register_device_ops(&kvm_my_debug_print_device_ops,
				     KVM_DEV_TYPE_MY_DEBUG_PRINT);
	if (rc) {
		return rc;
	}

	return 0;
}
