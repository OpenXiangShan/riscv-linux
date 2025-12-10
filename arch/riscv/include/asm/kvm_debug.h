#ifndef __KVM_DEBUG_PRINT_H__
#define __KVM_DEBUG_PRINT_H__

#include <linux/kvm_types.h>
#include <kvm/iodev.h>
#include <asm/csr.h>

struct kvm_debug_print {
	gpa_t addr;
	unsigned long size;
	struct kvm_io_device iodev;
};

int kvm_my_print_debug_init(void);

#endif
