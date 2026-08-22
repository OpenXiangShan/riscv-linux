/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_RISCV_GENIRQ_H
#define __KVM_RISCV_GENIRQ_H

#include <linux/kvm_types.h>
#include <linux/mutex.h>
#include <kvm/iodev.h>

struct kvm_genirq_vq {
	u32 num;
	u32 align;
	u32 pfn;
	u16 last_avail_idx;
	u16 used_idx;
};

struct kvm_genirq {
	gpa_t addr;
	unsigned long size;
	unsigned int irq;
	phys_addr_t backing_addr;
	unsigned long backing_size;
	void __iomem *backing_base;
	struct kvm_io_device iodev;
	struct mutex lock;
	bool initialized;

	u32 device_features_sel;
	u32 driver_features_sel;
	u32 guest_page_size;
	u32 queue_sel;
	u32 interrupt_status;
	u32 status;
	struct kvm_genirq_vq vq;

	u64 total_sends;
	u64 total_errors;
	u32 raw_status;
	u32 raw_flags;
	u64 raw_addr;
	u32 raw_data;
	u32 raw_count;
	u32 raw_stride;
};

int kvm_riscv_genirq_init(void);

#endif /* __KVM_RISCV_GENIRQ_H */
