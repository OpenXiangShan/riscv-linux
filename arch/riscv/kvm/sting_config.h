/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RISCV_KVM_STING_CONFIG_H__
#define __RISCV_KVM_STING_CONFIG_H__

#include <linux/compiler.h>
#include <linux/types.h>

#define KVM_RISCV_STING_LOG_NESTED	(1U << 0)
#define KVM_RISCV_STING_LOG_GSTAGE	(1U << 1)
#define KVM_RISCV_STING_LOG_ALL		(KVM_RISCV_STING_LOG_NESTED | \
					 KVM_RISCV_STING_LOG_GSTAGE)

extern unsigned int kvm_riscv_sting_log_mask;
extern bool kvm_riscv_sting_5006b_shutdown;

static inline bool kvm_riscv_sting_log_enabled(unsigned int category)
{
	return READ_ONCE(kvm_riscv_sting_log_mask) & category;
}

#endif
