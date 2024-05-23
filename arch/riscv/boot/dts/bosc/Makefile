# SPDX-License-Identifier: GPL-2.0

dtb-$(CONFIG_SOC_XIANGSHAN) += \
	kmh-v1.dtb \
	nanhu-v2.dtb \
	nanhu-v3.dtb \
	nanhu-v3-1core.dtb \
	nemu-platform.dtb \
	nemu-platform-initramfs.dtb \
	emu.dtb

obj-$(CONFIG_BUILTIN_DTB) += $(addsuffix .o, $(dtb-y))
