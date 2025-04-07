# SPDX-License-Identifier: GPL-2.0

# kunminghu-v2 has the H externsion, kmh-v1 don't have

dtb-$(CONFIG_SOC_XIANGSHAN) += \
	kmh-v1.dtb \
	nanhu-v2.dtb \
	nanhu-v3.dtb \
	nanhu-v3a.dtb \
	nanhu-v3-1core.dtb \
	nemu-platform.dtb \
	nemu-platform-initramfs.dtb \
	emu.dtb \
	kmh-v2-1core.dtb \
	kmh-v2-2core.dtb \
	kmh-v2-4core.dtb \
	kmh-v2-8core.dtb \
	kmh-v2-16core.dtb \
	kmh-v2-1core-uartlite.dtb \
	kmh-v2-2core-uartlite.dtb \
	kmh-v2-4core-uartlite.dtb \
	kmh-v2-8core-uartlite.dtb \
	kmh-v2-16core-uartlite.dtb \
	nanhu-v5-1core.dtb \
	nanhu-v5-1core-uartlite.dtb

obj-$(CONFIG_BUILTIN_DTB) += $(addsuffix .o, $(dtb-y))
