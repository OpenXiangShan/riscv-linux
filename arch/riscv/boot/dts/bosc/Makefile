# SPDX-License-Identifier: GPL-2.0

# kunminghu-v2 has the H externsion, kmh-v1 don't have

dtb-$(CONFIG_SOC_XIANGSHAN) += \
	kmh-bosc-soc-1die16c.dtb \
	kmh-bosc-soc-1die1c.dtb \
	kmh-v2-1core.dtb \
	kmh-v2-2core.dtb \
	kmh-v2-2core_h64.dtb \
	kmh-v2-2core_h64_256.dtb \
	kmh-v2-4core.dtb \
	kmh-v2-8core.dtb \
	kmh-v2-16core.dtb \
	kmh-v2-1core-uartlite.dtb \
	kmh-v2-2core-uartlite.dtb \
	kmh-v2-4core-uartlite.dtb \
	kmh-v2-8core-uartlite.dtb \
	kmh-v2-16core-uartlite.dtb \

obj-$(CONFIG_BUILTIN_DTB) += $(addsuffix .o, $(dtb-y))
