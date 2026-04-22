/* SPDX-License-Identifier: GPL-2.0-only */
.section ".data.einj", "aw", @progbits
.align 12

.globl einj_workspace_start
.globl einj_workspace_end

einj_workspace_start:
.incbin "arch/riscv/boot/dts/bosc/einj_workspace.bin"
einj_workspace_end:
