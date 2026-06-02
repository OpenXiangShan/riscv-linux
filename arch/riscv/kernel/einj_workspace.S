/* SPDX-License-Identifier: GPL-2.0-only */
.section ".data.einj", "aw", @progbits
.align 12

.globl einj_workspace_start
.globl einj_workspace_end

#ifndef EINJ_WORKSPACE_BIN
#define EINJ_WORKSPACE_BIN "arch/riscv/boot/dts/bosc/einj_workspace.bin"
#endif

einj_workspace_start:
.incbin EINJ_WORKSPACE_BIN
einj_workspace_end:
