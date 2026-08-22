/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_GENIRQ_H
#define _LINUX_VIRTIO_GENIRQ_H

#include <linux/bits.h>
#include <linux/stddef.h>
#include <linux/types.h>

#define VIRTIO_GENIRQ_VERSION		1
#define VIRTIO_GENIRQ_QUEUE_SIZE		128
#define VIRTIO_GENIRQ_NUM_QUEUES	1
#define VIRTIO_GENIRQ_CMD_QUEUE		0
#define VIRTIO_GENIRQ_MAX_TARGETS	64
#define VIRTIO_GENIRQ_MAX_OPS		512
#define VIRTIO_GENIRQ_MAX_REPEAT	1000000U
#define VIRTIO_GENIRQ_REQ_MAGIC		0x51524947U

enum virtio_genirq_cmd {
	VIRTIO_GENIRQ_CMD_RUN = 1,
	VIRTIO_GENIRQ_CMD_GET_STATS = 2,
	VIRTIO_GENIRQ_CMD_RESET_STATS = 3,
};

enum virtio_genirq_op_type {
	VIRTIO_GENIRQ_OP_SEND = 1,
	VIRTIO_GENIRQ_OP_SEND_RANGE = 2,
	VIRTIO_GENIRQ_OP_DELAY_NS = 3,
	VIRTIO_GENIRQ_OP_RANDOM = 4,
};

enum virtio_genirq_status {
	VIRTIO_GENIRQ_STATUS_OK = 0,
	VIRTIO_GENIRQ_STATUS_INVALID = 1,
	VIRTIO_GENIRQ_STATUS_UNSUPPORTED = 2,
	VIRTIO_GENIRQ_STATUS_IOERR = 3,
};

#define VIRTIO_GENIRQ_RAW_F_DATA_INC	BIT(0)
#define VIRTIO_GENIRQ_RAW_KICK_SEND	1U

struct virtio_genirq_config {
	__le32 version;
	__le32 max_targets;
	__le32 max_ops;
	__le32 max_repeat;
	__le64 total_sends;
	__le64 total_errors;
	__le32 raw_status;
	__le32 raw_flags;
	__le64 raw_addr;
	__le32 raw_data;
	__le32 raw_count;
	__le32 raw_stride;
	__le32 raw_kick;
} __packed;

struct virtio_genirq_req_hdr {
	__le32 magic;
	__le16 version;
	__le16 opcode;
	__le32 flags;
	__le32 target_count;
	__le32 op_count;
	__le64 seq;
} __packed;

struct virtio_genirq_target {
	__le64 addr;
	__le32 data;
	__le32 flags;
} __packed;

struct virtio_genirq_op {
	__le16 type;
	__le16 target;
	__le32 count;
	__le64 arg0;
	__le64 arg1;
} __packed;

struct virtio_genirq_resp {
	__le32 status;
	__le32 error_op;
	__le64 seq;
	__le64 sends;
	__le64 errors;
} __packed;

#define VIRTIO_GENIRQ_MMIO_CONFIG	0x100
#define VIRTIO_GENIRQ_RAW_OFFSET(_field) \
	(VIRTIO_GENIRQ_MMIO_CONFIG + offsetof(struct virtio_genirq_config, _field))

#endif /* _LINUX_VIRTIO_GENIRQ_H */
