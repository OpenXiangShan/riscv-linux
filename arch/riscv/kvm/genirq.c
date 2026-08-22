// SPDX-License-Identifier: GPL-2.0
#include <linux/align.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/limits.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/virtio_genirq.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_ring.h>
#include <uapi/linux/virtio_mmio.h>
#include <asm/kvm_aia.h>

#define KVM_GENIRQ_VENDOR_ID		0x52535658U /* XVSR */
#define KVM_GENIRQ_MAGIC_VALUE		0x74726976U /* virt */
#define KVM_GENIRQ_MAX_REQ_LEN \
	(sizeof(struct virtio_genirq_req_hdr) + \
	 VIRTIO_GENIRQ_MAX_TARGETS * sizeof(struct virtio_genirq_target) + \
	 VIRTIO_GENIRQ_MAX_OPS * sizeof(struct virtio_genirq_op))

struct kvm_genirq_iov {
	gpa_t addr;
	u32 len;
	bool write;
};

struct kvm_genirq_desc {
	__le64 addr;
	__le32 len;
	__le16 flags;
	__le16 next;
} __packed;

struct kvm_genirq_used_elem {
	__le32 id;
	__le32 len;
} __packed;

struct kvm_genirq_chain {
	struct kvm_genirq_iov riov[VIRTIO_GENIRQ_QUEUE_SIZE];
	struct kvm_genirq_iov wiov[VIRTIO_GENIRQ_QUEUE_SIZE];
};

static DEFINE_MUTEX(kvm_genirq_backing_lock);

static gpa_t kvm_genirq_vring_base(struct kvm_genirq *g)
{
	return (gpa_t)g->vq.pfn * (g->guest_page_size ?: PAGE_SIZE);
}

static gpa_t kvm_genirq_vring_avail(struct kvm_genirq *g)
{
	return kvm_genirq_vring_base(g) +
	       g->vq.num * sizeof(struct kvm_genirq_desc);
}

static gpa_t kvm_genirq_vring_used(struct kvm_genirq *g)
{
	gpa_t avail = kvm_genirq_vring_avail(g);
	u32 align = g->vq.align ?: PAGE_SIZE;

	return ALIGN(avail + sizeof(__le16) * (3 + g->vq.num), align);
}

static u32 kvm_genirq_lcg_next(u32 *seed)
{
	*seed = *seed * 1103515245U + 12345U;
	return *seed;
}

static void kvm_genirq_refresh_config(struct kvm_genirq *g,
					      struct virtio_genirq_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->version = cpu_to_le32(VIRTIO_GENIRQ_VERSION);
	cfg->max_targets = cpu_to_le32(VIRTIO_GENIRQ_MAX_TARGETS);
	cfg->max_ops = cpu_to_le32(VIRTIO_GENIRQ_MAX_OPS);
	cfg->max_repeat = cpu_to_le32(VIRTIO_GENIRQ_MAX_REPEAT);
	cfg->total_sends = cpu_to_le64(g->total_sends);
	cfg->total_errors = cpu_to_le64(g->total_errors);
	cfg->raw_status = cpu_to_le32(g->raw_status);
	cfg->raw_flags = cpu_to_le32(g->raw_flags);
	cfg->raw_addr = cpu_to_le64(g->raw_addr);
	cfg->raw_data = cpu_to_le32(g->raw_data);
	cfg->raw_count = cpu_to_le32(g->raw_count);
	cfg->raw_stride = cpu_to_le32(g->raw_stride);
}

static int kvm_genirq_backing_send(struct kvm_genirq *g, phys_addr_t addr,
					   u32 data, u32 count, u32 stride,
					   u32 flags)
{
	u32 status;

	if (!g->backing_base)
		return -ENODEV;
	if (!count)
		count = 1;
	if (count > VIRTIO_GENIRQ_MAX_REPEAT)
		return -EINVAL;

	mutex_lock(&kvm_genirq_backing_lock);
	writel((u32)addr, g->backing_base +
	       VIRTIO_GENIRQ_RAW_OFFSET(raw_addr));
	writel((u32)(addr >> 32), g->backing_base +
	       VIRTIO_GENIRQ_RAW_OFFSET(raw_addr) + 4);
	writel(data, g->backing_base + VIRTIO_GENIRQ_RAW_OFFSET(raw_data));
	writel(count, g->backing_base + VIRTIO_GENIRQ_RAW_OFFSET(raw_count));
	writel(stride, g->backing_base + VIRTIO_GENIRQ_RAW_OFFSET(raw_stride));
	writel(flags, g->backing_base + VIRTIO_GENIRQ_RAW_OFFSET(raw_flags));
	writel(VIRTIO_GENIRQ_RAW_KICK_SEND,
	       g->backing_base + VIRTIO_GENIRQ_RAW_OFFSET(raw_kick));
	status = readl(g->backing_base + VIRTIO_GENIRQ_RAW_OFFSET(raw_status));
	mutex_unlock(&kvm_genirq_backing_lock);

	g->raw_status = status;
	if (status != VIRTIO_GENIRQ_STATUS_OK) {
		g->total_errors++;
		return -EIO;
	}

	g->total_sends += count;
	return 0;
}

static int kvm_genirq_send_msi(struct kvm *kvm, struct kvm_genirq *g,
				       u64 addr, u32 data, u32 count, u32 stride,
				       u32 flags)
{
	phys_addr_t hpa;
	int ret;

	ret = kvm_riscv_aia_imsic_translate_vsfile(kvm, addr, &hpa);
	if (ret) {
		g->total_errors++;
		g->raw_status = VIRTIO_GENIRQ_STATUS_IOERR;
		return ret;
	}

	return kvm_genirq_backing_send(g, hpa, data, count, stride, flags);
}

static u32 kvm_genirq_send_target(struct kvm *kvm, struct kvm_genirq *g,
					  const struct virtio_genirq_target *target,
					  u32 repeat)
{
	u64 addr = le64_to_cpu(target->addr);
	u32 data = le32_to_cpu(target->data);

	if (!repeat)
		repeat = 1;
	if (repeat > VIRTIO_GENIRQ_MAX_REPEAT)
		return VIRTIO_GENIRQ_STATUS_INVALID;

	return kvm_genirq_send_msi(kvm, g, addr, data, repeat, 0, 0) ?
	       VIRTIO_GENIRQ_STATUS_IOERR : VIRTIO_GENIRQ_STATUS_OK;
}

static u32 kvm_genirq_run_ops(struct kvm *kvm, struct kvm_genirq *g,
				      const struct virtio_genirq_target *targets,
				      u32 target_count,
				      const struct virtio_genirq_op *ops,
				      u32 op_count, u32 *error_op)
{
	u32 i, j;

	for (i = 0; i < op_count; i++) {
		const struct virtio_genirq_op *op = &ops[i];
		u16 type = le16_to_cpu(op->type);
		u16 target = le16_to_cpu(op->target);
		u32 count = le32_to_cpu(op->count);

		switch (type) {
		case VIRTIO_GENIRQ_OP_SEND:
			if (target >= target_count)
				goto invalid;
			if (kvm_genirq_send_target(kvm, g, &targets[target], count) !=
			    VIRTIO_GENIRQ_STATUS_OK)
				goto ioerr;
			break;
		case VIRTIO_GENIRQ_OP_SEND_RANGE:
		{
			u32 stride = le64_to_cpu(op->arg1) ? le64_to_cpu(op->arg1) : 1;
			u32 repeat = le64_to_cpu(op->arg0) ? le64_to_cpu(op->arg0) : 1;

			for (j = 0; j < count; j++) {
				u64 idx = target + (u64)j * stride;

				if (idx >= target_count)
					goto invalid;
				if (kvm_genirq_send_target(kvm, g, &targets[idx], repeat) !=
				    VIRTIO_GENIRQ_STATUS_OK)
					goto ioerr;
			}
			break;
		}
		case VIRTIO_GENIRQ_OP_DELAY_NS:
			break;
		case VIRTIO_GENIRQ_OP_RANDOM:
		{
			u32 seed = le64_to_cpu(op->arg0) ? le64_to_cpu(op->arg0) : 1;
			u32 nr = count ?: 1;

			if (!target_count)
				goto invalid;
			for (j = 0; j < nr; j++) {
				u32 idx = kvm_genirq_lcg_next(&seed) % target_count;

				if (kvm_genirq_send_target(kvm, g, &targets[idx], 1) !=
				    VIRTIO_GENIRQ_STATUS_OK)
					goto ioerr;
			}
			break;
		}
		default:
			*error_op = i;
			return VIRTIO_GENIRQ_STATUS_UNSUPPORTED;
		}
	}

	return VIRTIO_GENIRQ_STATUS_OK;

invalid:
	*error_op = i;
	return VIRTIO_GENIRQ_STATUS_INVALID;
ioerr:
	*error_op = i;
	return VIRTIO_GENIRQ_STATUS_IOERR;
}

static u32 kvm_genirq_handle_request(struct kvm *kvm, struct kvm_genirq *g,
				     void *req, u32 req_len,
				     struct virtio_genirq_resp *resp)
{
	struct virtio_genirq_req_hdr hdr;
	struct virtio_genirq_target *targets;
	struct virtio_genirq_op *ops;
	size_t min_len;
	u32 target_count, op_count, status, error_op = 0;
	u16 opcode;

	memset(resp, 0, sizeof(*resp));
	resp->status = cpu_to_le32(VIRTIO_GENIRQ_STATUS_INVALID);
	resp->error_op = cpu_to_le32(UINT_MAX);

	if (req_len < sizeof(hdr))
		goto out;

	memcpy(&hdr, req, sizeof(hdr));
	resp->seq = hdr.seq;
	if (le32_to_cpu(hdr.magic) != VIRTIO_GENIRQ_REQ_MAGIC ||
	    le16_to_cpu(hdr.version) != VIRTIO_GENIRQ_VERSION)
		goto out;

	target_count = le32_to_cpu(hdr.target_count);
	op_count = le32_to_cpu(hdr.op_count);
	if (target_count > VIRTIO_GENIRQ_MAX_TARGETS ||
	    op_count > VIRTIO_GENIRQ_MAX_OPS)
		goto out;

	min_len = sizeof(hdr) + target_count * sizeof(*targets) +
		  op_count * sizeof(*ops);
	if (req_len < min_len)
		goto out;

	targets = (struct virtio_genirq_target *)((u8 *)req + sizeof(hdr));
	ops = (struct virtio_genirq_op *)((u8 *)targets +
		 target_count * sizeof(*targets));
	opcode = le16_to_cpu(hdr.opcode);

	switch (opcode) {
	case VIRTIO_GENIRQ_CMD_RUN:
		if (!target_count)
			break;
		if (!op_count) {
			struct virtio_genirq_op op = {
				.type = cpu_to_le16(VIRTIO_GENIRQ_OP_SEND_RANGE),
				.target = 0,
				.count = cpu_to_le32(target_count),
				.arg0 = cpu_to_le64(1),
				.arg1 = cpu_to_le64(1),
			};

			status = kvm_genirq_run_ops(kvm, g, targets, target_count,
							 &op, 1, &error_op);
		} else {
			status = kvm_genirq_run_ops(kvm, g, targets, target_count,
							 ops, op_count, &error_op);
		}
		resp->status = cpu_to_le32(status);
		resp->error_op = cpu_to_le32(error_op);
		break;
	case VIRTIO_GENIRQ_CMD_GET_STATS:
		resp->status = cpu_to_le32(VIRTIO_GENIRQ_STATUS_OK);
		break;
	case VIRTIO_GENIRQ_CMD_RESET_STATS:
		g->total_sends = 0;
		g->total_errors = 0;
		resp->status = cpu_to_le32(VIRTIO_GENIRQ_STATUS_OK);
		break;
	default:
		resp->status = cpu_to_le32(VIRTIO_GENIRQ_STATUS_UNSUPPORTED);
		break;
	}

out:
	resp->sends = cpu_to_le64(g->total_sends);
	resp->errors = cpu_to_le64(g->total_errors);
	return le32_to_cpu(resp->status);
}

static int kvm_genirq_read_chain(struct kvm *kvm, struct kvm_genirq *g,
				 u16 head, struct kvm_genirq_iov *riov,
				 u32 *nr_riov, struct kvm_genirq_iov *wiov,
				 u32 *nr_wiov, u32 *read_len)
{
	gpa_t desc_base = kvm_genirq_vring_base(g);
	u16 idx = head;
	u32 chain;

	*nr_riov = 0;
	*nr_wiov = 0;
	*read_len = 0;

	for (chain = 0; chain < g->vq.num; chain++) {
		struct kvm_genirq_desc desc;
		struct kvm_genirq_iov *iov;
		u16 flags;

		if (idx >= g->vq.num)
			return -EINVAL;
		if (kvm_read_guest(kvm, desc_base + idx * sizeof(desc),
				   &desc, sizeof(desc)))
			return -EFAULT;

		flags = le16_to_cpu(desc.flags);
		if (flags & VRING_DESC_F_INDIRECT)
			return -EOPNOTSUPP;

		if (flags & VRING_DESC_F_WRITE) {
			if (*nr_wiov >= VIRTIO_GENIRQ_QUEUE_SIZE)
				return -EINVAL;
			iov = &wiov[(*nr_wiov)++];
		} else {
			if (*nr_riov >= VIRTIO_GENIRQ_QUEUE_SIZE)
				return -EINVAL;
			iov = &riov[(*nr_riov)++];
			if (check_add_overflow(*read_len, le32_to_cpu(desc.len),
					       read_len))
				return -EINVAL;
			if (*read_len > KVM_GENIRQ_MAX_REQ_LEN)
				return -EINVAL;
		}

		iov->addr = le64_to_cpu(desc.addr);
		iov->len = le32_to_cpu(desc.len);
		iov->write = !!(flags & VRING_DESC_F_WRITE);

		if (!(flags & VRING_DESC_F_NEXT))
			return 0;
		idx = le16_to_cpu(desc.next);
	}

	return -EINVAL;
}

static int kvm_genirq_copy_from_iov(struct kvm *kvm,
				    const struct kvm_genirq_iov *iov, u32 nr_iov,
				    void *buf, u32 len)
{
	u32 i, off = 0;

	for (i = 0; i < nr_iov; i++) {
		if (off + iov[i].len > len)
			return -EINVAL;
		if (kvm_read_guest(kvm, iov[i].addr, (u8 *)buf + off,
				   iov[i].len))
			return -EFAULT;
		off += iov[i].len;
	}

	return 0;
}

static u32 kvm_genirq_copy_to_iov(struct kvm *kvm,
				  const struct kvm_genirq_iov *iov, u32 nr_iov,
				  const void *buf, u32 len)
{
	u32 i, off = 0;

	for (i = 0; i < nr_iov && off < len; i++) {
		u32 todo = min(iov[i].len, len - off);

		if (kvm_write_guest(kvm, iov[i].addr, (const u8 *)buf + off, todo))
			break;
		off += todo;
	}

	return off;
}

static int kvm_genirq_add_used(struct kvm *kvm, struct kvm_genirq *g,
				 u16 head, u32 len)
{
	gpa_t used = kvm_genirq_vring_used(g);
	struct kvm_genirq_used_elem elem = {
		.id = cpu_to_le32(head),
		.len = cpu_to_le32(len),
	};
	__le16 used_idx;

	if (kvm_write_guest(kvm, used + sizeof(__le16) * 2 +
			    (g->vq.used_idx % g->vq.num) * sizeof(elem),
			    &elem, sizeof(elem)))
		return -EFAULT;

	g->vq.used_idx++;
	used_idx = cpu_to_le16(g->vq.used_idx);
	if (kvm_write_guest(kvm, used + sizeof(__le16), &used_idx,
			    sizeof(used_idx)))
		return -EFAULT;

	return 0;
}

static void kvm_genirq_pulse_irq(struct kvm *kvm, struct kvm_genirq *g)
{
	g->interrupt_status |= VIRTIO_MMIO_INT_VRING;
	kvm_riscv_aia_inject_irq(kvm, g->irq, true);
	kvm_riscv_aia_inject_irq(kvm, g->irq, false);
}

static int kvm_genirq_process_one(struct kvm *kvm, struct kvm_genirq *g,
				  u16 head)
{
	struct kvm_genirq_chain *chain;
	struct virtio_genirq_resp resp;
	u32 nr_riov, nr_wiov, req_len, resp_len;
	void *req;
	int ret;

	chain = kzalloc(sizeof(*chain), GFP_KERNEL);
	if (!chain)
		return -ENOMEM;

	ret = kvm_genirq_read_chain(kvm, g, head, chain->riov, &nr_riov,
					  chain->wiov, &nr_wiov, &req_len);
	if (ret)
		goto out_free_chain;

	req = kzalloc(req_len ?: 1, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_free_chain;
	}

	ret = kvm_genirq_copy_from_iov(kvm, chain->riov, nr_riov, req, req_len);
	if (ret) {
		memset(&resp, 0, sizeof(resp));
		resp.status = cpu_to_le32(VIRTIO_GENIRQ_STATUS_IOERR);
		resp.error_op = cpu_to_le32(UINT_MAX);
	} else {
		kvm_genirq_handle_request(kvm, g, req, req_len, &resp);
	}

	resp_len = kvm_genirq_copy_to_iov(kvm, chain->wiov, nr_wiov, &resp,
					       sizeof(resp));
	kfree(req);
	ret = kvm_genirq_add_used(kvm, g, head, resp_len);

out_free_chain:
	kfree(chain);
	return ret;
}

static int kvm_genirq_process_vq(struct kvm *kvm, struct kvm_genirq *g)
{
	gpa_t avail = kvm_genirq_vring_avail(g);
	__le16 le_avail_idx;
	u16 avail_idx;
	bool used = false;

	if (!g->vq.pfn || !g->vq.num)
		return -EINVAL;

	if (kvm_read_guest(kvm, avail + sizeof(__le16), &le_avail_idx,
			   sizeof(le_avail_idx)))
		return -EFAULT;
	avail_idx = le16_to_cpu(le_avail_idx);

	while (g->vq.last_avail_idx != avail_idx) {
		__le16 le_head;
		u16 head;
		int ret;

		if (kvm_read_guest(kvm, avail + sizeof(__le16) * 2 +
				   (g->vq.last_avail_idx % g->vq.num) * sizeof(__le16),
				   &le_head, sizeof(le_head)))
			return -EFAULT;

		head = le16_to_cpu(le_head);
		ret = kvm_genirq_process_one(kvm, g, head);
		if (ret)
			return ret;
		g->vq.last_avail_idx++;
		used = true;
	}

	if (used)
		kvm_genirq_pulse_irq(kvm, g);

	return 0;
}

static int kvm_genirq_config_read(struct kvm_genirq *g, u32 off, int len,
				  void *val)
{
	struct virtio_genirq_config cfg;
	u8 *src = (u8 *)&cfg;

	memset(val, 0, len);
	kvm_genirq_refresh_config(g, &cfg);
	if (off >= sizeof(cfg))
		return 0;

	len = min_t(u32, len, sizeof(cfg) - off);
	memcpy(val, src + off, len);
	return 0;
}

static int kvm_genirq_config_write(struct kvm *kvm, struct kvm_genirq *g,
				   u32 off, int len, const void *val)
{
	u32 v;
	phys_addr_t hpa;
	int ret;

	if (len != sizeof(v))
		return 0;

	memcpy(&v, val, sizeof(v));
	switch (off) {
	case offsetof(struct virtio_genirq_config, raw_flags):
		g->raw_flags = v;
		break;
	case offsetof(struct virtio_genirq_config, raw_addr):
		g->raw_addr &= 0xffffffff00000000ULL;
		g->raw_addr |= v;
		break;
	case offsetof(struct virtio_genirq_config, raw_addr) + 4:
		g->raw_addr &= 0xffffffffULL;
		g->raw_addr |= (u64)v << 32;
		break;
	case offsetof(struct virtio_genirq_config, raw_data):
		g->raw_data = v;
		break;
	case offsetof(struct virtio_genirq_config, raw_count):
		g->raw_count = v;
		break;
	case offsetof(struct virtio_genirq_config, raw_stride):
		g->raw_stride = v;
		break;
	case offsetof(struct virtio_genirq_config, raw_kick):
		if (v != VIRTIO_GENIRQ_RAW_KICK_SEND)
			break;
		ret = kvm_riscv_aia_imsic_translate_vsfile(kvm, g->raw_addr,
								  &hpa);
		if (ret) {
			g->raw_status = VIRTIO_GENIRQ_STATUS_IOERR;
			g->total_errors++;
			break;
		}
		kvm_genirq_backing_send(g, hpa, g->raw_data, g->raw_count,
					g->raw_stride, g->raw_flags);
		break;
	default:
		break;
	}

	return 0;
}

static int kvm_genirq_mmio_read(struct kvm_vcpu *vcpu,
				struct kvm_io_device *dev, gpa_t addr,
				int len, void *val)
{
	struct kvm_genirq *g = container_of(dev, struct kvm_genirq, iodev);
	u32 off = addr - g->addr;
	u32 out = 0;

	mutex_lock(&g->lock);
	if (off >= VIRTIO_MMIO_CONFIG) {
		kvm_genirq_config_read(g, off - VIRTIO_MMIO_CONFIG, len, val);
		goto out_unlock;
	}

	memset(val, 0, len);
	if (len != sizeof(out))
		goto out_unlock;

	switch (off) {
	case VIRTIO_MMIO_MAGIC_VALUE:
		out = KVM_GENIRQ_MAGIC_VALUE;
		break;
	case VIRTIO_MMIO_VERSION:
		out = 1;
		break;
	case VIRTIO_MMIO_DEVICE_ID:
		out = VIRTIO_ID_GENIRQ;
		break;
	case VIRTIO_MMIO_VENDOR_ID:
		out = KVM_GENIRQ_VENDOR_ID;
		break;
	case VIRTIO_MMIO_DEVICE_FEATURES:
		out = 0;
		break;
	case VIRTIO_MMIO_QUEUE_NUM_MAX:
		out = g->queue_sel == VIRTIO_GENIRQ_CMD_QUEUE ?
		      VIRTIO_GENIRQ_QUEUE_SIZE : 0;
		break;
	case VIRTIO_MMIO_QUEUE_PFN:
		out = g->vq.pfn;
		break;
	case VIRTIO_MMIO_QUEUE_READY:
		out = !!g->vq.pfn;
		break;
	case VIRTIO_MMIO_INTERRUPT_STATUS:
		out = g->interrupt_status;
		break;
	case VIRTIO_MMIO_STATUS:
		out = g->status;
		break;
	case VIRTIO_MMIO_SHM_LEN_LOW:
	case VIRTIO_MMIO_SHM_LEN_HIGH:
		out = U32_MAX;
		break;
	case VIRTIO_MMIO_SHM_BASE_LOW:
	case VIRTIO_MMIO_SHM_BASE_HIGH:
		out = 0;
		break;
	default:
		break;
	}
	memcpy(val, &out, sizeof(out));

out_unlock:
	mutex_unlock(&g->lock);
	return 0;
}

static int kvm_genirq_mmio_write(struct kvm_vcpu *vcpu,
				 struct kvm_io_device *dev, gpa_t addr,
				 int len, const void *val)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_genirq *g = container_of(dev, struct kvm_genirq, iodev);
	u32 off = addr - g->addr;
	u32 v = 0;

	if (len > sizeof(v))
		return 0;
	memcpy(&v, val, len);

	mutex_lock(&g->lock);
	if (off >= VIRTIO_MMIO_CONFIG) {
		kvm_genirq_config_write(kvm, g, off - VIRTIO_MMIO_CONFIG, len, val);
		goto out_unlock;
	}

	if (len != sizeof(v))
		goto out_unlock;

	switch (off) {
	case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
		g->device_features_sel = v;
		break;
	case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
		g->driver_features_sel = v;
		break;
	case VIRTIO_MMIO_DRIVER_FEATURES:
		break;
	case VIRTIO_MMIO_GUEST_PAGE_SIZE:
		g->guest_page_size = v;
		break;
	case VIRTIO_MMIO_QUEUE_SEL:
		g->queue_sel = v;
		break;
	case VIRTIO_MMIO_QUEUE_NUM:
		if (g->queue_sel == VIRTIO_GENIRQ_CMD_QUEUE &&
		    v <= VIRTIO_GENIRQ_QUEUE_SIZE)
			g->vq.num = v;
		break;
	case VIRTIO_MMIO_QUEUE_ALIGN:
		g->vq.align = v;
		break;
	case VIRTIO_MMIO_QUEUE_PFN:
		if (g->queue_sel != VIRTIO_GENIRQ_CMD_QUEUE)
			break;
		g->vq.pfn = v;
		g->vq.last_avail_idx = 0;
		g->vq.used_idx = 0;
		break;
	case VIRTIO_MMIO_QUEUE_NOTIFY:
		if (v == VIRTIO_GENIRQ_CMD_QUEUE)
			kvm_genirq_process_vq(kvm, g);
		break;
	case VIRTIO_MMIO_INTERRUPT_ACK:
		g->interrupt_status &= ~v;
		break;
	case VIRTIO_MMIO_STATUS:
		if (!v) {
			memset(&g->vq, 0, sizeof(g->vq));
			g->guest_page_size = 0;
			g->queue_sel = 0;
			g->interrupt_status = 0;
			g->status = 0;
		} else {
			g->status = v;
		}
		break;
	default:
		break;
	}

out_unlock:
	mutex_unlock(&g->lock);
	return 0;
}

static const struct kvm_io_device_ops kvm_genirq_iodev_ops = {
	.read = kvm_genirq_mmio_read,
	.write = kvm_genirq_mmio_write,
};

static int kvm_genirq_create(struct kvm_device *dev, u32 type)
{
	struct kvm_genirq *g = &dev->kvm->arch.genirq;

	mutex_init(&g->lock);
	return 0;
}

static void kvm_genirq_destroy(struct kvm_device *dev)
{
	struct kvm *kvm = dev->kvm;
	struct kvm_genirq *g = &kvm->arch.genirq;

	mutex_lock(&g->lock);
	if (g->initialized) {
		mutex_lock(&kvm->slots_lock);
		kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS, &g->iodev);
		mutex_unlock(&kvm->slots_lock);
		g->initialized = false;
	}
	if (g->backing_base) {
		iounmap(g->backing_base);
		g->backing_base = NULL;
	}
	mutex_unlock(&g->lock);
}

static int kvm_genirq_do_init(struct kvm_device *dev)
{
	struct kvm *kvm = dev->kvm;
	struct kvm_genirq *g = &kvm->arch.genirq;
	int ret;

	if (!g->addr || !g->size || !g->backing_addr || !g->backing_size ||
	    !g->irq)
		return -EINVAL;
	if (g->size < VIRTIO_MMIO_CONFIG + sizeof(struct virtio_genirq_config))
		return -EINVAL;
	if (g->backing_size < VIRTIO_GENIRQ_RAW_OFFSET(raw_kick) + sizeof(u32))
		return -EINVAL;
	if (!kvm_riscv_aia_initialized(kvm) || !irqchip_in_kernel(kvm))
		return -ENODEV;
	if (kvm->arch.aia.mode != KVM_DEV_RISCV_AIA_MODE_HWACCEL)
		return -EOPNOTSUPP;
	if (g->initialized)
		return -EBUSY;

	g->backing_base = ioremap(g->backing_addr, g->backing_size);
	if (!g->backing_base)
		return -ENOMEM;

	kvm_iodevice_init(&g->iodev, &kvm_genirq_iodev_ops);
	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, g->addr, g->size,
					      &g->iodev);
	mutex_unlock(&kvm->slots_lock);
	if (ret) {
		iounmap(g->backing_base);
		g->backing_base = NULL;
		return ret;
	}

	g->initialized = true;
	return 0;
}

static int kvm_genirq_set_attr(struct kvm_device *dev,
				       struct kvm_device_attr *attr)
{
	struct kvm_genirq *g = &dev->kvm->arch.genirq;
	void __user *uaddr = (void __user *)(unsigned long)attr->addr;
	u64 value;
	int ret = 0;

	if (attr->group == KVM_DEV_RISCV_GENIRQ_GRP_CTRL) {
		if (attr->attr != KVM_DEV_RISCV_GENIRQ_CTRL_INIT)
			return -ENXIO;
		mutex_lock(&g->lock);
		ret = kvm_genirq_do_init(dev);
		mutex_unlock(&g->lock);
		return ret;
	}

	if (copy_from_user(&value, uaddr, sizeof(value)))
		return -EFAULT;

	mutex_lock(&g->lock);
	if (g->initialized) {
		ret = -EBUSY;
		goto out_unlock;
	}

	switch (attr->group) {
	case KVM_DEV_RISCV_GENIRQ_GRP_DEVICE:
		switch (attr->attr) {
		case KVM_DEV_RISCV_GENIRQ_DEV_ADDR:
			g->addr = value;
			break;
		case KVM_DEV_RISCV_GENIRQ_DEV_SIZE:
			g->size = value;
			break;
		case KVM_DEV_RISCV_GENIRQ_DEV_IRQ:
			g->irq = value;
			break;
		default:
			ret = -ENXIO;
			break;
		}
		break;
	case KVM_DEV_RISCV_GENIRQ_GRP_BACKING:
		switch (attr->attr) {
		case KVM_DEV_RISCV_GENIRQ_BACKING_ADDR:
			g->backing_addr = value;
			break;
		case KVM_DEV_RISCV_GENIRQ_BACKING_SIZE:
			g->backing_size = value;
			break;
		default:
			ret = -ENXIO;
			break;
		}
		break;
	default:
		ret = -ENXIO;
		break;
	}

out_unlock:
	mutex_unlock(&g->lock);
	return ret;
}

static int kvm_genirq_get_attr(struct kvm_device *dev,
				       struct kvm_device_attr *attr)
{
	struct kvm_genirq *g = &dev->kvm->arch.genirq;
	void __user *uaddr = (void __user *)(unsigned long)attr->addr;
	u64 value = 0;
	int ret = 0;

	mutex_lock(&g->lock);
	switch (attr->group) {
	case KVM_DEV_RISCV_GENIRQ_GRP_DEVICE:
		switch (attr->attr) {
		case KVM_DEV_RISCV_GENIRQ_DEV_ADDR:
			value = g->addr;
			break;
		case KVM_DEV_RISCV_GENIRQ_DEV_SIZE:
			value = g->size;
			break;
		case KVM_DEV_RISCV_GENIRQ_DEV_IRQ:
			value = g->irq;
			break;
		default:
			ret = -ENXIO;
			break;
		}
		break;
	case KVM_DEV_RISCV_GENIRQ_GRP_BACKING:
		switch (attr->attr) {
		case KVM_DEV_RISCV_GENIRQ_BACKING_ADDR:
			value = g->backing_addr;
			break;
		case KVM_DEV_RISCV_GENIRQ_BACKING_SIZE:
			value = g->backing_size;
			break;
		default:
			ret = -ENXIO;
			break;
		}
		break;
	default:
		ret = -ENXIO;
		break;
	}
	mutex_unlock(&g->lock);

	if (ret)
		return ret;
	return copy_to_user(uaddr, &value, sizeof(value)) ? -EFAULT : 0;
}

static int kvm_genirq_has_attr(struct kvm_device *dev,
				       struct kvm_device_attr *attr)
{
	switch (attr->group) {
	case KVM_DEV_RISCV_GENIRQ_GRP_DEVICE:
		if (attr->attr <= KVM_DEV_RISCV_GENIRQ_DEV_IRQ)
			return 0;
		break;
	case KVM_DEV_RISCV_GENIRQ_GRP_BACKING:
		if (attr->attr <= KVM_DEV_RISCV_GENIRQ_BACKING_SIZE)
			return 0;
		break;
	case KVM_DEV_RISCV_GENIRQ_GRP_CTRL:
		if (attr->attr == KVM_DEV_RISCV_GENIRQ_CTRL_INIT)
			return 0;
		break;
	default:
		break;
	}

	return -ENXIO;
}

static struct kvm_device_ops kvm_genirq_device_ops = {
	.name = "kvm-riscv-virtio-genirq",
	.create = kvm_genirq_create,
	.destroy = kvm_genirq_destroy,
	.set_attr = kvm_genirq_set_attr,
	.get_attr = kvm_genirq_get_attr,
	.has_attr = kvm_genirq_has_attr,
};

int kvm_riscv_genirq_init(void)
{
	return kvm_register_device_ops(&kvm_genirq_device_ops,
				       KVM_DEV_TYPE_MY_VIRTIO_GENIRQ);
}
