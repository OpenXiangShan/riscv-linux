// SPDX-License-Identifier: GPL-2.0
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/irqchip/riscv-imsic.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_genirq.h>
#include <linux/virtio_ids.h>

enum virtio_genirq_pattern {
	VIRTIO_GENIRQ_PATTERN_SAME,
	VIRTIO_GENIRQ_PATTERN_RANGE,
	VIRTIO_GENIRQ_PATTERN_RANDOM,
};

struct virtio_genirq_target_state {
	u64 addr;
	u32 data;
	int virq;
	u32 index;
	bool requested;
	atomic64_t actual;
	u64 expected;
};

struct virtio_genirq {
	struct virtio_device *vdev;
	struct virtqueue *vq;
	struct completion cmd_done;
	struct mutex lock;
	struct platform_device *msi_pdev;
	struct virtio_genirq_target_state *targets;
	struct dentry *debugfs_dir;

	u32 target_count;
	u32 pattern;
	u32 repeat;
	u32 target;
	u32 seed;
	u32 timeout_ms;
	u64 seq;
	int last_ret;
	u32 last_status;
	u32 last_error_op;
	u64 last_sends;
	u64 last_errors;
};

static struct dentry *virtio_genirq_debugfs_root;

static const char *virtio_genirq_pattern_name(u32 pattern)
{
	switch (pattern) {
	case VIRTIO_GENIRQ_PATTERN_SAME:
		return "same";
	case VIRTIO_GENIRQ_PATTERN_RANGE:
		return "range";
	case VIRTIO_GENIRQ_PATTERN_RANDOM:
		return "random";
	default:
		return "unknown";
	}
}

static u32 virtio_genirq_lcg_next(u32 *seed)
{
	*seed = *seed * 1103515245U + 12345U;
	return *seed;
}

static irqreturn_t virtio_genirq_msi_handler(int irq, void *data)
{
	struct virtio_genirq_target_state *target = data;

	atomic64_inc(&target->actual);
	return IRQ_HANDLED;
}

static void virtio_genirq_write_msi_msg(struct msi_desc *desc,
					struct msi_msg *msg)
{
	struct virtio_genirq *g = dev_get_drvdata(desc->dev);
	struct virtio_genirq_target_state *target;
	u32 index = desc->msi_index;

	if (!g || index >= g->target_count)
		return;

	target = &g->targets[index];
	target->addr = ((u64)msg->address_hi << 32) | msg->address_lo;
	target->data = msg->data;
}

static void virtio_genirq_free_targets_locked(struct virtio_genirq *g)
{
	u32 i;

	if (g->targets) {
		for (i = 0; i < g->target_count; i++) {
			if (g->targets[i].requested)
				free_irq(g->targets[i].virq, &g->targets[i]);
		}
	}

	if (g->msi_pdev) {
		platform_device_msi_free_irqs_all(&g->msi_pdev->dev);
		platform_device_unregister(g->msi_pdev);
		g->msi_pdev = NULL;
	}

	kfree(g->targets);
	g->targets = NULL;
	g->target_count = 0;
}

static int virtio_genirq_alloc_targets_locked(struct virtio_genirq *g,
					      u32 count)
{
	struct irq_domain *domain;
	u32 i;
	int ret;

	if (count > VIRTIO_GENIRQ_MAX_TARGETS)
		return -EINVAL;

	virtio_genirq_free_targets_locked(g);
	if (!count)
		return 0;

	domain = imsic_get_irqdomain();
	if (!domain)
		return -ENODEV;

	g->targets = kcalloc(count, sizeof(*g->targets), GFP_KERNEL);
	if (!g->targets)
		return -ENOMEM;

	g->msi_pdev = platform_device_alloc("virtio_genirq_msi",
					       PLATFORM_DEVID_AUTO);
	if (!g->msi_pdev) {
		ret = -ENOMEM;
		goto err_free_targets;
	}

	g->msi_pdev->dev.parent = &g->vdev->dev;
	g->msi_pdev->dev.msi.domain = domain;
	dev_set_drvdata(&g->msi_pdev->dev, g);

	ret = platform_device_add(g->msi_pdev);
	if (ret)
		goto err_put_platform;

	g->target_count = count;
	for (i = 0; i < count; i++) {
		g->targets[i].virq = -1;
		g->targets[i].index = i;
		atomic64_set(&g->targets[i].actual, 0);
	}

	ret = platform_device_msi_init_and_alloc_irqs(&g->msi_pdev->dev,
							 count,
							 virtio_genirq_write_msi_msg);
	if (ret)
		goto err_unreg_platform;

	for (i = 0; i < count; i++) {
		struct msi_msg msg;

		g->targets[i].virq = msi_get_virq(&g->msi_pdev->dev, i);
		if (g->targets[i].virq <= 0) {
			ret = -ENODEV;
			goto err_free_irqs;
		}

		get_cached_msi_msg(g->targets[i].virq, &msg);
		if (!g->targets[i].addr) {
			g->targets[i].addr = ((u64)msg.address_hi << 32) |
					     msg.address_lo;
			g->targets[i].data = msg.data;
		}

		ret = request_irq(g->targets[i].virq, virtio_genirq_msi_handler,
				  0, "virtio_genirq", &g->targets[i]);
		if (ret)
			goto err_free_irqs;
		g->targets[i].requested = true;
	}

	return 0;

err_free_irqs:
	for (i = 0; i < count; i++) {
		if (g->targets[i].requested)
			free_irq(g->targets[i].virq, &g->targets[i]);
		g->targets[i].requested = false;
		g->targets[i].virq = -1;
	}
	platform_device_msi_free_irqs_all(&g->msi_pdev->dev);
err_unreg_platform:
	g->target_count = 0;
	platform_device_unregister(g->msi_pdev);
	g->msi_pdev = NULL;
	goto err_free_targets;
err_put_platform:
	platform_device_put(g->msi_pdev);
	g->msi_pdev = NULL;
err_free_targets:
	kfree(g->targets);
	g->targets = NULL;
	return ret;
}

static void virtio_genirq_vq_done(struct virtqueue *vq)
{
	struct virtio_genirq *g = vq->vdev->priv;
	unsigned int len;

	while (virtqueue_get_buf(vq, &len))
		complete(&g->cmd_done);
}

static int virtio_genirq_send_request(struct virtio_genirq *g, void *req,
				      u32 req_len, struct virtio_genirq_resp *resp)
{
	struct scatterlist out_sg, in_sg;
	struct scatterlist *sgs[] = { &out_sg, &in_sg };
	unsigned long timeout;
	int ret;

	sg_init_one(&out_sg, req, req_len);
	sg_init_one(&in_sg, resp, sizeof(*resp));
	reinit_completion(&g->cmd_done);

	ret = virtqueue_add_sgs(g->vq, sgs, 1, 1, g, GFP_KERNEL);
	if (ret)
		return ret;

	virtqueue_kick(g->vq);
	timeout = msecs_to_jiffies(g->timeout_ms ?: 5000);
	if (!wait_for_completion_timeout(&g->cmd_done, timeout)) {
		virtqueue_detach_unused_buf(g->vq);
		return -ETIMEDOUT;
	}

	return 0;
}

static void virtio_genirq_add_expected(struct virtio_genirq *g)
{
	u32 i;
	u64 seen = 0;

	switch (g->pattern) {
	case VIRTIO_GENIRQ_PATTERN_SAME:
		if (g->target < g->target_count)
			g->targets[g->target].expected++;
		break;
	case VIRTIO_GENIRQ_PATTERN_RANGE:
		for (i = 0; i < g->target_count; i++)
			g->targets[i].expected++;
		break;
	case VIRTIO_GENIRQ_PATTERN_RANDOM:
	{
		u32 seed = g->seed ?: 1;
		u32 nr = g->repeat ?: 1;

		for (i = 0; i < nr; i++) {
			u32 idx = virtio_genirq_lcg_next(&seed) % g->target_count;

			seen |= BIT_ULL(idx);
		}
		for (i = 0; i < g->target_count; i++) {
			if (seen & BIT_ULL(i))
				g->targets[i].expected++;
		}
		break;
	}
	default:
		break;
	}
}

static int virtio_genirq_run_locked(struct virtio_genirq *g)
{
	struct virtio_genirq_req_hdr *hdr;
	struct virtio_genirq_target *targets;
	struct virtio_genirq_op *ops;
	struct virtio_genirq_resp *resp;
	u32 op_count = 1;
	u32 req_len;
	u32 i;
	void *req;
	int ret;

	if (!g->target_count || !g->targets)
		return -EINVAL;
	if (!g->vq)
		return -ENODEV;
	if ((g->repeat ?: 1) > VIRTIO_GENIRQ_MAX_REPEAT)
		return -EINVAL;
	if (g->pattern == VIRTIO_GENIRQ_PATTERN_SAME &&
	    g->target >= g->target_count)
		return -EINVAL;

	req_len = sizeof(*hdr) + g->target_count * sizeof(*targets) +
		  op_count * sizeof(*ops);
	req = kzalloc(req_len, GFP_KERNEL);
	resp = kzalloc(sizeof(*resp), GFP_KERNEL);
	if (!req || !resp) {
		ret = -ENOMEM;
		goto out_free;
	}

	hdr = req;
	targets = req + sizeof(*hdr);
	ops = req + sizeof(*hdr) + g->target_count * sizeof(*targets);

	hdr->magic = cpu_to_le32(VIRTIO_GENIRQ_REQ_MAGIC);
	hdr->version = cpu_to_le16(VIRTIO_GENIRQ_VERSION);
	hdr->opcode = cpu_to_le16(VIRTIO_GENIRQ_CMD_RUN);
	hdr->target_count = cpu_to_le32(g->target_count);
	hdr->op_count = cpu_to_le32(op_count);
	hdr->seq = cpu_to_le64(++g->seq);

	for (i = 0; i < g->target_count; i++) {
		targets[i].addr = cpu_to_le64(g->targets[i].addr);
		targets[i].data = cpu_to_le32(g->targets[i].data);
	}

	switch (g->pattern) {
	case VIRTIO_GENIRQ_PATTERN_SAME:
		ops[0].type = cpu_to_le16(VIRTIO_GENIRQ_OP_SEND);
		ops[0].target = cpu_to_le16(g->target);
		ops[0].count = cpu_to_le32(g->repeat ?: 1);
		break;
	case VIRTIO_GENIRQ_PATTERN_RANGE:
		ops[0].type = cpu_to_le16(VIRTIO_GENIRQ_OP_SEND_RANGE);
		ops[0].count = cpu_to_le32(g->target_count);
		ops[0].arg0 = cpu_to_le64(g->repeat ?: 1);
		ops[0].arg1 = cpu_to_le64(1);
		break;
	case VIRTIO_GENIRQ_PATTERN_RANDOM:
		ops[0].type = cpu_to_le16(VIRTIO_GENIRQ_OP_RANDOM);
		ops[0].count = cpu_to_le32(g->repeat ?: 1);
		ops[0].arg0 = cpu_to_le64(g->seed ?: 1);
		break;
	default:
		ret = -EINVAL;
		goto out_free;
	}

	ret = virtio_genirq_send_request(g, req, req_len, resp);
	g->last_ret = ret;
	if (!ret) {
		g->last_status = le32_to_cpu(resp->status);
		g->last_error_op = le32_to_cpu(resp->error_op);
		g->last_sends = le64_to_cpu(resp->sends);
		g->last_errors = le64_to_cpu(resp->errors);
		if (g->last_status == VIRTIO_GENIRQ_STATUS_OK)
			virtio_genirq_add_expected(g);
	} else {
		g->last_status = VIRTIO_GENIRQ_STATUS_IOERR;
		g->last_error_op = U32_MAX;
	}
	msleep(20);

out_free:
	kfree(resp);
	kfree(req);
	return ret;
}

static void virtio_genirq_clear_locked(struct virtio_genirq *g)
{
	u32 i;

	for (i = 0; i < g->target_count; i++) {
		atomic64_set(&g->targets[i].actual, 0);
		g->targets[i].expected = 0;
	}
	g->last_ret = 0;
	g->last_status = 0;
	g->last_error_op = 0;
	g->last_sends = 0;
	g->last_errors = 0;
}

static int virtio_genirq_target_count_get(void *data, u64 *val)
{
	struct virtio_genirq *g = data;

	mutex_lock(&g->lock);
	*val = g->target_count;
	mutex_unlock(&g->lock);
	return 0;
}

static int virtio_genirq_target_count_set(void *data, u64 val)
{
	struct virtio_genirq *g = data;
	int ret;

	if (val > VIRTIO_GENIRQ_MAX_TARGETS)
		return -EINVAL;

	mutex_lock(&g->lock);
	ret = virtio_genirq_alloc_targets_locked(g, (u32)val);
	mutex_unlock(&g->lock);
	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(virtio_genirq_target_count_fops,
				 virtio_genirq_target_count_get,
				 virtio_genirq_target_count_set, "%llu\n");

static ssize_t virtio_genirq_pattern_read(struct file *file, char __user *buf,
					  size_t len, loff_t *ppos)
{
	struct virtio_genirq *g = file->private_data;
	char tmp[16];
	int n;

	mutex_lock(&g->lock);
	n = scnprintf(tmp, sizeof(tmp), "%s\n",
		      virtio_genirq_pattern_name(g->pattern));
	mutex_unlock(&g->lock);
	return simple_read_from_buffer(buf, len, ppos, tmp, n);
}

static ssize_t virtio_genirq_pattern_write(struct file *file,
					   const char __user *buf, size_t len,
					   loff_t *ppos)
{
	struct virtio_genirq *g = file->private_data;
	char tmp[16];
	char *name;
	u32 pattern;

	if (len >= sizeof(tmp))
		return -EINVAL;
	if (copy_from_user(tmp, buf, len))
		return -EFAULT;
	tmp[len] = '\0';
	name = strim(tmp);

	if (!strcmp(name, "same"))
		pattern = VIRTIO_GENIRQ_PATTERN_SAME;
	else if (!strcmp(name, "range"))
		pattern = VIRTIO_GENIRQ_PATTERN_RANGE;
	else if (!strcmp(name, "random"))
		pattern = VIRTIO_GENIRQ_PATTERN_RANDOM;
	else
		return -EINVAL;

	mutex_lock(&g->lock);
	g->pattern = pattern;
	mutex_unlock(&g->lock);
	return len;
}

static const struct file_operations virtio_genirq_pattern_fops = {
	.open = simple_open,
	.read = virtio_genirq_pattern_read,
	.write = virtio_genirq_pattern_write,
	.llseek = default_llseek,
};

static ssize_t virtio_genirq_run_write(struct file *file,
				       const char __user *buf, size_t len,
				       loff_t *ppos)
{
	struct virtio_genirq *g = file->private_data;
	int ret;

	mutex_lock(&g->lock);
	ret = virtio_genirq_run_locked(g);
	mutex_unlock(&g->lock);
	return ret ? ret : len;
}

static const struct file_operations virtio_genirq_run_fops = {
	.open = simple_open,
	.write = virtio_genirq_run_write,
	.llseek = noop_llseek,
};

static ssize_t virtio_genirq_clear_write(struct file *file,
					 const char __user *buf, size_t len,
					 loff_t *ppos)
{
	struct virtio_genirq *g = file->private_data;

	mutex_lock(&g->lock);
	virtio_genirq_clear_locked(g);
	mutex_unlock(&g->lock);
	return len;
}

static const struct file_operations virtio_genirq_clear_fops = {
	.open = simple_open,
	.write = virtio_genirq_clear_write,
	.llseek = noop_llseek,
};

static int virtio_genirq_stats_show(struct seq_file *s, void *unused)
{
	struct virtio_genirq *g = s->private;
	u32 i;
	u64 total_expected = 0;
	u64 total_actual = 0;
	bool pass = true;

	mutex_lock(&g->lock);
	for (i = 0; i < g->target_count; i++) {
		u64 actual = atomic64_read(&g->targets[i].actual);

		total_expected += g->targets[i].expected;
		total_actual += actual;
		if (actual != g->targets[i].expected)
			pass = false;
	}

	seq_printf(s,
		   "device=%s backend=virtqueue target_count=%u pattern=%s repeat=%u target=%u seed=%u timeout_ms=%u\n",
		   dev_name(&g->vdev->dev), g->target_count,
		   virtio_genirq_pattern_name(g->pattern), g->repeat,
		   g->target, g->seed, g->timeout_ms);
	seq_printf(s,
		   "last_ret=%d last_status=%u last_error_op=%u last_sends=%llu last_errors=%llu seq=%llu\n",
		   g->last_ret, g->last_status, g->last_error_op,
		   (unsigned long long)g->last_sends,
		   (unsigned long long)g->last_errors,
		   (unsigned long long)g->seq);
	seq_printf(s, "summary expected=%llu actual=%llu pass=%u\n",
		   (unsigned long long)total_expected,
		   (unsigned long long)total_actual,
		   pass && g->last_status == VIRTIO_GENIRQ_STATUS_OK);

	for (i = 0; i < g->target_count; i++) {
		struct virtio_genirq_target_state *target = &g->targets[i];

		seq_printf(s,
			   "target[%u] virq=%d addr=0x%llx data=%u expected=%llu actual=%lld pass=%u\n",
			   i, target->virq,
			   (unsigned long long)target->addr, target->data,
			   (unsigned long long)target->expected,
			   (long long)atomic64_read(&target->actual),
			   target->expected == atomic64_read(&target->actual));
	}
	mutex_unlock(&g->lock);

	return 0;
}

static int virtio_genirq_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, virtio_genirq_stats_show, inode->i_private);
}

static const struct file_operations virtio_genirq_stats_fops = {
	.open = virtio_genirq_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void virtio_genirq_debugfs_create(struct virtio_genirq *g)
{
	g->debugfs_dir = debugfs_create_dir(dev_name(&g->vdev->dev),
						 virtio_genirq_debugfs_root);
	debugfs_create_file("target_count", 0600, g->debugfs_dir, g,
			    &virtio_genirq_target_count_fops);
	debugfs_create_file("pattern", 0600, g->debugfs_dir, g,
			    &virtio_genirq_pattern_fops);
	debugfs_create_u32("repeat", 0600, g->debugfs_dir, &g->repeat);
	debugfs_create_u32("target", 0600, g->debugfs_dir, &g->target);
	debugfs_create_u32("seed", 0600, g->debugfs_dir, &g->seed);
	debugfs_create_u32("timeout_ms", 0600, g->debugfs_dir, &g->timeout_ms);
	debugfs_create_file("run", 0200, g->debugfs_dir, g,
			    &virtio_genirq_run_fops);
	debugfs_create_file("clear", 0200, g->debugfs_dir, g,
			    &virtio_genirq_clear_fops);
	debugfs_create_file("stats", 0400, g->debugfs_dir, g,
			    &virtio_genirq_stats_fops);
}

static int virtio_genirq_probe(struct virtio_device *vdev)
{
	struct virtio_genirq *g;

	g = devm_kzalloc(&vdev->dev, sizeof(*g), GFP_KERNEL);
	if (!g)
		return -ENOMEM;

	g->vdev = vdev;
	g->pattern = VIRTIO_GENIRQ_PATTERN_RANGE;
	g->repeat = 1;
	g->seed = 1;
	g->timeout_ms = 5000;
	g->last_status = VIRTIO_GENIRQ_STATUS_OK;
	mutex_init(&g->lock);
	init_completion(&g->cmd_done);
	vdev->priv = g;

	g->vq = virtio_find_single_vq(vdev, virtio_genirq_vq_done, "cmd");
	if (IS_ERR(g->vq))
		return PTR_ERR(g->vq);

	virtio_device_ready(vdev);
	virtio_genirq_debugfs_create(g);
	dev_info(&vdev->dev, "virtio genirq debugfs ready\n");

	return 0;
}

static void virtio_genirq_remove(struct virtio_device *vdev)
{
	struct virtio_genirq *g = vdev->priv;

	debugfs_remove_recursive(g->debugfs_dir);
	mutex_lock(&g->lock);
	virtio_genirq_free_targets_locked(g);
	mutex_unlock(&g->lock);
	vdev->config->del_vqs(vdev);
	virtio_reset_device(vdev);
}

static const struct virtio_device_id virtio_genirq_id_table[] = {
	{ VIRTIO_ID_GENIRQ, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_genirq_driver = {
	.driver.name = KBUILD_MODNAME,
	.id_table = virtio_genirq_id_table,
	.probe = virtio_genirq_probe,
	.remove = virtio_genirq_remove,
};

static int __init virtio_genirq_init(void)
{
	virtio_genirq_debugfs_root = debugfs_create_dir("virtio_genirq", NULL);
	return register_virtio_driver(&virtio_genirq_driver);
}

static void __exit virtio_genirq_exit(void)
{
	unregister_virtio_driver(&virtio_genirq_driver);
	debugfs_remove_recursive(virtio_genirq_debugfs_root);
}

module_init(virtio_genirq_init);
module_exit(virtio_genirq_exit);
MODULE_DEVICE_TABLE(virtio, virtio_genirq_id_table);
MODULE_DESCRIPTION("Virtio generic IRQ/MSI stress test driver");
MODULE_LICENSE("GPL");
