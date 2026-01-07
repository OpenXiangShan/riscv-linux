#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/kprobes.h>
#include <linux/list.h>

static void __remove_blank(char *buf);
static int is_what(char *buf, const char *target);
static void parse_string(char *buf, char *ret);

struct kprobe_struct {
	struct list_head list;
	const char symbol_name[64];
	const char when[1024];
	struct kprobe kp;
};

struct my_debug_trgger_debug_intf {
	const char file_name[64];
	struct dentry *d;
	struct dentry *parent;
	const struct file_operations *ops;
};

static char symbol_name[64] = { 0 };
static char when[1024] = { 0 };
static LIST_HEAD(kprobes);

static void exec_trigger(void)
{
	printk("########### do trigger!!!\n");

	__asm__ volatile (
		".rept 40\n\t"
		"nop\n\t"
		".endr\n\t"
		".word 0x81c04073"
		::: "memory"
	);
}

static int __get_reg(char *str, struct pt_regs *regs, unsigned long *reg)
{
	if (!strcmp(str, "epc")) {
		*reg = regs->epc;
		return 0;
	} else if (!strcmp(str, "ra")) {
		*reg = regs->ra;
		return 0;
	} else if (!strcmp(str, "sp")) {
		*reg = regs->sp;
		return 0;
	} else if (!strcmp(str, "gp")) {
		*reg = regs->gp;
		return 0;
	} else if (!strcmp(str, "tp")) {
		*reg = regs->tp;
		return 0;
	} else if (!strcmp(str, "t0")) {
		*reg = regs->t0;
		return 0;
	} else if (!strcmp(str, "t1")) {
		*reg = regs->t1;
		return 0;
	} else if (!strcmp(str, "s0")) {
		*reg = regs->s0;
		return 0;
	} else if (!strcmp(str, "s1")) {
		*reg = regs->s1;
		return 0;
	} else if (!strcmp(str, "a0")) {
		*reg = regs->a0;
		return 0;
	} else if (!strcmp(str, "a1")) {
		*reg = regs->a1;
		return 0;
	} else if (!strcmp(str, "a2")) {
		*reg = regs->a2;
		return 0;
	} else if (!strcmp(str, "a3")) {
		*reg = regs->a3;
		return 0;
	} else if (!strcmp(str, "a4")) {
		*reg = regs->a4;
		return 0;
	} else if (!strcmp(str, "a5")) {
		*reg = regs->a5;
		return 0;
	} else if (!strcmp(str, "a6")) {
		*reg = regs->a6;
		return 0;
	} else if (!strcmp(str, "a7")) {
		*reg = regs->a7;
		return 0;
	} else if (!strcmp(str, "s2")) {
		*reg = regs->s2;
		return 0;
	} else if (!strcmp(str, "s3")) {
		*reg = regs->s3;
		return 0;
	} else if (!strcmp(str, "s4")) {
		*reg = regs->s4;
		return 0;
	} else if (!strcmp(str, "s5")) {
		*reg = regs->s5;
		return 0;
	} else if (!strcmp(str, "s6")) {
		*reg = regs->s6;
		return 0;
	} else if (!strcmp(str, "s7")) {
		*reg = regs->s7;
		return 0;
	} else if (!strcmp(str, "s8")) {
		*reg = regs->s8;
		return 0;
	} else if (!strcmp(str, "s9")) {
		*reg = regs->s9;
		return 0;
	} else if (!strcmp(str, "s10")) {
		*reg = regs->s10;
		return 0;
	} else if (!strcmp(str, "s11")) {
		*reg = regs->s11;
		return 0;
	} else if (!strcmp(str, "t3")) {
		*reg = regs->t3;
		return 0;
	} else if (!strcmp(str, "t4")) {
		*reg = regs->t4;
		return 0;
	} else if (!strcmp(str, "t5")) {
		*reg = regs->t5;
		return 0;
	} else if (!strcmp(str, "t6")) {
		*reg = regs->t6;
		return 0;
	} else if (!strcmp(str, "status")) {
		*reg = regs->status;
		return 0;
	} else if (!strcmp(str, "badaddr")) {
		*reg = regs->badaddr;
		return 0;
	} else if (!strcmp(str, "cause")) {
		*reg = regs->cause;
		return 0;
	} else if (!strcmp(str, "orig_a0")) {
		*reg = regs->orig_a0;
		return 0;
	}

	return -1;
}

static int parse_when(char **buf, char *ret)
{
	int len = 0;

	while ((**buf != 0) && (**buf != '\n') && (**buf != '\r')) {
		if (**buf == ',')
			break;
		*ret++ = **buf;
		(*buf)++;
		len++;
	}
	*ret = 0;
	(*buf)++;

	return len;
}

static int __do_exit_trigger(unsigned long reg, char *op, unsigned long val)
{
	printk("reg:0x%lx op:%s val:0x%lx\n", reg, op, val);

	if (!strcmp(op, "==")) {
		return (reg == val);
	} else if (!strcmp(op, ">=")) {
		return (reg >= val);
	} else if (!strcmp(op, "<=")) {
		return (reg <= val);
	} else if (!strcmp(op, "!=")) {
		return (reg != val);
	} else
		return -1;

	return -1;
}

static int __exit_trigger(char *buf, struct pt_regs *regs)
{
	char left[64];
	char right[16];
	char op[8];
	char *l_ptr = left, *r_ptr = right, *op_ptr = op;
	int r = 0;
	unsigned long reg, val;
	int ret;

	while ((*buf != 0) && (*buf != '\n') && (*buf != '\r')) {
		if ((*buf == '=') || (*buf == '>') || (*buf == '<') || (*buf == '!')) {
			*op_ptr++ = *buf++;
			r = 1;
		}
		else if (r == 0)
			*l_ptr++ = *buf++;
		else
			*r_ptr++ = *buf++;
	}

	*l_ptr = 0;
	*r_ptr = 0;
	*op_ptr = 0;

	printk("%s -- '%s' '%s' '%s'\n", __FUNCTION__, left, op, right);

	if (__get_reg(left, regs, &reg))
		return 0;

	if (kstrtoul(right, 0, &val))
		return 0;

	ret = __do_exit_trigger(reg, op, val);
	if (ret == -1)
		return 0;

	return !ret;
}

static void do_trigger(char *when, struct pt_regs *regs)
{
	char tmp[64];
	int len;

	while (1) {
		len = parse_when(&when, tmp);
		if (len == 0)
			break;

		if (__exit_trigger(tmp, regs))
			return;
	}

	exec_trigger();
}

static int kprobe_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe_struct *k;

	printk("######### %s -- %s\n", __FUNCTION__, p->symbol_name);

	k = container_of(p, struct kprobe_struct, kp);
	if (!k) {
		printk("Can not find kprobe struct \n");
		return -1;
	}

	do_trigger((char *)k->when, regs);

	return 0;
}

static int register_kprobe_struct(char *symbol_name, char *when)
{
	struct kprobe_struct *k;
	int ret;

	list_for_each_entry(k, &kprobes, list) {
		if (!strcmp(k->kp.symbol_name, symbol_name))
			return 0;
	}

	k = (struct kprobe_struct *)kzalloc(sizeof(*k), GFP_KERNEL);
	if (!k) {
		printk("malloc kprobe struct failed\n");
		return -1;
	}

	if (when)
		strcpy((char *)k->when, when);
	strcpy((char *)k->symbol_name, symbol_name);
	k->kp.symbol_name = k->symbol_name;
	k->kp.pre_handler = kprobe_handler_pre;

	list_add_tail(&k->list, &kprobes);

	ret = register_kprobe(&k->kp);
	if (ret) {
		printk("register_kprobe %s failed, error: %d\n", k->kp.symbol_name, ret);
		return -1;
	}

	return 0;
}

static ssize_t register_ops_write(struct file *file, const char __user * buf,
				  size_t count, loff_t * ppos)
{
	register_kprobe_struct(symbol_name, when);

	return count;
}

static const struct file_operations register_ops = {
	.owner = THIS_MODULE,
	.write = register_ops_write,
};

static ssize_t symbol_name_ops_write(struct file *file, const char __user * buf,
				     size_t count, loff_t * ppos)
{
	char *ptr = symbol_name;

	if (count > 64) {
		count = 64;
		symbol_name[64] = 0;
	}

	if (copy_from_user(symbol_name, buf, count)) {
		printk("%s -- copy from user failed\n", __FUNCTION__);
		return -1;
	}

	while ((*ptr != 0) && (*ptr != '\n'))
		ptr++;

	if (*ptr == '\n')
		*ptr = 0;

	printk("%s\n", symbol_name);

	return count;
}

static const struct file_operations symbol_name_ops = {
	.owner = THIS_MODULE,
	.write = symbol_name_ops_write,
};

static ssize_t when_ops_write(struct file *file, const char __user * buf,
			      size_t count, loff_t * ppos)
{
	char *ptr = when;

	if (count > 1024)
		count = 1024;

	if (copy_from_user(when, buf, count)) {
		printk("%s -- copy from user failed\n", __FUNCTION__);
		return -1;
	}

	while ((*ptr != 0) && (*ptr != '\n'))
		ptr++;

	if (*ptr == '\n')
		*ptr = 0;

	__remove_blank(when);

	printk("%s\n", when);

	return count;
}

static const struct file_operations when_ops = {
	.owner = THIS_MODULE,
	.write = when_ops_write,
};


static ssize_t show_info_ops_read(struct file *file, char __user * buf,
				  size_t count, loff_t * ppos)
{
	printk("symbol_name: '%s' when: '%s'\n", symbol_name, when);

	return 0;
}

static const struct file_operations show_info_ops = {
	.owner = THIS_MODULE,
	.read = show_info_ops_read,
};

static ssize_t show_all_ops_read(struct file *file, char __user * buf,
				 size_t count, loff_t * ppos)
{
	struct kprobe_struct *k;

	list_for_each_entry(k, &kprobes, list) {
		printk("symbol_name: '%s', when: '%s'\n", k->kp.symbol_name, k->when);
	}

	return 0;
}

static const struct file_operations show_all_ops = {
	.owner = THIS_MODULE,
	.read = show_all_ops_read,
};

static struct my_debug_trgger_debug_intf debug_intf[] = {
	{ "register", NULL, NULL, &register_ops },
	{ "symbol_name", NULL, NULL, &symbol_name_ops },
	{ "when", NULL, NULL, &when_ops },
	{ "show_info", NULL, NULL, &show_info_ops},
	{ "show_all", NULL, NULL, &show_all_ops},
};
#define DEBUG_TRIGGER_ATTR_COUNT (sizeof(debug_intf) / sizeof(debug_intf[0]))

static int my_get_line(char **buf, char *ret)
{
	int len = 0;

	if ((**buf == '\n') || (**buf == '\r'))
		return 1;

	while ((**buf != 0) && (**buf != '\n') && (**buf != '\r')) {
		*ret = **buf;
		//printk("ret:%c buf:%c len:%d\n", *ret, **buf, len+1);
		(*buf)++;
		ret++;
		len++;
	}

	*ret = 0;

	return len;
}

#define FUNC_NAME_STRING "symbol_name:"
#define WHEN_STRING "when:"

static int is_what(char *buf, const char *target)
{
	char tmp[256];
	char *ptr = tmp;

	while ((*buf != 0) && (*buf != '\n') && (*buf != '\r'))
		*ptr++ = *buf++;

	*ptr = 0;

	//printk("%s -- tmp:%s target:%s\n", __FUNCTION__, tmp, target);

	return !strncmp(tmp, target, strlen(target) - 1);
}

static void __remove_blank(char *buf)
{
	int i, ori = 0, new = 0;

	while ((buf[ori] != 0) && (buf[ori] != '\n') && (buf[ori] != '\r')) {
		if (buf[ori] != ' ')
			buf[new++] = buf[ori++];
		else
			ori++;
	}

	for (i = new; i < ori; i++)
		buf[i] = 0;
}

static void parse_string(char *buf, char *ret)
{
	while ((*buf != ':') && (*buf != 0) && (*buf != '\n') && (*buf != '\r'))
		buf++;

	if (*buf == ':')
		buf++;

	while ((*buf != 0) && (*buf != '\n') && (*buf != '\r'))
		*ret++ = *buf++;

	*ret = 0;
}

static int set_kprobe_from_reserved(char *buf)
{
	char tmp[256];
	char func_name[64];
	char when[128];

	while (1) {
		int len;

		len = my_get_line(&buf, tmp);
		if (len == 0)
			break;

		__remove_blank(tmp);

		if (!strcmp(tmp, "[func]")) {
			memset(when, 0, 128);
			memset(func_name, 0, 64);
		} else if (is_what(tmp, FUNC_NAME_STRING)) {
			parse_string(tmp, func_name);
		} else if (is_what(tmp, WHEN_STRING)) {
			parse_string(tmp, when);
		} else if (!strcmp(tmp, "[end_func]"))
			register_kprobe_struct(func_name, when);

		memset(tmp, 0, len + 1);
		buf++;
	}

	return 0;
}

static int my_debug_trigger_probe(struct platform_device *pdev)
{
	int i;
	struct dentry *parent_dir;
	void __iomem *base;
	struct device_node *rmem_node;
	struct reserved_mem *rmem;

	rmem_node = of_parse_phandle(pdev->dev.of_node, "memory-region", 0);
	if (!rmem_node) {
		printk("Cound not found rmem_node...\n");
		goto create_debugfs;
	}
	rmem = of_reserved_mem_lookup(rmem_node);
	if (!rmem) {
		printk("of_reserved_mem_lookup fail\n");
		goto create_debugfs;
	}
	printk("Reserved memory: phys:0x%lx, size:0x%lx\n",
		(unsigned long)rmem->base, (unsigned long)rmem->size);

	base = ioremap(rmem->base, rmem->size);
	if (!base)
		goto create_debugfs;

	set_kprobe_from_reserved((char *)base);

create_debugfs:
	parent_dir = debugfs_create_dir("my_debug_trigger_dir", NULL);
	if (IS_ERR(parent_dir)) {
		printk("create my_debug_trigger_dir fail\n");
		return -1;
	}

	for (i = 0; i < DEBUG_TRIGGER_ATTR_COUNT; i++) {
		debug_intf[i].parent = parent_dir;
		debug_intf[i].d = debugfs_create_file(debug_intf[i].file_name,
						      S_IRUGO | S_IWUSR,
						      debug_intf[i].parent,
						      NULL,
						      debug_intf[i].ops);
	}

	return 0;
}

static void my_debug_trigger_remove(struct platform_device *pdev)
{
}

static const struct of_device_id my_debug_trigger_of_match[] = {
	{ .compatible = "my,debug-trigger" },
	{ }
};

static struct platform_driver my_debug_trigger_driver = {
	.probe = my_debug_trigger_probe,
	.remove = my_debug_trigger_remove,
	.driver = {
		.name = "my-reserved-mem-driver",
		.of_match_table = my_debug_trigger_of_match,
	},
};

module_platform_driver(my_debug_trigger_driver);
