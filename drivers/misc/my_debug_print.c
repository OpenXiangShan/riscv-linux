#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/my_debug_print.h>

struct my_debug_print_data {
	void __iomem *base;
	phys_addr_t phys;
	int size;
	int head;
	int tail;
	spinlock_t spin_lock;
};

static DEFINE_SPINLOCK(lock);

static struct my_debug_print_data *print_data = NULL;

static char tmp_buf[4096];
static int tmp_head = 0, tmp_tail = 0, tmp_size = 4096;

static void __my_debug_putc(char *buf, int *head, int *tail, char c, int size)
{
	char *addr = (char *)buf;

	spin_lock(&lock);
	addr[*tail] = c;

	if (*tail == size)
		*tail = 0;
	else
		*tail += 1;

	if (*tail == *head)
		*head += 1;
	spin_unlock(&lock);
}

static void my_debug_putc(char c)
{
	if (!print_data)
		__my_debug_putc(tmp_buf, &tmp_head, &tmp_tail, c, tmp_size);
	else
		__my_debug_putc(print_data->base, &print_data->head, &print_data->tail, c, print_data->size);
}

static void my_debug_puts(char *str)
{
	while (*str != '\0')
		my_debug_putc(*str++);
}

typedef __builtin_va_list __gnuc_va_list;
typedef __gnuc_va_list va_list;

static const unsigned char hex_tab[] =
    { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
	'f'
};

#define BACKSPACE_ASCII 8

#define  MAX_NUMBER_BYTES  64
#define  F_PRECISION       8
//#define va_start(v,l) __builtin_va_start(v,l)
//#define va_end(v) __builtin_va_end(v)
//#define va_arg(v,l) __builtin_va_arg(v,l)

static void out_string(char *str, char lead, int maxwidth)
{
	int count = 0, i;
	char *tmp = str;

	while (*tmp++)
		count++;

	my_debug_puts(str);

	for (i = 0; i < maxwidth - count; i++)
		my_debug_putc(lead);
}

static void out_num(unsigned long n, int base, char lead, int maxwidth)
{
	unsigned long m = 0;
	char buf[MAX_NUMBER_BYTES], *s = buf + sizeof(buf);
	int count = 0, i = 0;

	*--s = '\0';

	if (n < 0)
		m = -n;
	else
		m = n;

	do {
		*--s = hex_tab[m % base];
		count++;

		if (base == 2 && (count % 8 == 0)) {
			*--s = ' ';
		}
	}
	while ((m /= base) != 0);

	if (maxwidth && count < maxwidth) {
		for (i = maxwidth - count; i; i--) {
			*--s = lead;
			if (base == 2 && ((++count) % 8 == 0)) {
				*--s = ' ';
			}
		}
	}

	if (n < 0)
		*--s = '-';

	my_debug_puts(s);
}

static int my_vprintf(const char *fmt, va_list ap)
{
	char lead = ' ';
	unsigned int maxwidth = 0;

	for (; *fmt != '\0'; fmt++) {
		if (*fmt != '%') {
			my_debug_putc(*fmt);
			continue;
		}
		lead = ' ';
		maxwidth = 0;

		fmt++;
		if (*fmt == '0') {
			lead = '0';
			fmt++;
		}

		while (*fmt >= '0' && *fmt <= '9') {
			maxwidth *= 10;
			maxwidth += (*fmt - '0');
			fmt++;
		}

		switch (*fmt) {
		case 'd':
			out_num(va_arg(ap, s64), 10, lead, maxwidth);
			break;
		case 'o':
			out_num(va_arg(ap, u64), 8, lead, maxwidth);
			break;
		case 'u':
			out_num(va_arg(ap, u32), 10, lead, maxwidth);
			break;
		case 'x':
		case 'X':
			out_num(va_arg(ap, u32), 16, lead, maxwidth);
			break;
		case 'l':
			if (*(fmt + 1) == 'l') {
				if (*(fmt + 2) == 'u') {
					fmt+=2;
					out_num(va_arg(ap, u64), 10, lead, maxwidth);
				} else if (*(fmt + 2) == 'x') {
					fmt+=2;
					out_num(va_arg(ap, u64), 16, lead, maxwidth);
				}
			} else if (*(fmt + 1) == 'u') {
				fmt++;
				out_num(va_arg(ap, u64), 10, lead, maxwidth);
			} else if (*(fmt + 1) == 'x') {
				fmt++;
				out_num(va_arg(ap, u64), 16, lead, maxwidth);
			} else if (*(fmt + 1) == 'd') {
				fmt++;
				out_num(va_arg(ap, s64), 10, lead, maxwidth);
			}
			break;
		case 'b':
			out_num(va_arg(ap, u32), 2, lead, maxwidth);
			break;
		case 'c':
			my_debug_putc(va_arg(ap, int));
			break;
		case 's':
			out_string(va_arg(ap, char *), lead, maxwidth);
			//my_debug_puts(va_arg(ap, char *));
			break;
		default:
			my_debug_putc(*fmt);
			break;
		}
	}

	return 0;
}

void my_debug_print(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	my_vprintf(fmt, ap);
	va_end(ap);
}
EXPORT_SYMBOL(my_debug_print);

static int seq_put_from_print_buf(struct seq_file *m, char *data)
{
	int len = 0;

	spin_lock(&lock);
	if (print_data->tail > print_data->head) {
		len = print_data->tail - print_data->head;
		seq_puts(m, data + print_data->head);
		print_data->head += len;
	} else {
		len = print_data->size - print_data->head;
		seq_puts(m, data + print_data->head);
		print_data->head += len;
		if (print_data->head == print_data->size)
			print_data->head = 0;
	}
	spin_unlock(&lock);

	return print_data->tail - print_data->head;
}

static int my_debug_print_seq_show(struct seq_file *m, void *v)
{
	int remain;

	if (print_data->tail == print_data->head)
		return 0;

	remain = seq_put_from_print_buf(m, (char *)print_data->base);

	return remain;
}

static int my_debug_print_open(struct inode *inode, struct file *file)
{
	return single_open(file, my_debug_print_seq_show, NULL);
}

static const struct file_operations my_debug_print_ops = {
	.owner = THIS_MODULE,
	.open = my_debug_print_open,
	.read = seq_read,
};

static int my_debug_print_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct my_debug_print_data *data;
	struct reserved_mem *rmem;
	void __iomem *base;
	int ret;
	struct device_node *rmem_node;
	struct dentry *d;

	//data = kzalloc(sizeof(*data), GFP_KERNEL);
	//if (!data)
	//	return -ENOMEM;

	rmem_node = of_parse_phandle(dev->of_node, "memory-region", 0);
	if (!rmem_node) {
		printk("Cound not found rmem_node...\n");
		ret = -ENODEV;
		goto free_data;
	}
	rmem = of_reserved_mem_lookup(rmem_node);
	if (!rmem) {
		printk("of_reserved_mem_lookup fail\n");
		ret = -ENODEV;
		goto release;
	}
	printk("Reserved memory: phys:0x%lx, size:0x%lx\n",
		(unsigned long)rmem->base, (unsigned long)rmem->size);

	base = ioremap(rmem->base, rmem->size);

	data = (struct my_debug_print_data *)base;

	data->phys = rmem->base + sizeof(*data);
	data->size = rmem->size;
	data->base = base + sizeof(*data);

	spin_lock(&lock);
	if (tmp_head != tmp_tail) {
		memcpy(data->base, tmp_buf, tmp_size);
		data->head = tmp_head;
		data->tail = tmp_tail;
	} else {
		data->head = 0;
		data->tail = 0;
	}
	print_data = data;
	spin_unlock(&lock);

	d = debugfs_create_file("my_debug_print", S_IRUGO | S_IWUSR, NULL, print_data,
				&my_debug_print_ops);
	if (!d) {
		printk("%s -- create debugfs fail\n", __FUNCTION__);
		return -1;
	}

	platform_set_drvdata(pdev, data);

	return 0;

release:
	of_reserved_mem_device_release(dev);
free_data:
	kfree(data);

	return ret;
}

static int my_debug_print_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id my_debug_print_of_match[] = {
	{ .compatible = "my,debug-print" },
	{ }
};

static struct platform_driver my_debug_print_driver = {
	.probe = my_debug_print_probe,
	.remove = my_debug_print_remove,
	.driver = {
		.name = "my-reserved-mem-driver",
		.of_match_table = my_debug_print_of_match,
	},
};

module_platform_driver(my_debug_print_driver);
