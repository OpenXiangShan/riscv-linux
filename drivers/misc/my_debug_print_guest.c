#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <asm/csr.h>
#include <asm/early_ioremap.h>
#include <linux/my_debug_print.h>

static phys_addr_t my_debug_mmio_base = 0;
static void __iomem *base = NULL;
static void __iomem *early_base = NULL;

#define SATP_MODE_MASK	_AC(0xF000000000000000, UL)

static int idx = 0;
static char tmp_buffer[4096] = { 0 };

static void puts_from_tmp_buffer(void __iomem *base, char *tmp)
{
	while (*tmp != 0) {
		writeb(*tmp, base);
		*tmp = 0;
		tmp++;
	}
}

static void my_debug_putc(char c)
{
	if (csr_read(satp) & SATP_MODE_MASK) {
		if (!slab_is_available()) {
			if (!early_base) {
				early_base = early_ioremap(my_debug_mmio_base, 4096);
				if (!early_base) {
					//printk("early_ioremap 0x%llx fail\n", my_debug_mmio_base);
					if (!early_base && (idx < 4096))
						tmp_buffer[idx++] = c;
					return;
				}
				puts_from_tmp_buffer(early_base, tmp_buffer);
			}
			writeb(c, early_base);
		} else {
			if (early_base) {
				early_iounmap(early_base, 4096);
				early_base = NULL;
			}
			if (!base) {
				base = ioremap(my_debug_mmio_base, 4096);
				if (!base) {
					printk("ioremap 0x%llx fail\n", my_debug_mmio_base);
					return;
				}
				puts_from_tmp_buffer(base, tmp_buffer);
			}
			writeb(c, base);
		}
	} else {
		writeb(c, (void __iomem *)my_debug_mmio_base);
	}
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

#if 0
static int __init my_debug_print_init(void)
{
	base = ioremap(my_debug_mmio_base, 4096);
	printk("####### %s base:0x%lx \n", __FUNCTION__, base);
	if (!base) {
		printk("ioremap 0x%lx fail\n", my_debug_mmio_base);
		return -EINVAL;
	}

	return 0;
}
device_initcall(my_debug_print_init);
#endif

static int __init my_debug_print_parse_mmio(char *arg)
{
    if (!arg)
        return -EINVAL;

    if (kstrtoull(arg, 0, &my_debug_mmio_base) != 0) {
        pr_err("Invalid mmio address: %s\n", arg);
        return -EINVAL;
    }

    printk("Parsed my_debug_print_mmio = 0x%llx\n", (unsigned long long)my_debug_mmio_base);
    return 0;
}
early_param("my_debug_print_mmio", my_debug_print_parse_mmio);

#if 0
static int __init my_debug_print_early_init(void)
{
	early_base = early_ioremap(my_debug_mmio_base, 4096);
	printk("####### %s early_base:0x%lx\n", __FUNCTION__, early_base);
	if (!early_base) {
		printk("early_ioremap 0x%lx fail\n", my_debug_mmio_base);
		return -EINVAL;
	}

	return 0;
}
early_initcall(my_debug_print_early_init);
#endif
