#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/kernel.h>

#include <linux/smp.h>

struct dsid_cgroup
{
	struct cgroup_subsys_state css;
	uint64_t dsid;
	uint64_t sizes;
	uint64_t freq;
	uint64_t inc;
};

static struct dsid_cgroup *css_dsid(struct cgroup_subsys_state *css)
{
	return css ? container_of(css,struct dsid_cgroup, css) : NULL;
}

static struct cgroup_subsys_state * dsid_css_alloc(struct cgroup_subsys_state *parent)
{
	struct dsid_cgroup *dsid;
	dsid = kzalloc(sizeof(struct dsid_cgroup), GFP_KERNEL);
	if(!dsid)
		return ERR_PTR(-ENOMEM);
	return &dsid->css;
}

static void dsid_css_free(struct cgroup_subsys_state *css)
{		
	kfree(css_dsid(css));
}

static int dsid_can_attach(struct cgroup_taskset *tset)
{
	struct task_struct *task;
	struct cgroup_subsys_state *dst_css;

	cgroup_taskset_for_each(task, dst_css, tset)
	{
		struct dsid_cgroup *dsid_ptr = css_dsid(dst_css);
		task->dsid = dsid_ptr->dsid;
	}
	return 0;
}

static ssize_t dsid_set_write(struct kernfs_open_file *of, char *buf, size_t nbytes, loff_t off)
{
	struct cgroup_subsys_state *css = of_css(of);
	struct dsid_cgroup *dsid = css_dsid(css);
	int err;
	long num;
	struct css_task_iter it;
	struct task_struct *task;
	buf = strstrip(buf);
	err	= kstrtol(buf,10,&num);
	if(err < 0)
		return -EINVAL;
	dsid->dsid = num;
	/*
	struct list_head head = css->cgroup->cset_links;
	struct list_head *cset_link;
	list_for_each(cset_link, &head)
	{
		struct css_set *cset = container_of(cset_link, struct cgrp_cset_link, cset_link)->;

	}*/
	css_task_iter_start(css, 0, &it);
	while((task = css_task_iter_next(&it)))
	{
		task->dsid = dsid->dsid;
	}
	css_task_iter_end(&it);

	return nbytes;
}

static int dsid_set_show(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);
	struct dsid_cgroup *dsid = css_dsid(css);
	seq_printf(sf,"dsid of this group is %d\n",dsid->dsid);
	return 0;
}

#define HART_DSID_OFFSET 1

static volatile uint64_t *cpbase;
uint64_t cp_reg_r(uint64_t dm_reg)
{
    return (uint64_t)*(cpbase + dm_reg);
}

void cp_reg_w(uint64_t dm_reg, uint64_t val)
{
    if (cpbase == NULL) {
        printk("cpbase is NULL\n");
    }
    else {
        *(cpbase + dm_reg) = val;
        //writeq(val, cpbase + dm_reg);
    }
}
void register_cp_mmio(void)
{
	cpbase = ioremap(0x20000, 0x10000);
}

void unregister_cp_mmio(void)
{
	iounmap(cpbase);
}
enum {
	/* Access current dsid */
	CP_REG_DSID_SEL            = 0x0,

	/* Access dsid selector */
	CP_REG_HART_SEL             = 0x1,

	/* Access mem offset with current dsid */
	CP_REG_MEM_OFFSET = 0x2,

	/* Access io offset with current dsid */
	CP_REG_IO_OFFSET = 0x3,

	/* Access waymask with current dsid */
	CP_REG_WAYMASK = 0x4,

	/* Access nohype barrier with current dsid */
	CP_REG_NOHYPE_BARRIER = 0x5,

	/* Access hartnum with current dsid */
	CP_REG_HARTNUM = 0x6,
};

const char *cp_reg_name[] = {
	/* Access dsid selector */
	[CP_REG_DSID_SEL - CP_REG_DSID_SEL] = "dsid_sel",

	/* Access hart selector */
	[CP_REG_HART_SEL - CP_REG_DSID_SEL] = "hart_sel",

	/* Access mem offset with current dsid */
	[CP_REG_MEM_OFFSET - CP_REG_DSID_SEL] = "mem_offset",

	/* Access io offset with current dsid */
	[CP_REG_IO_OFFSET - CP_REG_DSID_SEL] = "io_offset",

	/* Access waymask with current dsid */
	[CP_REG_WAYMASK - CP_REG_DSID_SEL] = "waymask",

	/* Access nohype barrier with current dsid */
	[CP_REG_NOHYPE_BARRIER - CP_REG_DSID_SEL] = "nohype_barrier",

	/* Access hartnum with current dsid */
	[CP_REG_HARTNUM - CP_REG_DSID_SEL] = "hartnum",

};

#define NR(arr) (sizeof(arr) / sizeof(arr[0]))

// waymask,access,miss,usage,sizes,freq,incs,read,write
// cpbase[idx * (1 << proc_dsid_width) + proc_dsid]

static ssize_t dsid_cp_write(struct kernfs_open_file *of, char *buf, size_t nbytes, loff_t off)
{
	struct cgroup_subsys_state *css = of_css(of);
	struct dsid_cgroup *dsid_ptr = css_dsid(css);
	struct css_task_iter it;
	struct task_struct *task;
	int err;
	uint64_t num;
	char *tab = buf;
	char *val = buf;
	while(*val != ' ') {
		if(*val++ == '\0')
		{
			printk("error, input format is: table_name hex_val \n");
			return -EINVAL;
		}
    }
	*val='\0';
	err	= kstrtou32(++val, 16, &num);
	if (err < 0) {
		return -EINVAL;
    }

    int i;
    for (i = 0; i < NR(cp_reg_name); i++) {
        const char *name = cp_reg_name[i];
        // TODO membase/memmask/hartid uses hartsel for indexing
        if (name && strcmp(name, buf) == 0) {
            cp_reg_w(CP_REG_DSID_SEL - CP_REG_DSID_SEL, dsid_ptr->dsid);
            cp_reg_w(i, num);
            return nbytes;
        }
    }

    printk("please input correct table name:\n");
    for (i = 0; i < NR(cp_reg_name); i++) {
        const char *name = cp_reg_name[i];
        if (name && strcmp(name,"N/A")) {
            printk("%s ", name);
        }
    }
    printk("\n");
    return -EINVAL;
}

static ssize_t dsid_core_cp_write(struct kernfs_open_file *of, char *buf, size_t nbytes, loff_t off)
{
	struct cgroup_subsys_state *css = of_css(of);
	struct dsid_cgroup *dsid_ptr = css_dsid(css);
	struct css_task_iter it;
	struct task_struct *task;
	uint64_t num;
	uint64_t id;
	char *val = buf;
	while(*val != ' ') {
		if(*val++ == '\0')
		{
			printk("error, input format is: table_name hex_val id_val \n");
			return -EINVAL;
		}
    }
	*(val++)='\0';
	char* id_val = val;
	while(*id_val != ' ') {
		if(*id_val++ == '\0')
		{
			printk("error, input format is: table_name hex_val id_val \n");
			return -EINVAL;
		}
    }
	*(id_val++)='\0';
	if (kstrtou32(val, 16, &num) < 0) {
		return -EINVAL;
    }
	if (kstrtou32(id_val, 16, &id) < 0) {
		return -EINVAL;
    }

    int i;
    for (i = 0; i < NR(cp_reg_name); i++) {
        const char *name = cp_reg_name[i];
        // TODO membase/memmask/hartid uses hartsel for indexing
        if (name && strcmp(name, buf) == 0) {
            cp_reg_w(CP_REG_DSID_SEL - CP_REG_DSID_SEL, id);
            cp_reg_w(i, num);
            return nbytes;
        }
    }

    printk("please input correct table name:\n");
    for (i = 0; i < NR(cp_reg_name); i++) {
        const char *name = cp_reg_name[i];
        if (name && strcmp(name,"N/A")) {
            printk("%s ", name);
        }
    }
    printk("\n");
    return -EINVAL;
}


static int dsid_cp_show(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);
	struct dsid_cgroup *dsid_ptr = css_dsid(css);
	int proc_dsid = dsid_ptr->dsid;

    cp_reg_w(CP_REG_DSID_SEL, dsid_ptr->dsid);
	seq_printf(sf,"dsid of this group:%d\n",proc_dsid);

    int i;
    for (i = 0; i < NR(cp_reg_name); i++) {
        const char *name = cp_reg_name[i];
        if (name && strcmp(name,"N/A")) {
            seq_printf(sf, "%s: 0x%x\n", name, cp_reg_r(i));
        }
    }

	return 0;
}

static struct cftype dsid_files[] =
{
	{
		.name = "dsid-set",
		.write = dsid_set_write,
		.seq_show = dsid_set_show,
	},
	{
		.name = "dsid-cp",
		.write = dsid_cp_write,
		.seq_show = dsid_cp_show,
	},
	{
		.name = "dsid-anyid-cp",
		.write = dsid_core_cp_write,
		.seq_show = dsid_cp_show,
	},
	{}//null terminator
	
};



struct cgroup_subsys dsid_cgrp_subsys =
{
	.css_alloc = dsid_css_alloc,
	.css_free = dsid_css_free,
	.can_attach = dsid_can_attach,
//	.free = dsid_free,
	.legacy_cftypes = dsid_files,
	.dfl_cftypes = dsid_files,
};
