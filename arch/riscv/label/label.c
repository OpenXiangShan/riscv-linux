#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/pid.h>

static char *input;
static char *output = "The dsid dife is empty";
static int parameter[4];  

static int convert(char *s, int* a)
{
    int t = 0, i = 0, r = 0;
    while(1)
    {
        if(s[i] == ' ' || s[i] == 0)
        {
            a[t++] = r;
            r = 0;
			if(t == 3) break;
        }
        else if(s[i] <= '9' && s[i] >= '0')
        {
            r = r*10 + s[i] - '0';
        }
        if(s[i] == 0) break;
        i++;
    }
    return t;
}

static int dsid_file_show(struct seq_file *m,void *v)
{
	seq_printf(m,"%s\n",output);
	return 0;
}

static ssize_t dsid_file_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos)
{
	int para_num;
	char *tmp = kzalloc((count+1), GFP_KERNEL);  
	struct task_struct *task;
	if (!tmp)
	{
		return -ENOMEM; 
	} 
    if (copy_from_user(tmp, buffer, count)) 
	{
		kfree(tmp);
		return -EFAULT;
	}
	kfree(input);
   	input = tmp;
//	para_num = convert(input,a);
	para_num = sscanf(input,"%d %d %d",parameter,parameter+1,parameter+2);
//
	if(para_num == 2 && parameter[1] == 0)
	{
		rcu_read_lock();
		//task = find_task_by_vpid(a[0]);
		task = pid_task(find_vpid(parameter[0]), PIDTYPE_PID);
		rcu_read_unlock();
		if (!task)
		{
			output = "No such process,write/read failed!";
			return -ESRCH;
		}
		sprintf(output,"Read done!Process %d's dsid is %d",parameter[0],task->dsid);
		printk("read dsid,is %d\n",task->dsid);
	}
	else if(para_num == 3 && parameter[1] == 1)
	{
		rcu_read_lock();
		//task = find_task_by_vpid(a[0]);
		task = pid_task(find_vpid(parameter[0]), PIDTYPE_PID);
		rcu_read_unlock();
		if (!task)
		{
			output = "No such process,write/read failed!";
			return -ESRCH;
		}
		task->dsid = parameter[2];
		sprintf(output,"Write done!Now process %d's dsid is %d",parameter[0],task->dsid);
		printk("write dsis,now dsid is %d\n",task->dsid);
	}
	else
	{
		output = "Parameter error,write/read failed!";
		printk("parameter error\n");
		printk("num = %d,%d %d %d",para_num,parameter[0],parameter[1],parameter[2]);
	}
	return count;  
}

static int dsid_file_open(struct inode *inode, struct file *file)  
{  
	    return single_open(file, dsid_file_show, NULL);  
}  
static const struct proc_ops dsidfile = 
{
	.proc_open    = dsid_file_open,
	.proc_read    = seq_read,
	.proc_release = single_release,  
	.proc_lseek  = seq_lseek,  
	.proc_write   = dsid_file_write,
};

extern void register_cp_mmio(void);
extern void unregister_cp_mmio(void);

static int __init label_init(void)
{
	struct proc_dir_entry *dsid = proc_create("dsid",0,NULL,&dsidfile);
	if(!dsid)
	{
		return -ENOMEM;
	}
	register_cp_mmio();
	printk("Label module installed!\n");
	return 0;
}

static void __exit label_exit(void)
{
	unregister_cp_mmio();
	printk("Label module uninstalled!\n");
	remove_proc_entry("dsid", NULL);
	return;
}

module_init(label_init);
module_exit(label_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chang Zihao");
MODULE_DESCRIPTION("A label task_struct Module");
