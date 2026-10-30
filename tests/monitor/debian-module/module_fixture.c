// SPDX-License-Identifier: GPL-2.0-only
/* Verify a module built against the distribution's unmodified headers. */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>

static int fixture_show(struct seq_file *file, void *unused)
{
	seq_printf(file, "module-fixture pid=%d task_size=%zu\n",
		   task_pid_nr(current), sizeof(struct task_struct));
	return 0;
}

static int __init fixture_init(void)
{
	return proc_create_single("module_fixture", 0444, NULL, fixture_show) ? 0 : -ENOMEM;
}

static void __exit fixture_exit(void)
{
	remove_proc_entry("module_fixture", NULL);
}

module_init(fixture_init);
module_exit(fixture_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Distribution module ABI qualification fixture");
