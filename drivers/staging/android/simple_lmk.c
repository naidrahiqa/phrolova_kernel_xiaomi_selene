#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/vmstat.h>
#include <linux/oom.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/printk.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/jiffies.h>

#define SIMPLE_LMK_VERSION "1.0.6"
#define LMK_DEFAULT_MIN_FREE	500
#define LMK_CHECK_INTERVAL_MS	100
#define LMK_MAX_KILLS_PER_CHECK	8
#define LMK_BOOT_DELAY_SECS	15

static unsigned long lmk_min_free_mb = LMK_DEFAULT_MIN_FREE;
static unsigned long lmk_check_interval = LMK_CHECK_INTERVAL_MS;
static unsigned long lmk_debug = 0;
static bool lmk_enabled = true;

static struct task_struct *lmk_task;
static struct kobject *lmk_kobj;
static unsigned long lmk_boot_time;

static bool lmk_is_critical_process(struct task_struct *p)
{
	static const char * const critical_names[] = {
		"system_server",
		"zygote64",
		"zygote",
		"surfaceflinger",
		"servicemanager",
		"vold",
		"installd",
		"logd",
		"lmkd",
		"adbd",
		"shell",
		NULL
	};
	const char * const *name;

	for (name = critical_names; *name; name++) {
		if (strncmp(p->comm, *name, TASK_COMM_LEN) == 0)
			return true;
	}
	return false;
}

static unsigned long lmk_get_free_mb(void)
{
	unsigned long free_pages = global_zone_page_state(NR_FREE_PAGES);
	return free_pages >> (20 - PAGE_SHIFT);
}

static struct task_struct *lmk_find_best_victim(void)
{
	struct task_struct *p;
	struct task_struct *victim = NULL;
	short min_score = 0;
	unsigned long max_rss = 0;

	rcu_read_lock();
	for_each_process(p) {
		struct signal_struct *sig;
		struct mm_struct *mm;
		short oom_score_adj;
		unsigned long rss;

		if (p->flags & PF_KTHREAD)
			continue;
		if (is_global_init(p))
			continue;
		if (lmk_is_critical_process(p))
			continue;

		sig = p->signal;
		if (!sig)
			continue;
		oom_score_adj = sig->oom_score_adj;
		if (oom_score_adj < 0)
			continue;

		mm = get_task_mm(p);
		if (!mm)
			continue;

		rss = get_mm_rss(mm);
		mmput(mm);

		if (!victim || oom_score_adj > min_score ||
		    (oom_score_adj == min_score && rss > max_rss)) {
			if (victim)
				put_task_struct(victim);
			get_task_struct(p);
			victim = p;
			min_score = oom_score_adj;
			max_rss = rss;
		}
	}
	rcu_read_unlock();

	return victim;
}

static void lmk_kill_process(struct task_struct *p)
{
	if (!p)
		return;

	pr_info("simple_lmk: killing %s pid=%d adj=%hd rss=%luMB\n",
		p->comm, task_pid_nr(p), p->signal->oom_score_adj,
		get_mm_rss(p->mm) >> (20 - PAGE_SHIFT));

	send_sig(SIGKILL, p, 0);
}

static int lmk_do_check(void *data)
{
	unsigned long free_mb;
	struct task_struct *victim;
	int kills;

	while (!kthread_should_stop()) {
		set_current_state(TASK_RUNNING);

		if (lmk_enabled && time_after(jiffies, lmk_boot_time)) {
			free_mb = lmk_get_free_mb();

			if (free_mb < lmk_min_free_mb) {
				kills = 0;
				while (free_mb < lmk_min_free_mb &&
				       kills < LMK_MAX_KILLS_PER_CHECK) {
					victim = lmk_find_best_victim();
					if (!victim)
						break;
					lmk_kill_process(victim);
					put_task_struct(victim);
					kills++;
					free_mb = lmk_get_free_mb();
				}
				if (lmk_debug)
					pr_debug("simple_lmk: free=%luMB threshold=%luMB killed=%d\n",
						 free_mb, lmk_min_free_mb, kills);
			}
		}

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(lmk_check_interval));
	}
	return 0;
}

static ssize_t min_free_mb_show(struct kobject *kobj, struct kobj_attribute *attr,
				char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%lu\n", lmk_min_free_mb);
}

static ssize_t min_free_mb_store(struct kobject *kobj, struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	int ret = kstrtoul(buf, 10, &lmk_min_free_mb);
	return ret ? ret : count;
}

static ssize_t check_interval_ms_show(struct kobject *kobj, struct kobj_attribute *attr,
				      char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%lu\n", lmk_check_interval);
}

static ssize_t check_interval_ms_store(struct kobject *kobj, struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	int ret = kstrtoul(buf, 10, &lmk_check_interval);
	if (ret)
		return ret;
	if (lmk_check_interval < 50)
		lmk_check_interval = 50;
	return count;
}

static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", lmk_enabled ? 1 : 0);
}

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	int ret;
	bool val;
	ret = kstrtobool(buf, &val);
	if (ret)
		return ret;
	lmk_enabled = val;
	return count;
}

static ssize_t kill_now_store(struct kobject *kobj, struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	struct task_struct *victim = lmk_find_best_victim();
	if (victim) {
		lmk_kill_process(victim);
		put_task_struct(victim);
	}
	return count;
}

static struct kobj_attribute min_free_attr = __ATTR_RW(min_free_mb);
static struct kobj_attribute check_interval_attr = __ATTR_RW(check_interval_ms);
static struct kobj_attribute enabled_attr = __ATTR_RW(enabled);
static struct kobj_attribute kill_now_attr = __ATTR_WO(kill_now);

static struct attribute *lmk_attrs[] = {
	&min_free_attr.attr,
	&check_interval_attr.attr,
	&enabled_attr.attr,
	&kill_now_attr.attr,
	NULL,
};

static struct attribute_group lmk_attr_group = {
	.attrs = lmk_attrs,
};

static int __init simple_lmk_init(void)
{
	int ret;

	lmk_kobj = kobject_create_and_add("simple_lmk", kernel_kobj);
	if (!lmk_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(lmk_kobj, &lmk_attr_group);
	if (ret) {
		kobject_put(lmk_kobj);
		return ret;
	}

	lmk_boot_time = jiffies + (LMK_BOOT_DELAY_SECS * HZ);

	lmk_task = kthread_run(lmk_do_check, NULL, "simple_lmk");
	if (IS_ERR(lmk_task)) {
		sysfs_remove_group(lmk_kobj, &lmk_attr_group);
		kobject_put(lmk_kobj);
		return PTR_ERR(lmk_task);
	}

	pr_info("simple_lmk: v%s loaded (min_free=%luMB, check_interval=%lums, boot_delay=%ds)\n",
		SIMPLE_LMK_VERSION, lmk_min_free_mb, lmk_check_interval, LMK_BOOT_DELAY_SECS);
	return 0;
}

static void __exit simple_lmk_exit(void)
{
	if (lmk_task)
		kthread_stop(lmk_task);
	sysfs_remove_group(lmk_kobj, &lmk_attr_group);
	kobject_put(lmk_kobj);
	pr_info("simple_lmk: unloaded\n");
}

module_init(simple_lmk_init);
module_exit(simple_lmk_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Simple Low Memory Killer");
MODULE_VERSION(SIMPLE_LMK_VERSION);

module_param_named(debug, lmk_debug, ulong, 0664);
module_param_named(min_free_mb, lmk_min_free_mb, ulong, 0664);
module_param_named(check_interval_ms, lmk_check_interval, ulong, 0664);
