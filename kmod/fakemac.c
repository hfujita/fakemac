#include <linux/kernel.h>
#include <linux/if_ether.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/hash.h>
#include <linux/etherdevice.h>
#include <linux/notifier.h>

#include <net/neighbour.h>

struct hh_cache;

MODULE_LICENSE("GPL");

#define STORE_HTBITS 8
#define STORE_HTSIZE (1 << STORE_HTBITS)

/* Check linux/sysctl.h for conflict with CTL_NET names */
#define NET_FAKEMAC 333

#define dprintk(args...) printk(args)

struct fakemac_ops_store {
	struct list_head list;
	struct net_device *dev;
	struct rcu_head rcu;
	int count;

	struct header_ops ops;
	const struct header_ops *orig_ops;
	u8 fakeaddr[ETH_ALEN];

	struct ctl_table_header *sysctl_header;
	struct ctl_table sysctl_table[2];
	char *dev_name;
	int enabled;
};

static struct list_head ethdevops_stores[STORE_HTSIZE];
static spinlock_t ethdevops_stores_lock[STORE_HTSIZE];
static struct kmem_cache *store_cachep;

static inline int ethdev_hash(const struct net_device *dev)
{
	/* unsigned long hash = hash_ptr(dev, STORE_HTBITS); */
	return (((unsigned long)dev) >> 4) % STORE_HTSIZE;
}

static struct fakemac_ops_store *find_store(const struct net_device *dev)
{
	struct fakemac_ops_store *e;
	int hash = ethdev_hash(dev);

	rcu_read_lock();
	list_for_each_entry_rcu(e, &ethdevops_stores[hash], list) {
		if (e->dev == dev) {
			rcu_read_unlock();
			return e;
		}
	}
	rcu_read_unlock();

	return NULL;
}

static int add_store(struct net_device *dev, struct fakemac_ops_store **re)
{
	int ret = 0;
	struct fakemac_ops_store *e;
	int hash = ethdev_hash(dev);
	spinlock_t *lock = &ethdevops_stores_lock[hash];

	spin_lock(lock);

	list_for_each_entry_rcu(e, &ethdevops_stores[hash], list) {
		if (e->dev == dev) {
			/* Already exists */
			e = NULL;
			ret = -EEXIST;
			goto out;
		}
	}

	e = kmem_cache_alloc(store_cachep, GFP_ATOMIC);
	if (e == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	e->dev      = dev;
	e->orig_ops = dev->header_ops;
	e->enabled  = 0;
	e->count    = 1;
	memset(&e->ops, 0, sizeof(e->ops));

	list_add_rcu(&e->list, &ethdevops_stores[hash]);

out:
	spin_unlock(lock);

	*re = e;

	return ret;
}

static void free_store_rcu(struct rcu_head *rcu)
{
	struct fakemac_ops_store *e;

	e = container_of(rcu, struct fakemac_ops_store, rcu);

	kmem_cache_free(store_cachep, e);
}

static void __del_store(struct fakemac_ops_store *e)
{
	list_del_rcu(&e->list);
	call_rcu(&e->rcu, free_store_rcu);
}

static void del_store(struct fakemac_ops_store *e)
{
	int hash = ethdev_hash(e->dev);
	spinlock_t *lock = &ethdevops_stores_lock[hash];

	spin_lock(lock);
	if (--e->count == 0)
		__del_store(e);
	spin_unlock(lock);
}

static int fake_eth_header(struct sk_buff *skb, struct net_device *dev,
			   unsigned short type,
			   const void *daddr, const void *saddr,
			   unsigned len)
{
	struct fakemac_ops_store *e = find_store(dev);

	BUG_ON(e == NULL);

	return e->orig_ops->create(skb, dev, type, daddr, e->fakeaddr, len);
}

static int fake_eth_rebuild_header(struct sk_buff *skb)
{
	struct fakemac_ops_store *e = find_store(skb->dev);
	int ret;
	struct ethhdr *eth = (struct ethhdr *) skb->data;

	BUG_ON(e == NULL);

	ret = e->orig_ops->rebuild(skb);
	memcpy(eth->h_source, e->fakeaddr, ETH_ALEN);

	return ret;
}

static int fake_eth_header_cache(const struct neighbour *neigh,
				 struct hh_cache *hh)
{
	int ret = 0;
	struct ethhdr *eth;
	struct fakemac_ops_store *e;

	BUG_ON(neigh == NULL);
	BUG_ON(neigh->dev == NULL);

	e = find_store(neigh->dev);

	BUG_ON(e == NULL);

	if (e->orig_ops->cache) {
		ret = e->orig_ops->cache(neigh, hh);
		if (ret)
			return ret;

		BUG_ON(hh == NULL);
		BUG_ON(hh->hh_data == NULL);

		eth = (struct ethhdr *)
			(((u8 *) hh->hh_data) + (HH_DATA_OFF(sizeof(*eth))));

		memcpy(eth->h_source, e->fakeaddr, sizeof(e->fakeaddr));
	}

	return ret;
}

static void inject_netdev_ops(struct fakemac_ops_store *store)
{
	int i;

	random_ether_addr(store->fakeaddr);

	printk(KERN_INFO "fakemac: injecting ops to %s: fakeaddr=%02x",
	       store->dev_name, store->fakeaddr[0]);
	for (i = 1; i < ETH_ALEN; i++)
		printk(":%02x", store->fakeaddr[i]);
	printk("\n");

	/*
	  Some network device (e.g. tun) leaves header_ops NULL.
	 */
	if (store->orig_ops) {
		store->ops = *store->orig_ops;
		if (store->orig_ops->create)
			store->ops.create  = fake_eth_header;
		if (store->orig_ops->rebuild)
			store->ops.rebuild = fake_eth_rebuild_header;
		if (store->orig_ops->cache)
			store->ops.cache   = fake_eth_header_cache;
	}

	/* TODO: atomic exchange */
	store->dev->header_ops = &store->ops;
}

static void resume_netdev_ops(struct fakemac_ops_store *e)
{
	dprintk(KERN_INFO "fakemac: resuming ops for %s\n",
		e->dev_name);

	/* TODO: atomic exchange */
	e->dev->header_ops = e->orig_ops;
}

static int fakemac_proc_handler(struct ctl_table *ctl, int write,
				struct file *filp, void __user *buffer,
				size_t *lenp, loff_t *ppos)
{
	int oldval = *(int *)(ctl->data);
	int newval;
	int ret = proc_dointvec(ctl, write, filp, buffer, lenp, ppos);
	struct fakemac_ops_store *st
		= (struct fakemac_ops_store *) ctl->extra1;

	newval =  *(int *)(ctl->data);

	if (write && newval != oldval) {
		if (newval)
			inject_netdev_ops(st);
		else
			resume_netdev_ops(st);
	}

	return ret;
}

/*
 * Basically taken from net/ipv4/devinet.c
 * See __devinet_sysctl_register for details
 */

static int fakemac_register_netdev(struct net *net, struct net_device *dev)
{
	int err;
	struct fakemac_ops_store *ops;
	struct ctl_path ctl_path[] = {
		{ .procname = "net", .ctl_name = CTL_NET, },
		{ .procname = "fakemac", .ctl_name = CTL_UNNUMBERED, },
		{},
	};

	dprintk(KERN_INFO "fakemac_register_netdev: adding %s...\n",
		dev->name);

	err = add_store(dev, &ops);
	if (err < 0)
		return err;

	ops->dev_name = kstrndup(dev->name, IFNAMSIZ, GFP_KERNEL);
	if (ops->dev_name == NULL) {
		err = -ENOBUFS;
		goto out_del_store;
	}

	memset(&ops->sysctl_table, 0, sizeof(ops->sysctl_table));

	ops->sysctl_table[0].data         = &ops->enabled;
	ops->sysctl_table[0].mode         = 0644;
	ops->sysctl_table[0].maxlen       = sizeof(int);
	ops->sysctl_table[0].proc_handler = fakemac_proc_handler;
	ops->sysctl_table[0].procname     = ops->dev_name;
	ops->sysctl_table[0].extra1       = ops;

	ops->sysctl_header =
		register_net_sysctl_table(net, ctl_path, ops->sysctl_table);
	if (ops->sysctl_header == NULL) {
		err = -ENOBUFS;
		goto free_name;
	}

	dprintk(KERN_INFO "fakemac_register_netdev: added successfully: %s\n",
		ops->dev_name);

	return 0;

free_name:
	kfree(ops->dev_name);
out_del_store:
	del_store(ops);

	return err;
}

static void __unregister_netdev(struct fakemac_ops_store *st)
{
	resume_netdev_ops(st);
	unregister_sysctl_table(st->sysctl_header);
	kfree(st->dev_name);

	st->sysctl_header = NULL;
	st->dev_name = NULL;

	del_store(st);
}

static int fakemac_unregister_netdev(struct net_device *dev)
{
	struct fakemac_ops_store *st = find_store(dev);

	if (st == NULL)
		return -ENODEV;

	__unregister_netdev(st);

	return 0;
}

static void fakemac_unregister_all_netdev(void)
{
	int i;

	rtnl_lock();

	rcu_read_lock();

	for (i = 0; i < STORE_HTSIZE; i++) {
		struct fakemac_ops_store *ops;
		struct list_head *head = &ethdevops_stores[i];

		while (ops = list_entry(
			       rcu_dereference(head->next),
			       struct fakemac_ops_store, list),
		       &ops->list != head) {
			__unregister_netdev(ops);
		}
	}

	rcu_read_unlock();

	rtnl_unlock();
}

static int fakemac_netdev_event(struct notifier_block *this,
				unsigned long event,
				void *ptr)
{
	struct net_device *dev = ptr;
	int err;

	ASSERT_RTNL();

	switch (event) {
	case NETDEV_REGISTER:
		dprintk(KERN_INFO "fakemac_netdev_event: "
			"netdev registered\n");
		err = fakemac_register_netdev(dev_net(dev), dev);
		if (err)
			return notifier_from_errno(err);

		break;

	case NETDEV_UNREGISTER:
		dprintk(KERN_INFO "fakemac_netdev_event: "
			"netdev unregistered\n");
		fakemac_unregister_netdev(dev);
		break;

	case NETDEV_CHANGENAME:
		fakemac_unregister_netdev(dev);
		err = fakemac_register_netdev(dev_net(dev), dev);
		if (err)
			return notifier_from_errno(err);
		break;

	default:
		dprintk(KERN_INFO "fakemac_netdev_event: "
			"unhandled event: %04lx\n", event);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block fakemac_netdev_notifier = {
	.notifier_call = fakemac_netdev_event,
};

static int __init fakemac_init(void)
{
	int i;
	int ret = 0;

	store_cachep = kmem_cache_create(
		"fakemac_ops_store", sizeof(struct fakemac_ops_store),
		0,
		0,
		NULL);

	for (i = 0; i < STORE_HTSIZE; i++) {
		INIT_LIST_HEAD(&ethdevops_stores[i]);
		spin_lock_init(&ethdevops_stores_lock[i]);
	}

	if (store_cachep == NULL) {
		printk(KERN_ERR
		       "fakemac: kmem_cache_create(store_cachep) failed\n");
		return -ENOMEM;
	}

	ret = register_netdevice_notifier(&fakemac_netdev_notifier);
	if (ret)
		goto out_cleancachep;

	return 0;

out_cleancachep:
	kmem_cache_destroy(store_cachep);
	return ret;
}

static void fakemac_exit(void)
{
	/*
	  Same as synchronize_net()...
	  Wait for a while in order to ensure that all ethdevops_stores
	  have been deleted.
	*/

	unregister_netdevice_notifier(&fakemac_netdev_notifier);

	fakemac_unregister_all_netdev();

	synchronize_net();

	kmem_cache_destroy(store_cachep);
}

module_init(fakemac_init);
module_exit(fakemac_exit);
