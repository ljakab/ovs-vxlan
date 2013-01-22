/*
 * Copyright (c) 2007-2012 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef VPORT_H
#define VPORT_H 1

#include <linux/list.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/u64_stats_sync.h>

#include "vport-capwap.h"

struct vport;
struct vport_parms;

struct vport_net {
	struct capwap_net capwap;
};

/* The following definitions are for users of the vport subsytem: */

int ovs_vport_init(void);
void ovs_vport_exit(void);

struct vport *ovs_vport_add(const struct vport_parms *);
void ovs_vport_del(struct vport *);

struct vport *ovs_vport_locate(struct net *net, const char *name);

int ovs_vport_set_addr(struct vport *, const unsigned char *);
void ovs_vport_set_stats(struct vport *, struct ovs_vport_stats *);
void ovs_vport_get_stats(struct vport *, struct ovs_vport_stats *);

int ovs_vport_set_options(struct vport *, struct nlattr *options);
int ovs_vport_get_options(const struct vport *, struct sk_buff *);

int ovs_vport_send(struct vport *, struct sk_buff *);

/* The following definitions are for implementers of vport devices: */

struct vport_percpu_stats {
	u64 rx_bytes;
	u64 rx_packets;
	u64 tx_bytes;
	u64 tx_packets;
	struct u64_stats_sync sync;
};

struct vport_err_stats {
	u64 rx_dropped;
	u64 rx_errors;
	u64 tx_dropped;
	u64 tx_errors;
};

/**
 * struct vport - one port within a datapath
 * @rcu: RCU callback head for deferred destruction.
 * @dp: Datapath to which this port belongs.
 * @linkname: The name of the link from /sys/class/net/<datapath>/brif to this
 * &struct vport.  (We keep this around so that we can delete it if the
 * device gets renamed.)  Set to the null string when no link exists.
 * @upcall_portid: The Netlink port to use for packets received on this port that
 * miss the flow table.
 * @port_no: Index into @dp's @ports array.
 * @hash_node: Element in @dev_table hash table in vport.c.
 * @dp_hash_node: Element in @datapath->ports hash table in datapath.c.
 * @ops: Class structure.
 * @percpu_stats: Points to per-CPU statistics used and maintained by vport
 * @stats_lock: Protects @err_stats and @offset_stats.
 * @err_stats: Points to error statistics used and maintained by vport
 * @offset_stats: Added to actual statistics as a sop to compatibility with
 * XAPI for Citrix XenServer.  Deprecated.
 */
struct vport {
	struct rcu_head rcu;
	struct datapath	*dp;
	char linkname[IFNAMSIZ];
	u32 upcall_portid;
	u16 port_no;

	struct hlist_node hash_node;
	struct hlist_node dp_hash_node;
	const struct vport_ops *ops;

	struct vport_percpu_stats __percpu *percpu_stats;

	spinlock_t stats_lock;
	struct vport_err_stats err_stats;
	struct ovs_vport_stats offset_stats;
};

#define VPORT_F_REQUIRED	(1 << 0) /* If init fails, module loading fails. */
#define VPORT_F_FLOW		(1 << 1) /* Sets OVS_CB(skb)->flow. */
#define VPORT_F_TUN_ID		(1 << 2) /* Sets OVS_CB(skb)->tun_id. */

/**
 * struct vport_parms - parameters for creating a new vport
 *
 * @name: New vport's name.
 * @type: New vport's type.
 * @options: %OVS_VPORT_ATTR_OPTIONS attribute from Netlink message, %NULL if
 * none was supplied.
 * @dp: New vport's datapath.
 * @port_no: New vport's port number.
 */
struct vport_parms {
	const char *name;
	enum ovs_vport_type type;
	struct nlattr *options;

	/* For ovs_vport_alloc(). */
	struct datapath *dp;
	u16 port_no;
	u32 upcall_portid;
};

/**
 * struct vport_ops - definition of a type of virtual port
 *
 * @type: %OVS_VPORT_TYPE_* value for this type of virtual port.
 * @flags: Flags of type VPORT_F_* that influence how the generic vport layer
 * handles this vport.
 * @init: Called at module initialization.  If VPORT_F_REQUIRED is set then the
 * failure of this function will cause the module to not load.  If the flag is
 * not set and initialzation fails then no vports of this type can be created.
 * @exit: Called at module unload.
 * @create: Create a new vport configured as specified.  On success returns
 * a new vport allocated with ovs_vport_alloc(), otherwise an ERR_PTR() value.
 * @destroy: Destroys a vport.  Must call vport_free() on the vport but not
 * before an RCU grace period has elapsed.
 * @set_options: Modify the configuration of an existing vport.  May be %NULL
 * if modification is not supported.
 * @get_options: Appends vport-specific attributes for the configuration of an
 * existing vport to a &struct sk_buff.  May be %NULL for a vport that does not
 * have any configuration.
 * @set_addr: Set the device's MAC address.  May be null if not supported.
 * @get_name: Get the device's name.
 * @get_addr: Get the device's MAC address.
 * @get_config: Get the device's configuration.
 * @get_ifindex: Get the system interface index associated with the device.
 * May be null if the device does not have an ifindex.
 * @send: Send a packet on the device.  Returns the length of the packet sent.
 */
struct vport_ops {
	enum ovs_vport_type type;
	u32 flags;

	/* Called at module init and exit respectively. */
	int (*init)(void);
	void (*exit)(void);

	/* Called with RTNL lock. */
	struct vport *(*create)(const struct vport_parms *);
	void (*destroy)(struct vport *);

	int (*set_options)(struct vport *, struct nlattr *);
	int (*get_options)(const struct vport *, struct sk_buff *);

	int (*set_addr)(struct vport *, const unsigned char *);

	/* Called with rcu_read_lock or RTNL lock. */
	const char *(*get_name)(const struct vport *);
	const unsigned char *(*get_addr)(const struct vport *);
	void (*get_config)(const struct vport *, void *);
	int (*get_ifindex)(const struct vport *);
	int (*send)(struct vport *, struct sk_buff *);
};

enum vport_err_type {
	VPORT_E_RX_DROPPED,
	VPORT_E_RX_ERROR,
	VPORT_E_TX_DROPPED,
	VPORT_E_TX_ERROR,
};

struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *,
			      const struct vport_parms *);
void ovs_vport_free(struct vport *);

#define VPORT_ALIGN 8

/**
 *	vport_priv - access private data area of vport
 *
 * @vport: vport to access
 *
 * If a nonzero size was passed in priv_size of vport_alloc() a private data
 * area was allocated on creation.  This allows that area to be accessed and
 * used for any purpose needed by the vport implementer.
 */
static inline void *vport_priv(const struct vport *vport)
{
	return (u8 *)vport + ALIGN(sizeof(struct vport), VPORT_ALIGN);
}

/**
 *	vport_from_priv - lookup vport from private data pointer
 *
 * @priv: Start of private data area.
 *
 * It is sometimes useful to translate from a pointer to the private data
 * area to the vport, such as in the case where the private data pointer is
 * the result of a hash table lookup.  @priv must point to the start of the
 * private data area.
 */
static inline struct vport *vport_from_priv(const void *priv)
{
	return (struct vport *)(priv - ALIGN(sizeof(struct vport), VPORT_ALIGN));
}

void ovs_vport_receive(struct vport *, struct sk_buff *);
void ovs_vport_record_error(struct vport *, enum vport_err_type err_type);

/* List of statically compiled vport implementations.  Don't forget to also
 * add yours to the list at the top of vport.c. */
extern const struct vport_ops ovs_netdev_vport_ops;
extern const struct vport_ops ovs_internal_vport_ops;
extern const struct vport_ops ovs_patch_vport_ops;
extern const struct vport_ops ovs_gre_vport_ops;
extern const struct vport_ops ovs_gre_ft_vport_ops;
extern const struct vport_ops ovs_gre64_vport_ops;
extern const struct vport_ops ovs_capwap_vport_ops;
extern const struct vport_ops ovs_vxlan_vport_ops;
extern const struct vport_ops ovs_lisp_vport_ops;

#endif /* vport.h */
