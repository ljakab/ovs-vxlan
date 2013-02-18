/*
 * Copyright (c) 2011 Nicira, Inc.
 * Copyright (c) 2013 Cisco Systems, Inc.
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/udp.h>

#include "datapath.h"
#include "tunnel.h"
#include "vport.h"

#define LISP_DST_PORT 4341  /* Well known UDP port for LISP data packets. */


/*
 *  LISP encapsulation header:
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |N|L|E|V|I|flags|            Nonce/Map-Version                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Instance ID/Locator Status Bits               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/**
 * struct lisphdr - LISP header
 * @nonce_present: Flag indicating the presence of a 24 bit nonce value.
 * @locator_status_bits_present: Flag indicating the presence of Locator Status
 *                               Bits (LSB).
 * @solicit_echo_nonce: Flag indicating the use of the echo noncing mechanism.
 * @map_version_present: Flag indicating the use of mapping versioning.
 * @instance_id_present: Flag indicating the presence of a 24 bit Instance ID.
 * @reserved_flags: 3 bits reserved for future flags.
 * @nonce: 24 bit nonce value.
 * @map_version: 24 bit mapping version.
 * @locator_status_bits: Locator Status Bits: 32 bits when instance_id_present
 *                       is not set, 8 bits when it is.
 * @instance_id: 24 bit Instance ID
 */
struct lisphdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8 reserved_flags:3;
	__u8 instance_id_present:1;
	__u8 map_version_present:1;
	__u8 solicit_echo_nonce:1;
	__u8 locator_status_bits_present:1;
	__u8 nonce_present:1;
#else
	__u8 nonce_present:1;
	__u8 locator_status_bits_present:1;
	__u8 solicit_echo_nonce:1;
	__u8 map_version_present:1;
	__u8 instance_id_present:1;
	__u8 reserved_flags:3;
#endif
	union {
		__u8 nonce[3];
		__u8 map_version[3];
	} u1;
	union {
		__be32 locator_status_bits;
		struct {
			__u8 instance_id[3];
			__u8 locator_status_bits;
		} word2;
	} u2;
};

#define LISP_HLEN (sizeof(struct udphdr) + sizeof(struct lisphdr))

static inline int lisp_hdr_len(const struct tnl_mutable_config *mutable,
			       const struct ovs_key_ipv4_tunnel *tun_key)
{
	return LISP_HLEN;
}

static inline struct lisphdr *lisp_hdr(const struct sk_buff *skb)
{
	return (struct lisphdr *)(udp_hdr(skb) + 1);
}

static inline struct lisp_net *ovs_get_lisp_net(struct net *net)
{
	struct ovs_net *ovs_net = net_generic(net, ovs_net_id);
	return &ovs_net->vport_net.lisp;
}

/* Compute source port for outgoing packet.
 * Currently we use the flow hash.
 */
static u16 get_src_port(struct sk_buff *skb)
{
	int low;
	int high;
	unsigned int range;
	u32 hash = OVS_CB(skb)->flow->hash;

	inet_get_local_port_range(&low, &high);
	range = (high - low) + 1;
	return (((u64) hash * range) >> 32) + low;
}

static int lisp_tnl_send(struct vport *vport, struct sk_buff *skb)
{
	int network_offset = skb_network_offset(skb);

	/* We only encapsulate IPv4 and IPv6 packets */
	switch (skb->protocol) {
	case htons(ETH_P_IP):
	case htons(ETH_P_IPV6):
		/* Pop off "inner" Ethernet header */
		skb_pull(skb, network_offset);
		return ovs_tnl_send(vport, skb) + network_offset;
	default:
		kfree_skb(skb);
		return 0;
	}
}

/* Convert 64 bit tunnel ID to 24 bit Instance ID. */
static void tunnel_id_to_instance_id(__be64 tun_id, __u8 *iid)
{

#ifdef __BIG_ENDIAN
	iid[0] = (__force __u8)(tun_id >> 16);
	iid[1] = (__force __u8)(tun_id >> 8);
	iid[2] = (__force __u8)tun_id;
#else
	iid[0] = (__force __u8)((__force u64)tun_id >> 40);
	iid[1] = (__force __u8)((__force u64)tun_id >> 48);
	iid[2] = (__force __u8)((__force u64)tun_id >> 56);
#endif
}

/* Convert 24 bit Instance ID to 64 bit tunnel ID. */
static __be64 instance_id_to_tunnel_id(__u8 *iid)
{
#ifdef __BIG_ENDIAN
	return (iid[0] << 16) | (iid[1] << 8) | iid[2];
#else
	return ((__force __be64)iid[0] << 40) | ((__force __be64)iid[1] << 48) |
	       ((__force __be64)iid[2] << 56);
#endif
}

static struct sk_buff *lisp_build_header(const struct vport *vport,
					 const struct tnl_mutable_config *mutable,
					 struct dst_entry *dst,
					 struct sk_buff *skb,
					 int tunnel_hlen)
{
	struct udphdr *udph = udp_hdr(skb);
	struct lisphdr *lisph = (struct lisphdr *)(udph + 1);
	const struct ovs_key_ipv4_tunnel *tun_key = OVS_CB(skb)->tun_key;
	__be64 out_key;
	u32 flags;

	tnl_get_param(mutable, tun_key, &flags, &out_key);

	udph->dest = htons(LISP_DST_PORT);
	udph->source = htons(get_src_port(skb));
	udph->check = 0;
	udph->len = htons(skb->len - skb_transport_offset(skb));

	lisph->nonce_present = 0;	/* We don't support echo nonce algorithm */
	lisph->locator_status_bits_present = 1;	/* Set LSB */
	lisph->solicit_echo_nonce = 0;	/* No echo noncing */
	lisph->map_version_present = 0;	/* No mapping versioning, nonce instead */
	lisph->instance_id_present = 1;	/* Store the tun_id as Instance ID  */
	lisph->reserved_flags = 0;	/* Reserved flags, set to 0  */

	lisph->u1.nonce[0] = 0;
	lisph->u1.nonce[1] = 0;
	lisph->u1.nonce[2] = 0;

	tunnel_id_to_instance_id(out_key, &lisph->u2.word2.instance_id[0]);
	lisph->u2.word2.locator_status_bits = 1;

	/*
	 * Allow our local IP stack to fragment the outer packet even if the
	 * DF bit is set as a last resort.  We also need to force selection of
	 * an IP ID here because Linux will otherwise leave it at 0 if the
	 * packet originally had DF set.
	 */
	skb->local_df = 1;
	__ip_select_ident(ip_hdr(skb), dst, 0);

	return skb;
}

/* Called with rcu_read_lock and BH disabled. */
static int lisp_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct vport *vport;
	struct lisphdr *lisph;
	const struct tnl_mutable_config *mutable;
	struct iphdr *iph, *inner_iph;
	struct ovs_key_ipv4_tunnel tun_key;
	__be64 key;
	u32 tunnel_flags = 0;
	struct ethhdr *ethh;
	__be16 protocol;

	if (unlikely(!pskb_may_pull(skb, LISP_HLEN)))
		goto error;

	lisph = lisp_hdr(skb);

	skb_pull_rcsum(skb, LISP_HLEN);

	if (lisph->instance_id_present != 1)
		key = 0;
	else
		key = instance_id_to_tunnel_id(&lisph->u2.word2.instance_id[0]);

	iph = ip_hdr(skb);
	vport = ovs_tnl_find_port(dev_net(skb->dev), iph->daddr, iph->saddr,
		key, TNL_T_PROTO_LISP, &mutable);
	if (unlikely(!vport))
		goto error;

	if (mutable->flags & TNL_F_IN_KEY_MATCH || !mutable->key.daddr)
		tunnel_flags = OVS_TNL_F_KEY;
	else
		key = 0;

	/* Save outer tunnel values */
	tnl_tun_key_init(&tun_key, iph, key, tunnel_flags);
	OVS_CB(skb)->tun_key = &tun_key;

	/* Drop non-IP inner packets */
	inner_iph = (struct iphdr *)(lisph + 1);
	switch (inner_iph->version) {
	case 4:
		protocol = htons(ETH_P_IP);
		break;
	case 6:
		protocol = htons(ETH_P_IPV6);
		break;
	default:
		goto error;
	}

	/* Add Ethernet header */
	skb_push(skb, ETH_HLEN);

	ethh = (struct ethhdr *)skb->data;
	memset(ethh, 0, ETH_HLEN);
	ethh->h_dest[0] = 0x02;
	ethh->h_source[0] = 0x02;
	ethh->h_proto = protocol;

	ovs_tnl_rcv(vport, skb);
	goto out;

error:
	kfree_skb(skb);
out:
	return 0;
}

/* Arbitrary value.  Irrelevant as long as it's not 0 since we set the handler. */
#define UDP_ENCAP_LISP 1
static int lisp_socket_init(struct net *net)
{
	int err;
	struct lisp_net *lisp_net = ovs_get_lisp_net(net);
	struct sockaddr_in sin;

	if (lisp_net->n_tunnels) {
		lisp_net->n_tunnels++;
		return 0;
	}

	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0,
			       &lisp_net->lisp_rcv_socket);
	if (err)
		goto error;

	/* release net ref. */
	sk_change_net(lisp_net->lisp_rcv_socket->sk, net);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(LISP_DST_PORT);

	err = kernel_bind(lisp_net->lisp_rcv_socket,
			  (struct sockaddr *)&sin,
			  sizeof(struct sockaddr_in));
	if (err)
		goto error_sock;

	udp_sk(lisp_net->lisp_rcv_socket->sk)->encap_type = UDP_ENCAP_LISP;
	udp_sk(lisp_net->lisp_rcv_socket->sk)->encap_rcv = lisp_rcv;

	udp_encap_enable();
	lisp_net->n_tunnels++;

	return 0;

error_sock:
	sk_release_kernel(lisp_net->lisp_rcv_socket->sk);
error:
	pr_warn("cannot register lisp protocol handler: %d\n", err);
	return err;
}

static const struct tnl_ops ovs_lisp_tnl_ops = {
	.tunnel_type	= TNL_T_PROTO_LISP,
	.ipproto	= IPPROTO_UDP,
	.hdr_len	= lisp_hdr_len,
	.build_header	= lisp_build_header,
};

static void release_socket(struct net *net)
{
	struct lisp_net *lisp_net = ovs_get_lisp_net(net);

	lisp_net->n_tunnels--;
	if (lisp_net->n_tunnels)
		return;

	sk_release_kernel(lisp_net->lisp_rcv_socket->sk);
}

static void lisp_tnl_destroy(struct vport *vport)
{
	ovs_tnl_destroy(vport);
	release_socket(ovs_dp_get_net(vport->dp));
}

static struct vport *lisp_tnl_create(const struct vport_parms *parms)
{
	int err;
	struct vport *vport;

	err = lisp_socket_init(ovs_dp_get_net(parms->dp));
	if (err)
		return ERR_PTR(err);

	vport = ovs_tnl_create(parms, &ovs_lisp_vport_ops, &ovs_lisp_tnl_ops);
	if (IS_ERR(vport))
		release_socket(ovs_dp_get_net(parms->dp));

	return vport;
}

const struct vport_ops ovs_lisp_vport_ops = {
	.type		= OVS_VPORT_TYPE_LISP,
	.flags		= VPORT_F_TUN_ID,
	.create		= lisp_tnl_create,
	.destroy	= lisp_tnl_destroy,
	.get_name	= ovs_tnl_get_name,
	.get_options	= ovs_tnl_get_options,
	.set_options	= ovs_tnl_set_options,
	.send		= lisp_tnl_send,
};
#else
#warning LISP tunneling will not be available on kernels before 2.6.26
#endif /* Linux kernel < 2.6.26 */
