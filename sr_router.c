/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*
	Check Case:
	- ARP Frame (check ethertype)
		- Request:
			- who has IP X?
			- X matches one of router interface IP
			- send back ARP reply w MAX address
			- reply goes to requesters MAC (not broadcast)
		- Reply:
			- responded to ARP request
			- look up pending ARP request in queue
			- forward packets that were waiting on MAC address

	- IP Frame (check ethertype)
		- Validate checksum, minimum length
		- Destination?
			- Router itself?
				- check dest ip matches any interface IP (walk sr->if_list)
				- yes: ICMP echo request w valid checksum -> send ICMP echo reply 
				- else: ignore 
			- Other Router?
				- decrement TTL (hit 0 -> ICMP time exceeded type 11,code 0 back to sender)
				- recompute IP checksum
				- lookup destination in routing table (exact match only - no longest prefix)
				- no match -> send ICMP destination net unreachable (type3, code0)
				- match found -> enqueue packet and send ARP request for next-hop IP

	ARP Request Queue (can't forward packet w/o dest MAC, wait for ARP reply): 
	- packet arrive, need forward -> add to ARP request queue via sr_arpcache_queuereq() -> send ARP req out correct interface
	- every second, sr_arpcache_sweepreqs() called	
		- re-send ARP requests with no reply >1 second
		- 5 failed attempts, drop all queued packets for IP, send ICMP Host unreachable (type3, code1) back to packet original sender
	- ARP reply -> find matching queue entry, forward all waiting packets w/ known MAC, remove from queue

	ICMP Messages: 
	- Ping to router interface type0, code0
	- No route to dest type3, code0
	- ARP timeout after 5 tries type3, code1
	- TTL expired in transit type11, code 0
	- for error msg (type3, 11) payload include original IP header + 8 bytes of original datagram. source of ICMP err should be own router interface IP

	Structs:
	- sr_ethernet_hdr_t: src/dst MAC, ethertype
	- sr_ip_hdr_t: src/dst IP, TTL, protocol, checksum
	- sr_icmp_hdr_t: type, code, checksum, payload
	- sr_arp_hdr_t: opcode, sender/target MAC and IP
	- sr->if_list: linked list of router interfaces
	- sr->routing_table: linked list of routing entries
*/

/* ARP helper */
static void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
static void send_arp_reply(struct sr_instance *sr, sr_arp_hdr_t *req_arp, struct sr_if *iface);
static void send_arp_request(struct sr_instance *sr, uint32_t target_ip, struct sr_if *out_iface);

/* IP helper */
static void handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
static int ip_for_me(struct sr_instance *sr, uint32_t dst_ip, struct sr_if **matched_iface);

/* ICMP helper */
static void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *og_packet, unsigned int og_len, char *in_iface_name);
static void send_icmp_error(struct sr_instance *sr, uint8_t *og_packet, char *in_iface_name, uint8_t type, uint8_t code);

/* Routing/Forward helper */
static struct sr_rt *routing_table_lookup(struct sr_instance *sr, uint32_t dst_ip);
static void forward_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_rt *rt_entry);

/* ARP queue helper */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);

  	/* fill in code here */
	if (len < sizeof(sr_ethernet_hdr_t)) {
		fprintf(stderr, "Packet too short for Ethernet header, dropped\n");
		return;
	}

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
	uint16_t etype = ntohs(eth_hdr->ether_type);

	if (etype == ethertype_arp) {
		handle_arp_packet(sr, packet, len, interface);
	} else if (etype == ethertype_ip) {
		handle_ip_packet(sr, packet, len, interface);
	} else {
		// Drop
	}	

}

/* ARP helper */
static void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
	if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
		fprintf(stderr, "ARP packet too short, dropped\n");
		return;
	}

	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	uint16_t op = ntohs(arp_hdr->ar_op);

	struct sr_if *iface = sr_get_interface(sr, interface);
	if (!iface) return;

	if (op == arp_op_request) {
		if (arp_hdr->ar_tip == iface->ip) {
			send_arp_reply(sr, arp_hdr, iface);
		}
	} else if (op == arp_op_reply) {
		struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

		if (req) {
			struct sr_packet *pkt;
			for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
				struct sr_if *out_if = sr_get_interface(sr, pkt->iface);
				if (!out_if) continue;

				sr_ethernet_hdr_t *fwd_eth = (sr_ethernet_hdr_t*)pkt->buf;
				memcpy(fwd_eth->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
				memcpy(fwd_eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);

				sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
			}
			sr_arpreq_destroy(&sr->cache, req);
		}
	}
}

static void send_arp_reply(struct sr_instance *sr, sr_arp_hdr_t *req_arp, struct sr_if *iface) {
	unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *reply = (uint8_t*)malloc(reply_len);
	memset(reply, 0, reply_len);

	sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t*)reply;
	memcpy(eth->ether_dhost, req_arp->ar_sha, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
	eth->ether_type = htons(ethertype_arp);

	sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
    	arp->ar_hrd = htons(arp_hrd_ethernet);
    	arp->ar_pro = htons(ethertype_ip);
    	arp->ar_hln = ETHER_ADDR_LEN;
    	arp->ar_pln = sizeof(uint32_t);
    	arp->ar_op  = htons(arp_op_reply);
    	memcpy(arp->ar_sha, iface->addr, ETHER_ADDR_LEN); 
    	arp->ar_sip = iface->ip;  
    	memcpy(arp->ar_tha, req_arp->ar_sha, ETHER_ADDR_LEN); 
    	arp->ar_tip = req_arp->ar_sip;
 
    	sr_send_packet(sr, reply, reply_len, iface->name);
    	free(reply);
}

static void send_arp_request(struct sr_instance *sr, uint32_t target_ip, struct sr_if *out_iface) {
	    unsigned int req_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    	uint8_t *req_buf = (uint8_t *)malloc(req_len);
    	memset(req_buf, 0, req_len);
 
    	sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)req_buf;
    	memset(eth->ether_dhost, 0xFF, ETHER_ADDR_LEN);
    	memcpy(eth->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
    	eth->ether_type = htons(ethertype_arp);
 
    sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(req_buf + sizeof(sr_ethernet_hdr_t));
    arp->ar_hrd = htons(arp_hrd_ethernet);
    arp->ar_pro = htons(ethertype_ip);
    arp->ar_hln = ETHER_ADDR_LEN;
    arp->ar_pln = sizeof(uint32_t);
    arp->ar_op  = htons(arp_op_request);
    memcpy(arp->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
    arp->ar_sip = out_iface->ip;
    memset(arp->ar_tha, 0x00, ETHER_ADDR_LEN);
    arp->ar_tip = target_ip;
 
    sr_send_packet(sr, req_buf, req_len, out_iface->name);
    free(req_buf);
}

/* IP helper */
static void handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
	    unsigned int min_ip_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    if (len < min_ip_len) {
        fprintf(stderr, "IP packet too short, dropped\n");
        return;
    }
 
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
 
    uint16_t og_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t calc_cksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    ip_hdr->ip_sum = og_cksum;
 
    if (og_cksum != calc_cksum) {
        fprintf(stderr, "IP checksum mismatch, dropped\n");
        return;
    }
 
    struct sr_if *matched_iface = NULL;
    if (ip_for_me(sr, ip_hdr->ip_dst, &matched_iface)) {
        if (ip_hdr->ip_p == ip_protocol_icmp) {
            sr_icmp_t08_hdr_t *icmp_hdr = (sr_icmp_t08_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr->ip_hl * 4);
 
            unsigned int icmp_len = ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4;
            uint16_t og_icmp_sum = icmp_hdr->icmp_sum;
            icmp_hdr->icmp_sum = 0;
            uint16_t calc_icmp_sum = cksum(icmp_hdr, icmp_len);
            icmp_hdr->icmp_sum = og_icmp_sum;
 
            if (og_icmp_sum != calc_icmp_sum) {
                fprintf(stderr, "ICMP checksum mismatch, dropped\n");
                return;
            }
 
            if (icmp_hdr->icmp_type == 8) {
                send_icmp_echo_reply(sr, packet, len, interface);
            }
        }
        return;
    }
 
    if (ip_hdr->ip_ttl <= 1) {
        send_icmp_error(sr, packet, interface, 11, 0);
        return;
    }
    ip_hdr->ip_ttl--;
 
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
 
    struct sr_rt *rt_entry = routing_table_lookup(sr, ip_hdr->ip_dst);
    if (!rt_entry) {
        send_icmp_error(sr, packet, interface, 3, 0);
        return;
    }

    forward_ip_packet(sr, packet, len, rt_entry);
}

static int ip_for_me(struct sr_instance *sr, uint32_t dst_ip, struct sr_if **matched_iface) {
	struct sr_if *iface;
	for (iface = sr->if_list; iface != NULL; iface = iface->next) {
		if (iface->ip == dst_ip) {
			if (matched_iface) *matched_iface = iface;
			return 1;
		}
	}
	return 0;
}

/* ICMP helper */
static void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *og_packet, unsigned int og_len, char *in_iface_name) {
	sr_ethernet_hdr_t *og_eth = (sr_ethernet_hdr_t*)og_packet;
	sr_ip_hdr_t *og_ip = (sr_ip_hdr_t*)(og_packet + sizeof(sr_ethernet_hdr_t));

	unsigned int reply_len = og_len;
	uint8_t *reply = (uint8_t*)malloc(reply_len);
	memcpy(reply, og_packet, reply_len);

	struct sr_if *in_if = sr_get_interface(sr, in_iface_name);

	sr_ethernet_hdr_t *reply_eth = (sr_ethernet_hdr_t*)reply;
	memcpy(reply_eth->ether_dhost, og_eth->ether_shost, ETHER_ADDR_LEN);
	memcpy(reply_eth->ether_shost, in_if->addr, ETHER_ADDR_LEN);

	sr_ip_hdr_t *reply_ip = (sr_ip_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));
	reply_ip->ip_dst = og_ip->ip_src;
	reply_ip->ip_src = og_ip->ip_dst;
	reply_ip->ip_ttl = INIT_TTL;
	reply_ip->ip_sum = 0;
	reply_ip->ip_sum = cksum(reply_ip, reply_ip->ip_hl * 4);

	sr_icmp_t08_hdr_t *reply_icmp = (sr_icmp_t08_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t) + reply_ip->ip_hl * 4);
	reply_icmp->icmp_type = 0;
	reply_icmp->icmp_code = 0;
	reply_icmp->icmp_sum = 0;
	unsigned int icmp_len = ntohs(reply_ip->ip_len) - reply_ip->ip_hl * 4;
	reply_icmp->icmp_sum = cksum(reply_icmp, icmp_len);

	sr_send_packet(sr, reply, reply_len, in_iface_name);
	free(reply);
}

static void send_icmp_error(struct sr_instance *sr, uint8_t *og_packet, char *in_iface_name, uint8_t type, uint8_t code) {
	sr_ethernet_hdr_t *og_eth = (sr_ethernet_hdr_t *)og_packet;
    sr_ip_hdr_t *og_ip = (sr_ip_hdr_t *)(og_packet + sizeof(sr_ethernet_hdr_t));
 
    struct sr_if *in_if = sr_get_interface(sr, in_iface_name);
    if (!in_if) return;
 
    unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    uint8_t *reply = (uint8_t *)calloc(1, reply_len);
 
    sr_ethernet_hdr_t *reply_eth = (sr_ethernet_hdr_t *)reply;
    memcpy(reply_eth->ether_dhost, og_eth->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth->ether_shost, in_if->addr, ETHER_ADDR_LEN);
    reply_eth->ether_type = htons(ethertype_ip);
 
    sr_ip_hdr_t *reply_ip = (sr_ip_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
    reply_ip->ip_v   = 4;
    reply_ip->ip_hl  = sizeof(sr_ip_hdr_t) / 4;
    reply_ip->ip_tos = 0;
    reply_ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
    reply_ip->ip_id  = 0;
    reply_ip->ip_off = htons(IP_DF);
    reply_ip->ip_ttl = INIT_TTL;
    reply_ip->ip_p   = ip_protocol_icmp;
    reply_ip->ip_src = in_if->ip;
    reply_ip->ip_dst = og_ip->ip_src;
    reply_ip->ip_sum = 0;
    reply_ip->ip_sum = cksum(reply_ip, sizeof(sr_ip_hdr_t));
 
    sr_icmp_t11_hdr_t *reply_icmp = (sr_icmp_t11_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    reply_icmp->icmp_type = type;
    reply_icmp->icmp_code = code;
    reply_icmp->unused    = 0;
 
    unsigned int og_ip_hdr_len = og_ip->ip_hl * 4;
    memcpy(reply_icmp->data, og_ip, og_ip_hdr_len);
    memcpy(reply_icmp->data + og_ip_hdr_len, (uint8_t *)og_ip + og_ip_hdr_len, 8);
 
    reply_icmp->icmp_sum = 0;
    reply_icmp->icmp_sum = cksum(reply_icmp, sizeof(sr_icmp_t11_hdr_t));
 
    sr_send_packet(sr, reply, reply_len, in_if->name);
    free(reply);

}

/* Routing/Forward helper */
static struct sr_rt *routing_table_lookup(struct sr_instance *sr, uint32_t dst_ip) {
	struct sr_rt *entry;
	for (entry = sr->routing_table; entry != NULL; entry = entry->next) {
		if ((entry->dest.s_addr & entry->mask.s_addr) == (dst_ip & entry->mask.s_addr)) {
			return entry;
		} 
	}

	return NULL;
}

static void forward_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_rt *rt_entry) {
	struct sr_if *out_if = sr_get_interface(sr, rt_entry->interface);
	if (!out_if) return;

	uint32_t next_hop_ip = rt_entry->gw.s_addr;
	uint8_t *fwd_packet = (uint8_t*)malloc(len);
	memcpy(fwd_packet, packet, len);

	sr_ethernet_hdr_t *fwd_eth = (sr_ethernet_hdr_t*)fwd_packet;
	memcpy(fwd_eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
	memset(fwd_eth->ether_dhost, 0x00, ETHER_ADDR_LEN);
	fwd_eth->ether_type = htons(ethertype_ip);

	struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, fwd_packet, len, rt_entry->interface);
	free(fwd_packet);

	handle_arpreq(sr, req);
}

/* ARP queue helper */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
	time_t now = time(NULL);

	if (difftime(now, req->sent) < 1.0) {
		return;
	}

	if (req->times_sent >= 5) {
		struct sr_packet *pkt;
		for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
			sr_ip_hdr_t *og_ip = (sr_ip_hdr_t*)(pkt->buf + sizeof(sr_ethernet_hdr_t));
			struct sr_rt *rt = routing_table_lookup(sr, og_ip->ip_src);
			char *return_iface = rt ? rt->interface : pkt->iface;
			send_icmp_error(sr, pkt->buf, return_iface, 3, 1);
		}
		sr_arpreq_destroy(&sr->cache, req);
	} else {
		if (req->packets) {
			struct sr_if *out_if = sr_get_interface(sr, req->packets->iface);
			if (out_if) {
				send_arp_request(sr, req->ip, out_if);
			}
		}
		req->sent = now;
		req->times_sent += 1;
	}
}

/* end sr_ForwardPacket */

