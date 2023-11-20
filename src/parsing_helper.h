/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */

/* 
 * This header file contains parsing functions that are used in the
 * fsx_kern.c program. The functions are marked as __always_inline, 
 * and fully defined in this header file to be included in the BPF
 * program.
 * 
 *  
 * Each helper parses a packet header, including doing bounds checking,
 * and returns the type of its content if succesful, and -1 otherwise.
 * 
 * In our framework, we are only concerned about Ethernet packets, IPv4,
 * IPv6, TCP, UDP and ICMP packets. For Ethernet and IP headers, the content 
 * type is the type of the payload (h_proto for Ethernet, nexthdr for IPv6).
 * For ICMP6 it is ICMP type (though we don't further parse after layer 4 of
 * the network stack). Similarly, for TCP ________________________________
 * 
 * Network Byte Order - Big Endian (By default)
 * Host Byte Order - Little Endian (in my system) [Use the following command
 * to check $time lscpu | grep 'Byte Order']
 * 
 * All return values are in host byte order unless specified. For instance,
 * the h_proto of Ethernet header is in Network Byte Order but the bpf_htons()
 * funciton in the bpf_endian.h header will take care of it.
 * 
 */


#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Header cursor to keep track of the current parsing position */
struct hdr_cursor{
    void *pos;
};

/* Function to parse the Ethernet header (Not considering VLAN) */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)		// Incorrect pointer case
		return -1;

	nh->pos += hdrsize;	//next header has been shifted now
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

/* Function to parse the IPv6 header */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h;
	ip6h = nh->pos;

	/* 
	Boundary Check condition using Pointer arthematic
	When we assign the nh->pos to ipv6hdr_fn structure
	then increamting the pointer by 1 will cause it move
	the size of the pointer. So we effectively check that
	the header lies inside the packet data_end
	 */

	if (ip6h + 1 > data_end)
		return -1;

	// Incrementing the nh->pos pointer using pointer 
	// arthematic once again
	nh->pos = ip6h + 1;

	// Now assign the header to the ip6hdr pointer that
	// we took as argument so that it can be accesed in 
	// in the main function

	*ip6hdr = ip6h;

	/* 
	Now, we return the ip6h->next_header field.
	
	The "Next Header" field in an IPv6 header is an 8-bit field 
	that indicates the type of extension header that follows the
	IPv6 header. It can also indicate the protocols contained 
	within upper-layer packets, such as TCP or UDP or ICMP 
	*/

	return ip6h->nexthdr;  
}

/* Function to parse the IPv4 header */

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct iphdr **iphdr)
{
    struct iphdr *iph;
    iph = nh->pos;

    // Boundary Check
    if(iph + 1 > data_end)
        return -1;

    // Incrementing Pointer
    nh->pos = iph + 1;

    // Assigning the pointer
    *iphdr = iph;

    /* 
     Now we return the iph->protocol field
     
     The "protocol" field in the IP header is an 8-bit number 
     that defines what protocol is used inside the IP packet
     This includes protocols like TCP, UDP and ICMP
     */
    return iph->protocol;
}


/* Function to parse the ICMPv6 header */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h;
	icmp6h = nh->pos;

	//Bound Check
	if (icmp6h +1 > data_end)
		return -1;
	
	nh->pos = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;

}


#endif