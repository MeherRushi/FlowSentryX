/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* All the packet parsing helper function 
are in the parsing_herlper.h header file */

#include "parsing_helper.h"

/* Map declarations - the pps and Blacklist IP map */


/* Packet parsing till the IP layer and updating the maps
 based on the IP address. Also refreshing the map after every
 60 seconds and shifting the IP to the Blacklist IP map. */

 /* Dropping packets whose IP is in the Blacklist IP map */


