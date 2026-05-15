# pa2a-starter

## Info

Name: Albert Ho

PID: A18488268

Email: alh027@ucsd.edu

## Description and Overview
I implemented the router in `sr_router.c`: it parses Ethernet frames, handles ARP, forwards IPv4 using the static table, and sends the ICMP messages the 
assignment asks for (echo reply to the router's own addresses, plus net unreachable, host unreachable, and time exceeded when appropriate). IP and ICMP checksums 
are checked before use and updated after any header change.

`sr_handlepacket` is the main entry. It rejects too-short frames, looks at the Ethernet type, and calls either `handle_arp_packet` or `handle_ip_packet`. On ARP 
requests, `handle_arp_packet` checks that the target IP belongs on the receiving interface; if so, `send_arp_reply` sends a unicast answer. On ARP replies it 
walks any packets that were waiting on that next hop, fills in their Ethernet destination and source for the correct outbound interface, sends them out, and 
clears the wait state. When IP needs forwarding but the next-hop MAC is unknown, `forward_ip_packet` copies the frame onto the right interface, queues it for that
 next hop, and calls `handle_arpreq` so an ARP request goes out. `handle_arpreq` spaces retries by about a second and, after five tries without an answer, sends
ICMP host unreachable back to the original sources. `sr_init` starts `sr_arpreq_sweep_thread`, which wakes up every second, walks the pending ARP list, and calls
 `handle_arpreq` on each entry so those retries still happen even when no new traffic arrives.

For IP, `handle_ip_packet` checks length and the IPv4 checksum. Traffic addressed to one of my interfaces only gets a reply if it is a valid ICMP echo; then 
`send_icmp_echo_reply` swaps the Ethernet and IP fields, flips the ICMP type to echo reply, and fixes checksums. Everything else addressed to me is dropped. 
Transit packets: if TTL is too low to forward, `send_icmp_error` sends time exceeded; otherwise TTL is decremented, the IP checksum is updated, and 
`routing_table_lookup` does an exact match on the destination. With no match, `send_icmp_error` sends net unreachable; with a match, control passes to 
`forward_ip_packet` as in the previous paragraph. `send_icmp_error` builds one ICMP error packet at a time, using the incoming interface's MAC and IP as the outer
 source and copying the inner IP header plus eight bytes of payload into the ICMP body.
