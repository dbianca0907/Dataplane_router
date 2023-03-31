#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void send_echo_reply(int interface, char *buf, size_t len) {
	struct ether_header *old_eth = (struct ether_header *) buf;
	struct iphdr *old_ip = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct icmphdr *old_icmp = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));


	uint8_t *mac = old_eth->ether_dhost;
	memcpy(old_eth->ether_dhost, old_eth->ether_shost, 6);
	memcpy(old_eth->ether_shost, mac, 6);

	uint32_t ip = old_ip->saddr;
	old_ip->saddr = old_ip->daddr;
	old_ip->daddr = ip;
	old_ip->check = 0;
	old_ip->check = htons(checksum((uint16_t*)old_ip, sizeof(struct iphdr)));

	old_ip->ttl = 64;
	old_icmp->type = 0;
	old_icmp->checksum = 0;
	old_icmp->checksum = htons(checksum((uint16_t*)old_icmp, sizeof(struct icmphdr)));

	send_to_link(interface, buf, len);
}

void send_icmp_message(struct ether_header *old_eth, struct iphdr *old_ip, int interface, char *buf, int type) {

	struct ether_header *new_eth = (struct ether_header *) malloc(sizeof(struct ether_header));
	struct iphdr *new_ip = (struct iphdr *) malloc(sizeof(struct iphdr));
	struct icmphdr *new_icmp = (struct icmphdr *) malloc(sizeof(struct icmphdr));
	char packet[MAX_PACKET_LEN];
	
	memcpy(new_eth->ether_dhost, old_eth->ether_shost, 6);
	memcpy(new_eth->ether_shost, old_eth->ether_dhost, 6);
	new_eth->ether_type = old_eth->ether_type;
	memcpy(packet, new_eth, sizeof(struct ether_header));

	memcpy(new_ip, old_ip, sizeof(struct iphdr));
	struct in_addr *ip = (struct in_addr *) malloc(sizeof(struct in_addr));
	inet_aton(get_interface_ip(interface), ip);
	new_ip->saddr = ip->s_addr;
	new_ip->daddr = old_ip->saddr;
	new_ip->ttl = 64;
	new_ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
	new_ip->check = 0;
	new_ip->check = htons(checksum((uint16_t*)old_ip, sizeof(struct iphdr)));
	memcpy(packet + sizeof(struct ether_header), new_ip, sizeof(struct iphdr));

	new_icmp->code = 0;
	new_icmp->type = type;
	new_icmp->checksum = 0;
	new_icmp->checksum = htons(checksum((uint16_t*)new_icmp, sizeof(struct icmphdr)));
	
	int offset = sizeof(struct ether_header) + sizeof(struct iphdr);
	memcpy(packet + offset, new_icmp, sizeof(struct icmphdr));
	memcpy(packet + offset + sizeof(struct icmphdr), buf + offset, 64);
	
	/*struct icmphdr *new_icmp2 = (struct icmphdr *) (packet + offset);

	new_icmp2->checksum = htons(checksum((uint16_t*)new_icmp2, sizeof(struct icmphdr) + 64));*/
	
	size_t len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	send_to_link(interface, packet, len);
}

struct route_table_entry* get_next_hop(uint32_t dest_ip, struct route_table_entry *rtable, int rt_size) {
	//need to sort the table first
	int best_indx = -1;
	for (int i = 0; i < rt_size; i++) {
		if ((dest_ip & rtable[i].mask) == rtable[i].prefix) {
			return &rtable[i];
		}
	}
	return NULL;
}

uint8_t get_mac_static(uint32_t ip, struct arp_entry *arp_table, int arp_size, uint8_t *mac) {
	int i;
	for (i = 0; i < arp_size; i++) {
		if (arp_table[i].ip == ip) {
			memcpy(mac, arp_table[i].mac, 6);
			return 1;
		}
	}
	return 0;
}

void forward_ip_packet(struct ether_header *eth, struct iphdr *iph, char *buf, 
						struct route_table_entry *rtable, uint8_t *mac_daddr, size_t len) {

	char packet[MAX_PACKET_LEN];
	struct ether_header *new_eth = (struct ether_header *) malloc(sizeof(struct ether_header));
	struct iphdr *new_iph = (struct iphdr *) malloc(sizeof(struct iphdr));

	uint8_t *mac_interface = (uint8_t *) malloc(6 * sizeof(uint8_t));
	get_interface_mac(rtable->interface, mac_interface);
	
	//print mac address
	printf("MAC address:\n");
	int i;
	for (i = 0; i < 6; i++) {
		printf("%02x", mac_daddr[i]);
		if (i != 5) {
			printf(":");
		}
	}
	printf("\n");

	//construct ethernet header
	memcpy(new_eth->ether_dhost, mac_daddr, 6);
	memcpy(new_eth->ether_shost, mac_interface, 6);
	new_eth->ether_type = eth->ether_type;

	//construct ip header
	memcpy(new_iph, iph, sizeof(struct iphdr));
	new_iph->ttl = iph->ttl - 1;
	new_iph->check = 0;
	new_iph->check = htons(checksum((uint16_t*) new_iph, sizeof(struct iphdr)));

	memcpy(packet, new_eth, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), new_iph, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), 
			buf + sizeof(struct ether_header) + sizeof(struct iphdr), len - sizeof(struct ether_header) - sizeof(struct iphdr));
	
	send_to_link(rtable->interface, packet, len);
}


int main(int argc, char *argv[]) {

	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "Failed to allocate memory for rtable");

	struct arp_entry *arp_table = (struct arp_entry *)malloc(sizeof(struct arp_entry) * 10000);
	
	int rt_size = read_rtable(argv[1], rtable);
	int arp_size = parse_arp_table("arp_table.txt", arp_table);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		//check if the packet is an IPv4 packet
		printf("start of packet\n");

		if (ntohs(eth_hdr->ether_type) == 0x0800) {
			printf("I found an IPv4 packet\n");
			struct iphdr *ip_header = (struct iphdr *) (buf + sizeof(struct ether_header));
			
			printf("source of packet %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
			printf("destination of packet %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr)); 
			
			if ((ip_header->protocol == IPPROTO_ICMP)) {
				struct icmphdr *icmp_header = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				
				if ((ip_header->daddr == inet_addr(get_interface_ip(interface)))
					&& icmp_header->type == 8) {
					printf("I found an ICMP echo request\n");
					send_echo_reply(interface, buf, len);
					break;
				}
			}
			printf("Forwarding the packet\n");

			//verify if the packet is valid
			uint16_t checksum_packet = ip_header->check;
			ip_header->check = 0;
			uint16_t checksum_correct = htons(checksum((uint16_t*)ip_header, sizeof(struct iphdr)));
			if (checksum_correct != checksum_packet) {
				printf("Checksum: %d\n", checksum_packet);
				printf("Checksum correct: %d\n", checksum_correct);
				printf("The packet is invalid\n");
				break;
			}
					
			//check if the TTL is valid
			if (ip_header->ttl <= 1) {
				printf("TTL expired\n");
				//send_icmp_message(eth_hdr, ip_header, interface, buf, 11);
				break;
			} 
			printf("checksum correct\n");
			//search for the next hop in the routing table
			struct route_table_entry *next_hop = get_next_hop(ip_header->daddr, rtable, rt_size);
			if (next_hop == NULL) {
				printf("Host unreachable\n");
				//send_icmp_message(eth_hdr, ip_header, interface, buf, 3);
				break;
			}
			//search for the interface to send the packet
			uint8_t mac_daddr;
			get_mac_static(next_hop->next_hop, arp_table, arp_size, &mac_daddr);
			//make ipv4 packet
			forward_ip_packet(eth_hdr, ip_header, buf, next_hop, &mac_daddr, len);
		} else {
			printf("I found a non-IPv4 packet\n");
		}
	}
	return 0;
}