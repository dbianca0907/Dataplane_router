#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*void send_echo_reply(int interface, char *buf, size_t len) {
	struct ether_header *old_eth = (struct ether_header *) buf;
	struct iphdr *old_ip = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct icmphdr *old_icmp = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));


	//uint8_t *mac = old_eth->ether_dhost;
	uint8_t *mac = (uint8_t *) malloc(6);
	memcpy(mac, old_eth->ether_dhost, 6);
	memcpy(old_eth->ether_dhost, old_eth->ether_shost, 6);
	memcpy(old_eth->ether_shost, mac, 6);

	uint32_t ip = old_ip->saddr;
	old_ip->saddr = old_ip->daddr;
	old_ip->daddr = ip;
	old_ip->ttl = 64;
	old_ip->check = 0;
	old_ip->check = htons(checksum((uint16_t*)old_ip, sizeof(struct iphdr)));

	old_icmp->type = 0;
	old_icmp->checksum = 0;
	old_icmp->checksum = htons(checksum((uint16_t*)old_icmp, sizeof(struct icmphdr)));

	send_to_link(interface, buf, len);
}*/

void send_echo_message(int interface, char *buf, size_t len, int type) {
	struct ether_header *old_eth = (struct ether_header *) buf;
	struct iphdr *old_ip = (struct iphdr *) (buf + sizeof(struct ether_header));

	//uint8_t *mac = old_eth->ether_dhost;
	uint8_t *mac = (uint8_t *) malloc(6);
	memcpy(mac, old_eth->ether_dhost, 6);
	memcpy(old_eth->ether_dhost, old_eth->ether_shost, 6);
	memcpy(old_eth->ether_shost, mac, 6);

	uint32_t ip = old_ip->saddr;
	old_ip->saddr = old_ip->daddr;
	old_ip->daddr = ip;
	old_ip->ttl = 64;
	old_ip->check = 0;
	old_ip->check = htons(checksum((uint16_t*)old_ip, sizeof(struct iphdr)));

	if (type == 0) {
		struct icmphdr *old_icmp = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
		old_icmp->type = 0;
		old_icmp->checksum = 0;
		old_icmp->checksum = htons(checksum((uint16_t*)old_icmp, sizeof(struct icmphdr)));
		send_to_link(interface, buf, len);
	} else {
		struct icmphdr *new_icmp = (struct icmphdr *) malloc(sizeof(struct icmphdr));
		char new_packet[MAX_PACKET_LEN];
		new_icmp->type = type;
		new_icmp->code = 0;
		new_icmp->checksum = 0;
		new_icmp->checksum = htons(checksum((uint16_t*)new_icmp, sizeof(struct icmphdr)));
		memcpy(new_packet, buf, sizeof(struct ether_header) + sizeof(struct iphdr));
		memcpy(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr), 
				new_icmp, sizeof(struct icmphdr));
		size_t new_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
		send_to_link(interface, new_packet, new_len);
	}

}


struct route_table_entry* get_best_route(uint32_t dest_ip, struct route_table_entry *rtable, int rt_size) {

	int indx = -1;
	for (int i = 0; i < rt_size; i++) {
		if ((dest_ip & rtable[i].mask) == (rtable[i].prefix & rtable[i].mask)) {
			if (ntohl(rtable[i].mask) > ntohl(rtable[indx].mask) || indx == -1) {
				indx = i;
			}
			
		}
	}
	if (indx == -1) {
		return NULL;
	}
	return &rtable[indx];
}

void ip_forward(char *packet, size_t len, int interface, struct route_table_entry *rtable,
					int rt_size, struct arp_entry *arp_table, int arp_size) {	
	struct ether_header *eth_hdr = (struct ether_header *) packet;
	struct iphdr *ip_hdr = (struct iphdr *) (packet + sizeof(struct ether_header));

	//verify checksum
	uint16_t checksum_packet = ip_hdr->check;
	ip_hdr->check = 0;
	uint16_t checksum_correct = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));

	if (checksum_packet != checksum_correct) {
		printf("Checksum is not correct!\n");
		return;
	}

	//verify TTl
	if (ip_hdr->ttl <= 1) {
		printf("TTL is not correct!\n");
		send_echo_message(interface, packet, len, 11);
		return;
	}

	//check if it is an icmp packet

	if ((ip_hdr->protocol == IPPROTO_ICMP)) {
		struct icmphdr *icmp_header = (struct icmphdr *) (packet + sizeof(struct ether_header) + sizeof(struct iphdr));
				
		if ((ip_hdr->daddr == inet_addr(get_interface_ip(interface)))
			&& icmp_header->type == 8) {
			printf("I found an ICMP echo request\n");
			//send_echo_reply(interface, packet, len);
			send_echo_message(interface, packet, len, 0);
			return;
		}
	}

	//modify ip packet
	ip_hdr->ttl--;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));

	//find the best route
	struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, rtable, rt_size);

	//Host unreachable
	if (best_route == NULL) {
		printf("Host unreachable!\n");
		send_echo_message(interface, packet, len, 3);
		return;
	}

	//modify ethernet header
	uint8_t *mac_src = (uint8_t *)malloc(6 * sizeof(uint8_t));
	get_interface_mac(best_route->interface, mac_src);
	memcpy(eth_hdr->ether_shost, mac_src, 6);

	//find the mac address of the next hop
	for (int i = 0; i < arp_size; i++) {
		if (arp_table[i].ip == best_route->next_hop) {
			memcpy(eth_hdr->ether_dhost, arp_table[i].mac, 6);
			break;
		}
	}

	send_to_link(best_route->interface, packet, len);
}


int main(int argc, char *argv[]) {

	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "Failed to allocate memory for rtable");

	struct arp_entry *arp_table = (struct arp_entry *)malloc(sizeof(struct arp_entry) * 100000);
	
	int rt_size = read_rtable(argv[1], rtable);
	int arp_size = parse_arp_table("arp_table.txt", arp_table);
	//qsort(rtable, rt_size, sizeof(struct route_table_entry), compare);

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
		if (ntohs(eth_hdr->ether_type) == 0x0800) {
			printf("I found an IPv4 packet!\n");
			ip_forward(buf, len, interface, rtable, rt_size, arp_table, arp_size);
		}
	}
	return 0;
}