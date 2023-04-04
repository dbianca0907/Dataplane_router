#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct route_table_entry *rtable;
struct arp_entry *arp_table;
int rt_size;
int arp_size;
queue Queue_arp;

struct packet_queue {
	struct route_table_entry *best_route;
	char packet[MAX_PACKET_LEN];
	size_t len;
};

void send_echo_message(int interface, char *buf, size_t len, int type) {
	struct ether_header *old_eth = (struct ether_header *) buf;
	struct iphdr *old_ip = (struct iphdr *) (buf + sizeof(struct ether_header));

	//for TTL and Host Unreachable
	char initial_ip_header[MAX_PACKET_LEN];
	memcpy(initial_ip_header, buf + sizeof(struct ether_header), sizeof(struct iphdr));

	//swap mac addresses
	uint8_t *mac = (uint8_t *) malloc(6);
	memcpy(mac, old_eth->ether_dhost, 6);
	memcpy(old_eth->ether_dhost, old_eth->ether_shost, 6);
	memcpy(old_eth->ether_shost, mac, 6);

	//modify ip header
	uint32_t ip = old_ip->saddr;
	old_ip->saddr = old_ip->daddr;
	old_ip->daddr = ip;
	old_ip->ttl = 64;
	old_ip->check = 0;
	old_ip->check = htons(checksum((uint16_t*)old_ip, sizeof(struct iphdr)));

	if (type == 0) {
		//for icmp echo reply
		struct icmphdr *old_icmp = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
		old_icmp->type = 0;
		old_icmp->checksum = 0;
		old_icmp->checksum = htons(checksum((uint16_t*)old_icmp, sizeof(struct icmphdr)));
		send_to_link(interface, buf, len);
	} else {
		//for TTL and Host Unreachable
		struct icmphdr *new_icmp = (struct icmphdr *) malloc(sizeof(struct icmphdr));
		char new_packet[MAX_PACKET_LEN];
		old_ip->protocol = IPPROTO_ICMP;
		old_ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
		old_ip->check = 0;
		old_ip->check = htons(checksum((uint16_t*)old_ip, sizeof(struct iphdr)));

		new_icmp->type = type;
		new_icmp->code = 0;
		new_icmp->checksum = 0;
		new_icmp->checksum = htons(checksum((uint16_t*)new_icmp, sizeof(struct icmphdr)));
		memcpy(new_packet, buf, sizeof(struct ether_header) + sizeof(struct iphdr));
		memcpy(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr), 
				new_icmp, sizeof(struct icmphdr));
		memcpy(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
				initial_ip_header, sizeof(struct iphdr));
		size_t new_len = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr);
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

void send_arp_request (struct route_table_entry *best_route, char *packet, size_t len) {
	//create new packet
	char new_packet[MAX_PACKET_LEN];

	//create headers
	struct ether_header *eth_hdr = (struct ether_header *) malloc(sizeof(struct ether_header));
	struct arp_header *arp_hdr = (struct arp_header *) malloc(sizeof(struct arp_header));

	//fill in the headers
	memcpy(eth_hdr->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6);

	uint8_t mac_saddr[6];
	get_interface_mac(best_route->interface, mac_saddr);
	memcpy(eth_hdr->ether_shost, mac_saddr, 6);
	eth_hdr->ether_type = htons(0x0806);

	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	arp_hdr->tpa = best_route->next_hop;
	arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
	memcpy(arp_hdr->sha, mac_saddr, 6);

	memcpy(new_packet, eth_hdr, sizeof(struct ether_header));
	memcpy(new_packet + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
	size_t new_packet_len = sizeof(struct ether_header) + sizeof(struct arp_header);

	//add the packet in the queue
	struct packet_queue *packet_queue = (struct packet_queue *)malloc(sizeof(struct packet_queue));
	packet_queue->best_route = best_route;
	memcpy(packet_queue->packet, packet, len);
	packet_queue->len = len;
	queue_enq(Queue_arp, packet_queue);

	send_to_link(best_route->interface, new_packet, new_packet_len);
}

void ip_forward(char *packet, size_t len, int interface) {	
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

	int found = 0;
	for (int i = 0; i < arp_size; i++) {
		if (arp_table[i].ip == best_route->next_hop) {
			memcpy(eth_hdr->ether_dhost, arp_table[i].mac, 6);
			found = 1;
			break;
		}
	}

	if (found == 0) {
		printf("I don't know the mac address of the next hop!\n");
		send_arp_request(best_route, packet, len);
		return;
	}
	send_to_link(best_route->interface, packet, len);
}

void receive_arp_request(int interface, char *packet, size_t len) {
	uint8_t mac_src[6];
	get_interface_mac(interface, mac_src);
	struct ether_header *eth = (struct ether_header *) packet;
	struct arp_header *arp = (struct arp_header *) (packet + sizeof(struct ether_header));

	//update mac addresses
	uint8_t mac_dest[6];
	memcpy(mac_dest, eth->ether_shost, 6);
	memcpy(eth->ether_shost, mac_src, 6);
	memcpy(eth->ether_dhost, mac_dest, 6);

	arp->op = htons(2);

	//swap ip adresses
	uint32_t ip_aux = arp->spa;
	arp->spa = arp->tpa;
	arp->tpa = ip_aux;

	//complete mac addresses
	memcpy(arp->tha, arp->sha, 6);
	memcpy(arp->sha, mac_src, 6);

	send_to_link(interface, packet, len);
}

void receive_arp_reply(char *packet) {
	struct arp_header *arp_hdr = (struct arp_header *) (packet + sizeof(struct ether_header));

	//the ip address is already in the arp table
	for (int i =0; i < arp_size; i++) {
		if (arp_table[i].ip == arp_hdr->spa) {
			return;
		}
	}

	// add in arp table
	arp_table[arp_size].ip = arp_hdr->spa;
	memcpy(arp_table[arp_size].mac, arp_hdr->sha, 6);
	arp_size++;

	//send the packets from the queue
	while (!queue_empty(Queue_arp)) {
		struct packet_queue *q = queue_deq(Queue_arp);

		for (int i = 0; i < arp_size; i++) {
			if (q->best_route->next_hop == arp_table[i].ip) {

				char packet_from_queue[MAX_PACKET_LEN];
				memcpy(packet_from_queue, q->packet, q->len);

				int interface = q->best_route->interface;
				size_t len = q->len;
				struct ether_header *eth = (struct ether_header *) packet_from_queue;
				memcpy(eth->ether_dhost, arp_table[i].mac, 6);
				send_to_link(interface, packet_from_queue, len);
			}
		}
		free(q);
	}

}

int main(int argc, char *argv[]) {

	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "Failed to allocate memory for rtable");

	arp_table = (struct arp_entry *)malloc(sizeof(struct arp_entry) * 100000);
	
	rt_size = read_rtable(argv[1], rtable);
	Queue_arp = queue_create();
	arp_size = 0;
	//arp_size = parse_arp_table("arp_table.txt", arp_table);
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
			ip_forward(buf, len, interface);
		} else if (ntohs(eth_hdr->ether_type) == 0x0806) {
			struct arp_header *arp_header = (struct arp_header *) (buf + sizeof(struct ether_header));
			if (arp_header->op == htons(1)) {
				//am primit un arp request
				printf("I found an ARP request\n");
				receive_arp_request(interface, buf, len);
			} else { // am primit un arp reply
				receive_arp_reply(buf);
			}
		}
	}
	return 0;
}