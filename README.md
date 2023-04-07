Dumitru Bianca-Andreea, 322CA

# PCOM - DataPlane Router

## Implemented tasks:

### 1. LPM efficient

 For finding the longest prefix match, I used **binary search**. Before applying the algorithm, I used **quicksort** to efficiently sort the routing table in a descending order based on prefix and mask. I implemented the function "compare" that establishes the order of the routing table's entries.

 **Compare function** returns a positive number, if the second prefix or mask is greater than the first one, in order to swap them. Otherwise it returns an negative number and the order isn't changed.

### 2. The routing process (IPv4)

Theese are the steps for implementing the routing process:

- verify if the received packet contains an IPv4 header
- if it contains an ipv4 header:
 I make sure that the checksum is correct (by making again the checksum of the packet and comparing it to the received checksum);
 I verify and decrement the TTL and after that I calculate again the checksum (because the TTL was modified);
 I check if the packet contains an icmp header, if it is so, I modify the packet and I send an echo reply message;
- Find the best route, using LPM;
- Modify the ethernet header: the source MAC address will be the MAC address of the corresponding interface for the next-hop and I search for the destinantion MAC address in the arp table. If the arp table doesn't have the needed MAC addres I send an arp request packet.
- After the previous steps I send the packet

### 3. Arp 
    