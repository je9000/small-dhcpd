#include "dhcpsrv.h"

int IsDHCPPacketToMe(u_char *pkt_data, size_t packet_size)
{
    struct ether_header *eth;
    struct ip *iph;
    struct udphdr *udph;
    struct in_addr *server_id_ip;
    struct dhcp_packet *dhcph;
    eth = (struct ether_header *) pkt_data;

    if (packet_size < DHCP_FIXED_LEN) return 0;
    
    /* DHC_FIXED_LEN includes the ethernet, IP, and UDP headers
    if (packet_size < sizeof(struct ether_header) + sizeof(struct ip)) return 0; */

    if ((memcmp(&eth->ether_dhost, &ether_addr_broadcast, ETHER_ADDR_LEN) != 0) &&
        (memcmp(&eth->ether_dhost, &adapter.adapter_address, ETHER_ADDR_LEN) != 0)) return 0;

    iph = (struct ip *) (pkt_data + sizeof(struct ether_header));

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        if (iph->ip_p == IPPROTO_UDP) {
            udph = (struct udphdr *) (((size_t) iph) + (iph->ip_hl * 4));
            if ((ntohs(udph->uh_dport) == PORT_BOOTPS) && (ntohs(udph->uh_sport) == PORT_BOOTPC)) {
                dhcph = (struct dhcp_packet *) (((size_t) udph) + (sizeof(struct udphdr)));
                server_id_ip = GetDHCPOptionPointer(dhcph, packet_size, DHO_DHCP_SERVER_IDENTIFIER);

                if ((server_id_ip != NULL) && (server_id_ip->s_addr != adapter.adapter_ip.s_addr))
                    return 0;

                if (dhcph->options[0] != 0x63) return 0;
                if (dhcph->options[1] != 0x82) return 0;;
                if (dhcph->options[2] != 0x53) return 0;;
                if (dhcph->options[3] != 0x63) return 0;;

                return 1;
            }
        }
    }
    return 0;
}

u_char GetDHCPMessageType(struct dhcp_packet *dhcph, size_t packet_size)
{
    u_char *mtype;

    mtype = (u_char *) GetDHCPOptionPointer(dhcph, packet_size, DHO_DHCP_MESSAGE_TYPE);
    if (mtype != NULL) return *mtype;
    return 0;
}

void* GetDHCPOptionPointer(struct dhcp_packet *dhcph, size_t packet_size, u_char op)
{
    size_t x = 0;
    struct dhcp_opt *dopt;

#ifdef CORRECT_DHCP_MAGIC_COOKIE_OFFSET
    x += 4;
#endif

    while ((x < (packet_size - DHCP_FIXED_NON_UDP)) && (dhcph->options[x] != 255)) {
        dopt = (struct dhcp_opt *) (&dhcph->options[x]);
        if (dopt->option == op) {
            return &dopt->value[0];
        } else {
            x += dopt->len + 2;
        }
    }
    return NULL;
}

struct dhcp_opt_ll* NewDHCPOptions(u_char type, void *value, u_char value_len)
{
    struct dhcp_opt_ll *opts;

    /* dhcp_opt_ll defines itself as having 1 byte for the value length... so subtract it
       to get the size of just the structure, then add 1 because we really do want a size of 1 */
    opts = malloc(sizeof(struct dhcp_opt_ll) - 1 + value_len);
    if (!opts) return NULL;

    opts->options.len = value_len;
    opts->options.option = type;
    memcpy(&opts->options.value, value, value_len);
    opts->next = NULL;
    return opts;
}

int PushDHCPOption(struct dhcp_opt_ll *opts, u_char option_type, void *value, u_char value_len)
{
    struct dhcp_opt_ll *newopt;

    newopt = malloc(sizeof(struct dhcp_opt_ll) - 1 + value_len);
    if (!newopt) return 0;
    newopt->options.len = value_len;
    newopt->options.option = option_type;
    newopt->next = NULL;
    memcpy(&newopt->options.value, value, value_len); // Lose the &?
    while(opts->next != NULL) opts = opts->next;
    opts->next = newopt;
    return DHCP_OPT_BASE_SIZE + value_len;
}

void FreeDHCPOptions(struct dhcp_opt_ll *opts)
{
    struct dhcp_opt_ll *current_opt = opts;
    struct dhcp_opt_ll *next_opt;
    if (!current_opt) return;
    next_opt = current_opt->next;

    free(opts);
    current_opt = next_opt;

    while (current_opt != NULL) {
        next_opt = current_opt->next;
        free(current_opt);
        current_opt = next_opt;
    }
}

int SendDHCP(struct ether_addr *to,
             struct in_addr *to_ip,
             struct in_addr *gateway_ip,
             struct dhcp_opt_ll *options,
             struct ether_addr *dhcp_client_address,
             struct in_addr *client_ip,
             struct in_addr *next_ip,
             u_int32_t TransactionID
            )
{
    struct ip *iph;
    struct udphdr *udph;
    struct dhcp_packet *dhcph;
    struct ether_header *eth;
    struct dhcp_opt_ll *opt_start = options;
    u_char *sendbuf;
    size_t dhcp_size, sendsize;
    u_int itemp;

    dhcp_size = 0;
    while (options != NULL) {
        dhcp_size += (options->options.len + DHCP_OPT_BASE_SIZE);
        options = options->next;
    }
    options = opt_start;

    dhcp_size += 5; /* Tack on the Magic Cookie and the trailing 0xFF */

    sendsize = sizeof(struct ether_header) +
               sizeof(struct ip) +
               sizeof(struct udphdr) +
               DHCP_FIXED_NON_UDP +
               dhcp_size;

    if (sendsize % 2 != 0) sendsize++;    /* Make sure the packet is of even length. Packet will be
                                           zeroed out next. */

    sendbuf = (u_char *) malloc(sendsize);
    if (sendbuf == NULL) return 0;
    memset(sendbuf, 0, sendsize);

    eth = (struct ether_header *) sendbuf;
    iph = (struct ip *) (((size_t) eth) + sizeof(struct ether_header)); 
    udph = (struct udphdr *) (((size_t) iph) + 20); /* + (iph->ip_hl * 4) */
    dhcph = (struct dhcp_packet *) (((size_t) udph) + sizeof(struct udphdr));

    eth->ether_type = htons(ETHERTYPE_IP);
    memcpy(&eth->ether_dhost, to, ETHER_ADDR_LEN);
    memcpy(&eth->ether_shost, &adapter.adapter_address, ETHER_ADDR_LEN);

    iph->ip_dst = *to_ip;
    iph->ip_src = adapter.adapter_ip;

    iph->ip_hl = 5;

    iph->ip_id = (u_short) (rand() & 0x0000FFFF);
    iph->ip_off = 0;
    iph->ip_len = htons((u_short) sendsize - sizeof(struct ether_header));
    iph->ip_ttl = 128;
    iph->ip_v = 4;
    iph->ip_p = IPPROTO_UDP;

    udph->uh_dport = htons(PORT_BOOTPC);
    udph->uh_sport = htons(PORT_BOOTPS);
    udph->uh_ulen = htons((u_short) sendsize - sizeof(struct ether_header) - (iph->ip_hl * 4));

    dhcph->op = DHCPOFFER;
    dhcph->htype = HTYPE_ETHER;
    dhcph->hlen = ETHER_ADDR_LEN;
    dhcph->hops = 0;
    dhcph->xid = htonl(TransactionID);
    dhcph->secs = 0;
    dhcph->flags = 0;

    /* Client IP address (if already in use) */
    dhcph->ciaddr.s_addr = 0;
    /* Client IP address */
    dhcph->yiaddr = *client_ip;
    /* IP address of next server to talk to (to boot from?) */
    dhcph->siaddr = *next_ip;
    /* DHCP relay agent IP address */
    dhcph->giaddr = *gateway_ip;

    memcpy(&dhcph->chaddr, dhcp_client_address, ETHER_ADDR_LEN);

#ifdef CORRECT_DHCP_MAGIC_COOKIE_OFFSET
    dhcph->options[0] = 0x63;
    dhcph->options[1] = 0x82;
    dhcph->options[2] = 0x53;
    dhcph->options[3] = 0x63;

    itemp = 4;

    while (options != NULL) {
        dhcph->options[itemp++] = options->options.option;
        dhcph->options[itemp++] = options->options.len;
        memcpy(&dhcph->options[itemp], &options->options.value[0], options->options.len);
        itemp += options->options.len;
        options = options->next;
    }
    dhcph->options[itemp] = 0xFF;
#endif

    /* UDP header checksum needs to be calculated with the ip_ttl set to 0. Store it, then restore it. */
    itemp = iph->ip_ttl;
    iph->ip_ttl = 0;
    do_checksum((u_char *) iph, IPPROTO_UDP, sizeof(struct udphdr) + DHCP_FIXED_NON_UDP + dhcp_size);
    iph->ip_ttl = (u_char) itemp;
    do_checksum((u_char *) iph, IPPROTO_IP, sizeof(struct ip));

#ifdef WIN32
    if (pcap_sendpacket(fp, sendbuf, (int) sendsize) == -1) {
#else
    if (libnet_adv_write_link(libnet_if, sendbuf, (u_int32_t) sendsize) == -1) {
#endif
        fprintf(stderr, "Error writing packet to network!\n");
        return 1;
    }

    return 0;
}
