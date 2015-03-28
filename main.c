/* Simple DHCP Server */

#include "dhcpsrv.h"

#include <stdio.h>

char **back_argv;
int back_argc;

int main(int argc, char **argv) {
    pcap_if_t *alldevs, *d;
    struct pcap_pkthdr *header;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char *pkt_data;
    u_int i;
    int res, parse_params_result;
#ifdef WIN32
    WSADATA wsad;
#else
    char libnet_errbuf[LIBNET_ERRBUF_SIZE];
#endif

    memset(&ether_addr_broadcast, 255, ETHER_ADDR_LEN);
    in_addr_broadcast.s_addr = (u_long) -1;
    in_addr_zero.s_addr = 0;
    srand((unsigned) time(NULL));

    /* Set the adapter_ip to zero and then parse the command line. If they don't
       specify an IP address to listen on, we'll know because adapter_ip is still
       zero. */
    adapter.adapter_ip.s_addr = 0;
    
    parse_params_result = parse_args(argc, argv);

    /* Make sure we're in a consistant state before continuing. We test for
       adapter.adapter_ip.s_addr == 0 later on and we need to be sure that's
       safe. */
    if ((parse_params_result == NO_ADAPTER) && (adapter.adapter_ip.s_addr != 0)) {
        fprintf(stderr, "Internal inconsistancy defining IP address\n.");
        exit(1);
    }

    /* The user didn't provide a packet source: Retrieve the local device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    /* If the adapter.adapter_ip is zero here, then the user didn't specify an IP to listen on
       (and we received a NO_ADAPTER above). */
    if (adapter.adapter_ip.s_addr == 0) {
        fprintf(stderr, "\nValid IPs and their associated adapters are listed here:\n");
    }

#ifdef WIN32
    if (WSAStartup(MAKEWORD(2, 0), &wsad) != 0) {
        fprintf(stderr, "Error initializing Winsock (%i)!\n", WSAGetLastError());
        return -1;
    }
#endif

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        if (d->addresses != NULL) {
            pcap_addr_t *a;
            for(a = d->addresses; a; a = a->next) {
                if (a->addr->sa_family != AF_INET) continue;
                if (adapter.adapter_ip.s_addr == 0) {
                    fprintf(stderr, "\t%s\t(%s)\n", d->name, inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
                } else if (((struct sockaddr_in *)a->addr)->sin_addr.s_addr == adapter.adapter_ip.s_addr) {
                    printf("Using adapter %s...\n", d->name);
                    i = (u_int) strlen(d->name);

                    /* Store a copy of the adapter name because we free alldevs below. */
                    adapter.adapter_name = (char *) malloc(i + 1);
                    strncpy(adapter.adapter_name, d->name, i);
                    adapter.adapter_name[i] = 0;

                    /* Fancy schamncy way of getting the IP out of the structure. */
                    /* adapter.adapter_ip = (((struct sockaddr_in *) d->addresses->addr)->sin_addr); */
                    adapter.adapter_netmask = ((struct sockaddr_in *)a->netmask)->sin_addr;

                    #ifndef WIN32
                    libnet_if = libnet_init(
                            LIBNET_LINK_ADV,                        // injection type
                            adapter.adapter_name,                   // network interface
                            libnet_errbuf);                         // errbuf
                    if (!libnet_if)
                    {
                        fprintf(stderr, "Failed calling libnet_init: %s\n", libnet_errbuf);
                        return -1;
                    }
                    #endif

                    break;
                }
            } /* Loop over each address in d->addresses */
        }
    }

    pcap_freealldevs(alldevs);

    if (parse_params_result == NO_BACKEND) {
        exit(1);
    }

    if (!back_init(back_argc, back_argv)) {
        back_free();
        fprintf(stderr, "Unable to load Perl intreperter, aborting.\n");
        exit(1);
    }

    if (adapter.adapter_ip.s_addr == 0) {
        fprintf(stderr, "\nPlease specify the IP address of the adapter to listen on with the --listen <IP> parameter.\n");
        exit(1);
    }

    if (!adapter.adapter_name)
    {
        fprintf(stderr, "No interfaces with IP address %s found!\n\n"
               "Make sure WinPcap is installed and that you have an ethernet interface\n" 
               "with an IP address assigned to it.\n", inet_ntoa(adapter.adapter_ip));
        return -1;
    }
    
    if (!GetLocalMACAddress(adapter.adapter_ip, adapter.adapter_name, &adapter.adapter_address)) {
        fprintf(stderr, "Unable to get the MAC address for the adapter: %s!", adapter.adapter_name);
        return -1;
    }

    printf("\nDHCP server started.\n");

    /* Do not check for the switch type ('-s') */
    if ((fp = pcap_open_live(adapter.adapter_name,        // name of the device
        65536,                                            // portion of the packet to capture. 
                                                        // 65536 grants that the whole packet will be captured on all the MACs.
        1,                                                // promiscuous mode (nonzero means promiscuous)
        1000,                                            // read timeout
        errbuf                                            // error buffer
        )) == NULL)
    {
        fprintf(stderr,"\nError opening adapter\n");
        return -1;
    }

    /* Read the packets */
    while((res = pcap_next_ex( fp, &header, (const u_char **) &pkt_data)) >= 0) {
        struct ip *iph;
        struct udphdr *udph;
        struct dhcp_packet *dhcph;

        /* Timeout elapsed */
        if (res == 0) continue;

        /* We're only interested in DHCP packets */
        if (!IsDHCPPacketToMe(pkt_data, header->caplen)) continue;
        PrintPacketDetails(pkt_data, header->caplen);

        iph = (struct ip *) (((size_t) pkt_data) + sizeof(struct ether_header)); 
        udph = (struct udphdr *) (((size_t) iph) + (iph->ip_hl * 4));
        dhcph = (struct dhcp_packet *) (((size_t) udph) + sizeof(struct udphdr));

        i = GetDHCPMessageType(dhcph, ((size_t) header->caplen - 
                               (((size_t) pkt_data) - ((size_t) dhcph)))
                              );

        switch (i) {
            case DHCPDISCOVER:
                HandleDHCPDiscover((struct ether_header *) pkt_data, iph, dhcph);
                break;
            case DHCPREQUEST:
                HandleDHCPRequest((struct ether_header *) pkt_data, iph, dhcph);
                break;
            case DHCPDECLINE:
                HandleDHCPDecline((struct ether_header *) pkt_data, iph, dhcph);
                break;
            case DHCPRELEASE:
                HandleDHCPRelease((struct ether_header *) pkt_data, iph, dhcph);
                break;
            case DHCPINFORM:
                HandleDHCPInform((struct ether_header *) pkt_data, iph, dhcph);
                break;
            default:
                printf("Received a packet (%i) we don't want to deal with!\n\n", i);
        }

    }

    free(adapter.adapter_name);
    if (res == -1)
    {
        printf("Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }

    pcap_close(fp);
#ifdef WIN32
    WSACleanup();
#endif
    return 0;
}

void PrintPacketDetails(u_char *pkt_data, size_t pkt_len) {
    char temps[18];
    char tempd[18];
    struct ether_header *eth;
    struct ip *iph;
    struct udphdr *udph;
    struct dhcp_packet *dhcph;
    struct in_addr *server_id_ip;
    size_t dhcplen;
    eth = (struct ether_header *) pkt_data;

    iph = (struct ip *) (pkt_data + sizeof(struct ether_header));

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        EthAddrToString(((u_char *) &eth->ether_dhost), (char *) &tempd);
        EthAddrToString(((u_char *) &eth->ether_shost), (char *) &temps);
        printf("\nEthernet frame from: %s -> %s\n", (char *) &temps, (char *) &tempd);
        if (iph->ip_p == IPPROTO_UDP) {
            udph = (struct udphdr *) (((size_t) iph) + (iph->ip_hl * 4));
            if ((ntohs(udph->uh_dport) == PORT_BOOTPS) && (ntohs(udph->uh_sport) == PORT_BOOTPC)) {
                /* Has to be like this because inet_ntoa can/will re-use the memory from the first call for the second */
                printf("IP packet from %s:%hi ->", inet_ntoa(iph->ip_src), ntohs(udph->uh_sport));
                printf(" %s:%hi\n", inet_ntoa(iph->ip_dst), ntohs(udph->uh_dport));

                dhcph = (struct dhcp_packet *) (((size_t) udph) + sizeof(struct udphdr));
                dhcplen = pkt_len - (((size_t) dhcph) - ((size_t) eth));

                server_id_ip = GetDHCPOptionPointer(dhcph, pkt_len, DHO_DHCP_SERVER_IDENTIFIER);
                if (server_id_ip != NULL) {
                    printf("ServerID: %s\n", inet_ntoa(*server_id_ip));
                } else {
                    printf("No Server ID supplied.\n");
                }
                printf("DHCP packet type: ");

                switch (GetDHCPMessageType(dhcph, dhcplen)) {
                    case DHCPDISCOVER:
                        printf("DISCOVER\n");
                        break;
                    case DHCPOFFER:
                        printf("OFFER\n");
                        break;
                    case DHCPREQUEST:
                        printf("REQUEST\n");
                        break;
                    case DHCPDECLINE:
                        printf("DECLINE\n");
                        break;
                    case DHCPACK:
                        printf("ACK\n");
                        break;
                    case DHCPNAK:
                        printf("NAK\n");
                        break;
                    case DHCPRELEASE:
                        printf("RELEASE\n");
                        break;
                    case DHCPINFORM:
                        printf("INFORM\n");
                        break;
                    default:
                        printf("Unknown\n");
                }

            }
        } else {
            printf("Other IP packet received (protocol %hi\n\n", iph->ip_p);
        }
    }
}

/* It's really unclean not to clean up all memory allocated so far
    when we return due to a memory failure, but the program exit()s
    right afterwards and the OS will clean up after us. Sorry, I'm
    in a hurry. */
int parse_args(int argc, char **argv)
{
    int x = 1;
    int have_backend = 0;
    int back_arg_started = 0;
    char *back_path;
    size_t back_path_size = 0;

    /* Pre-allocate the first two entries in the array to the name of the 
       program being run and the name of the perl script to be run. Note,
       we malloc() the required memory later. */
    back_argc = 2;

    while (x < argc) {
        if (back_arg_started != 0) {
            back_argv[back_argc] = (char *) malloc(strlen(argv[x]) + 1);
            if (back_argv[back_argc] == NULL) goto no_memory;
            strncpy(back_argv[back_argc], argv[x], strlen(argv[x]) + 1);
            back_argc++;
        } else {
            if ((x < (argc - 1)) && ((strcmp(argv[x], "--listen-ip") == 0))) {
                adapter.adapter_ip.s_addr = inet_addr(argv[x + 1]);
                x++;

            } else if ((x < (argc - 1)) && (strcmp(argv[x], "--back-path") == 0)) {
                have_backend++;
                back_path_size = strlen(argv[x + 1]) + 1;
                back_path = (char *) malloc(back_path_size);
                memcpy(back_path, argv[x + 1], back_path_size);
                x++;

            } else if ((x < (argc - 1)) && (strcmp(argv[x], "--") == 0)) {
                back_arg_started = 1;
                /* If we're here, that means the user specified parameters for the
                   back-end script. malloc() enough room for those parameters plus
                   the first two (the path to me and the path to the script). */
                back_argv = malloc(sizeof(char *) * back_argc + (argc - x - 1));
                if (back_argv == NULL) goto no_memory;
            }
        }
        x++;
    }

    /* Abort if we don't have all of the variables we need. The order in which we check
       is important. */
    if (!have_backend) {
        print_usage();
        return NO_BACKEND;
    }

    /* If back_arg_started == 0 then the user didn't specify a command line for the
       back end. That means we'll need to malloc() memory for the first two parameters
       here. */
    if (back_arg_started == 0) {
        back_argv = malloc(sizeof(char *) * back_argc);
        if (back_argv == NULL) goto no_memory;
    }

    back_argv[0] = (char *) malloc(back_path_size);
    if (back_argv[0] == NULL) goto no_memory;
    back_argv[1] = (char *) malloc(back_path_size);
    if (back_argv[1] == NULL) goto no_memory;

    memcpy(back_argv[0], argv[0], strlen(argv[0]) + 1);
    memcpy(back_argv[1], back_path, back_path_size);
    return 1;

no_memory:
    fprintf(stderr, "Memory error parsing arguments, aborting.\n");
    exit(1);
}

void print_usage(void)
{
    fprintf(stderr, "usage: dhcpsrv --listen-ip <ip> --backend-path <path> [-- args]\n");
    fprintf(stderr, "\tCommand Summary:\n");
    fprintf(stderr, "\t\t--listen-ip\tThe IP address of the adapter to listen on.\n");
    fprintf(stderr, "\t\t--backend-path\tThe path to the perl script to use as the\n");
    fprintf(stderr, "\t\t\t\tback-end logic.\n");
    fprintf(stderr, "\t\t-- [args]\tAny following arguments will be passed directly\n");
    fprintf(stderr, "\t\t\t\tto the back-end.\n");
}
