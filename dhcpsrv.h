#ifndef _DHCPSRV_H
#define _DHCPSRV_H

/* Includes */

#ifdef WIN32
 typedef unsigned char u_char;
 typedef unsigned short u_short;
 typedef unsigned char u_int8_t;
 typedef unsigned int u_int32_t;
 typedef unsigned short u_int16_t;
 typedef u_int16_t ether_short;
 /* Pcap uses Winsock2.h, so including it here is okay. Perl uses Winsock.h, which
    re-defines values in Winsock2.h, so they collide. */
 #include <winsock2.h>
 #include "headers/ethernet.h"
 #include "headers/dhcp.h"
 #include "headers/ip.h"
 #include "headers/udp.h"
#else
 #include <sys/types.h>
 #include <netinet/in_systm.h>
 #include <netinet/in.h>
 #include <netinet/ip.h>
 #include <netinet/udp.h>
 #include "headers/dhcp.h"
 #include <net/ethernet.h>
 #include <sys/socket.h>
 #include <libnet.h>
#endif

#include <pcap.h>
#include <string.h>
#include "checksums.h"

/* Back-end data structure and include */

#define BACK_DHCP_OFFER_RETURN_VALUES 5

struct back_dhcp_offer {
    struct in_addr offer_ip;
    struct in_addr subnet_mask;
    struct in_addr gateway_ip;
    struct in_addr dns_ip;
    int lease_time;
};

#include "perlback.h"

/* Definitions */

#define CORRECT_DHCP_MAGIC_COOKIE_OFFSET 
#define PORT_BOOTPS 67
#define PORT_BOOTPC 68
#define DHCP_OPT_BASE_SIZE 2

#define NO_ADAPTER -1
#define NO_BACKEND -2

#define EthAddrToString(addr, out) \
    sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", addr[0], addr[1], \
                                      addr[2], addr[3], \
                                      addr[4], addr[5]);

/* Structures */

#pragma pack(1)
struct dhcp_opt {
    u_char option;
    u_char len;
    u_char value[1];
};
#pragma pack()

struct dhcp_opt_ll {
    struct dhcp_opt_ll* next;
    struct dhcp_opt options;
};

struct LocalAdapterInfo {
    struct in_addr adapter_ip;
    struct in_addr adapter_netmask;
    char *adapter_name;
    struct ether_addr adapter_address;
};


/* Global Variables */

struct ether_addr ether_addr_broadcast;
struct in_addr in_addr_broadcast;
struct in_addr in_addr_zero;
struct LocalAdapterInfo adapter;
pcap_t *fp;

#ifndef WIN32
libnet_t *libnet_if;
#endif

/* Function Definitions */

void PrintPacketDetails(u_char *pkt_data, size_t pkt_len);
int GetLocalMACAddress(struct in_addr associated_ip, char *dev, struct ether_addr *out);
int parse_args(int argc, char *argv[]);
void print_usage(void);

int PushDHCPOption(struct dhcp_opt_ll *opts, u_char type, void *value, u_char value_len);
struct dhcp_opt_ll * NewDHCPOptions(u_char type, void *value, u_char value_len);
void FreeDHCPOptions(struct dhcp_opt_ll *opts);

int IsDHCPPacketToMe(u_char *pkt_data, size_t packet_size);
void* GetDHCPOptionPointer(struct dhcp_packet *dhcph, size_t packet_size, u_char op);
u_char GetDHCPMessageType(struct dhcp_packet *dhcph, size_t packet_size);

void HandleDHCPDiscover(struct ether_header *eth, struct ip *iph, struct dhcp_packet *r_dhcph);
void HandleDHCPRequest(struct ether_header *eth, struct ip *iph, struct dhcp_packet *r_dhcph);
void HandleDHCPRelease(struct ether_header *eth, struct ip *iph, struct dhcp_packet *r_dhcph);
void HandleDHCPInform(struct ether_header *eth, struct ip *iph, struct dhcp_packet *r_dhcph);
void HandleDHCPDecline(struct ether_header *eth, struct ip *iph, struct dhcp_packet *r_dhcph);

int SendDHCP(struct ether_addr *to,
             struct in_addr *to_ip,
             struct in_addr *gateway_ip,
             struct dhcp_opt_ll *options,
             struct ether_addr *dhcp_client_address,
             struct in_addr *client_ip,
             struct in_addr *next_ip,
             u_int32_t TransactionID
            );

#endif
