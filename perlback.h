#include "dhcpsrv.h"

int back_init(int argc, char **argv);
void back_free();

int back_dispatch_offer_stub(char *function_name, struct ether_addr *client_address, struct in_addr *requested_ip,
                             struct in_addr *gateway_ip, u_int32_t TransactionID, struct back_dhcp_offer *offer);

int back_dispatch_offer(struct ether_addr *client_address, struct in_addr *requested_ip,
                        struct in_addr *gateway_ip, u_int32_t TransactionID, struct back_dhcp_offer *offer);

int back_dispatch_offer_ack(struct ether_addr *client_address, struct in_addr *requested_ip,
                        struct in_addr *gateway_ip, u_int32_t TransactionID, struct back_dhcp_offer *offer);

int back_dispatch_inform(struct ether_addr *client_address, struct in_addr *requested_ip,
                        struct in_addr *gateway_ip, u_int32_t TransactionID, struct back_dhcp_offer *offer);

void back_dispatch_release(struct ether_addr *client_address, struct in_addr *released_ip, struct in_addr *gateway_ip, u_int32_t TransactionID);
void back_dispatch_decline(struct ether_addr *client_address, struct in_addr *gateway_ip, u_int32_t TransactionID);
