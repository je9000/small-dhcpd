#include "dhcpsrv.h"

void HandleDHCPDiscover(struct ether_header *eth, struct ip *iph, struct dhcp_packet *r_dhcph) {
    struct dhcp_opt_ll *opts;
    int itemp;
    u_char ctemp;
    struct back_dhcp_offer offer;
    struct in_addr iatemp;
    iatemp.s_addr = 0;

    /* Ask the backend what to do */
    itemp = back_dispatch_offer((struct ether_addr *) &eth->ether_shost, &r_dhcph->ciaddr, 
                                &r_dhcph->giaddr, ntohl(r_dhcph->xid), &offer);
    if (!itemp) return;

    /* Message Type */
    ctemp = DHCPOFFER;
    opts = NewDHCPOptions(DHO_DHCP_MESSAGE_TYPE, &ctemp, 1); 

    if (!PushDHCPOption(opts, DHO_SUBNET_MASK, &offer.subnet_mask.s_addr, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }
    
    if (!PushDHCPOption(opts, DHO_ROUTERS, &offer.gateway_ip.s_addr, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    if (!PushDHCPOption(opts, DHO_DOMAIN_NAME_SERVERS, &offer.dns_ip.s_addr, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    /* When that the client should try and renew its IP */
    itemp = htonl(offer.lease_time);
    if (!PushDHCPOption(opts, DHO_DHCP_RENEWAL_TIME, &itemp, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    /* When that the client should start looking for a new DHCP server */
    itemp = htonl(offer.lease_time + (60 * 5));
    if (!PushDHCPOption(opts, DHO_DHCP_REBINDING_TIME, &itemp, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    /* When that the client should give up its IP completly */
    itemp = htonl(offer.lease_time + (60 * 10));
    if (!PushDHCPOption(opts, DHO_DHCP_LEASE_TIME, &itemp, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    if (!PushDHCPOption(opts, DHO_DHCP_SERVER_IDENTIFIER, &adapter.adapter_ip, sizeof(adapter.adapter_ip))) {
        FreeDHCPOptions(opts);
        return;
    }

    /* Remember to set the siaddr to zero since this is the last DHCP request in the exchange */
    if (r_dhcph->giaddr.s_addr == 0) {
        SendDHCP((struct ether_addr *) &eth->ether_shost, &in_addr_broadcast, &in_addr_zero, opts,
                 (struct ether_addr *) &r_dhcph->chaddr, &offer.offer_ip, &adapter.adapter_ip, ntohl(r_dhcph->xid));
    } else {
        SendDHCP((struct ether_addr *) &eth->ether_shost, &r_dhcph->giaddr, &r_dhcph->giaddr, opts,
                 (struct ether_addr *) &r_dhcph->chaddr, &offer.offer_ip, &adapter.adapter_ip, ntohl(r_dhcph->xid));
    }

    FreeDHCPOptions(opts);
}

void HandleDHCPRequest(struct ether_header *eth, struct ip *iph, struct dhcp_packet *r_dhcph) {
    struct dhcp_opt_ll *opts;
    int itemp;
    u_char ctemp;
    struct in_addr iatemp, iatemp2;
    struct ether_addr *eth_dest;
    void *ptemp;
    struct back_dhcp_offer offer;

    /* This is a little complex. The Request can either come from a new unconfigured client
       or from an existing one trying to renew or extend its lease. If it's from an new client,
       make sure that the destination IPs and ethernet addresses are both set to "broadcast".
       Otherwise, set them to the source's addresses (which could be different if there's a
       DHCP relay between us and the client. */
    if (iph->ip_src.s_addr == 0) {
        iatemp2 = in_addr_broadcast;
        eth_dest = (struct ether_addr *) &eth->ether_shost; //&ether_addr_broadcast;
    } else {
        iatemp2 = iph->ip_src;
        eth_dest = (struct ether_addr *) &eth->ether_shost;
    }

    /* Get the address of the requested IP from the request packet and copy its data to iatemp so we
       have can tell the back end what IP the client is requesting. If they don't supply one, perhaps
       they're trying to renew, and it will be in their client address field. */
    ptemp = GetDHCPOptionPointer(r_dhcph, sizeof(struct in_addr), DHO_DHCP_REQUESTED_ADDRESS);

    if (ptemp != NULL) {
        memcpy(&iatemp, ptemp, sizeof(struct in_addr));
    } else {
        memcpy(&iatemp, &r_dhcph->ciaddr, sizeof(struct in_addr));
    }

    /* Tell the back end that the client accepted the request and give it a final chance to decline */
    itemp = back_dispatch_offer_ack((struct ether_addr *) &r_dhcph->chaddr, &iatemp, 
                                    &r_dhcph->giaddr, ntohl(r_dhcph->xid), &offer);
    if (!itemp) {
        /* Message Type */
        ctemp = DHCPNAK;
        opts = NewDHCPOptions(DHO_DHCP_MESSAGE_TYPE, &ctemp, 1); 

        if (!PushDHCPOption(opts, DHO_DHCP_SERVER_IDENTIFIER, &adapter.adapter_ip, sizeof(adapter.adapter_ip))) {
            FreeDHCPOptions(opts);
            return;
        }

        if (r_dhcph->giaddr.s_addr == 0) {
            SendDHCP(eth_dest, &iatemp2, &in_addr_zero, opts,
                    (struct ether_addr *) &r_dhcph->chaddr, &in_addr_zero, &in_addr_zero, ntohl(r_dhcph->xid));
        } else {
            SendDHCP((struct ether_addr *) &eth->ether_shost, &r_dhcph->giaddr, &r_dhcph->giaddr, opts,
                    (struct ether_addr *) &r_dhcph->chaddr, &in_addr_zero, &in_addr_zero, ntohl(r_dhcph->xid));
        }
        return;
    }

    iatemp = offer.offer_ip;

    /* Message Type */
    ctemp = DHCPACK;
    opts = NewDHCPOptions(DHO_DHCP_MESSAGE_TYPE, &ctemp, 1); 

    if (!PushDHCPOption(opts, DHO_SUBNET_MASK, &offer.subnet_mask.s_addr, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }
    
    if (!PushDHCPOption(opts, DHO_ROUTERS, &offer.gateway_ip.s_addr, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    if (!PushDHCPOption(opts, DHO_DOMAIN_NAME_SERVERS, &offer.dns_ip.s_addr, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    /* When that the client should try and renew its IP */
    itemp = htonl(offer.lease_time);
    if (!PushDHCPOption(opts, DHO_DHCP_RENEWAL_TIME, &itemp, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    /* When that the client should start looking for a new DHCP server */
    itemp = htonl(offer.lease_time + (60 * 5));
    if (!PushDHCPOption(opts, DHO_DHCP_REBINDING_TIME, &itemp, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    /* When that the client should give up its IP completly */
    itemp = htonl(offer.lease_time + (60 * 10));
    if (!PushDHCPOption(opts, DHO_DHCP_LEASE_TIME, &itemp, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    if (!PushDHCPOption(opts, DHO_DHCP_SERVER_IDENTIFIER, &adapter.adapter_ip, sizeof(adapter.adapter_ip))) {
        FreeDHCPOptions(opts);
        return;
    }

    if (r_dhcph->giaddr.s_addr == 0) {
        SendDHCP(eth_dest, &iatemp2, &in_addr_zero, opts,
                 (struct ether_addr *) &r_dhcph->chaddr, &offer.offer_ip, &in_addr_zero, ntohl(r_dhcph->xid));
    } else {
        SendDHCP((struct ether_addr *) &eth->ether_shost, &r_dhcph->giaddr, &r_dhcph->giaddr, opts,
                 (struct ether_addr *) &r_dhcph->chaddr, &offer.offer_ip, &in_addr_zero, ntohl(r_dhcph->xid));
    }

    FreeDHCPOptions(opts);
}

void HandleDHCPRelease(struct ether_header *eth, struct ip *iph, struct dhcp_packet *r_dhcph) {
    back_dispatch_release((struct ether_addr *) &r_dhcph->chaddr, &r_dhcph->ciaddr, &r_dhcph->giaddr, ntohl(r_dhcph->xid));
}

void HandleDHCPDecline(struct ether_header *eth, struct ip *iph, struct dhcp_packet *r_dhcph) {
    back_dispatch_decline((struct ether_addr *) &r_dhcph->chaddr, &r_dhcph->giaddr, ntohl(r_dhcph->xid));
}

void HandleDHCPInform(struct ether_header *eth, struct ip *iph, struct dhcp_packet *r_dhcph) {
    struct dhcp_opt_ll *opts;
    int itemp;
    u_char ctemp;
    struct in_addr iatemp, iatemp2;
    struct back_dhcp_offer offer;

    if (iph->ip_src.s_addr == 0) {
        iatemp2 = in_addr_broadcast;
    } else {
        iatemp2 = iph->ip_src;
    }

    /* Tell the back end that the client accepted the request and give it a final chance to decline */
    itemp = back_dispatch_inform((struct ether_addr *) &r_dhcph->chaddr, &r_dhcph->ciaddr, 
                                 &r_dhcph->giaddr, ntohl(r_dhcph->xid), &offer);
    if (!itemp) {
        /* Message Type */
        ctemp = DHCPNAK;
        opts = NewDHCPOptions(DHO_DHCP_MESSAGE_TYPE, &ctemp, 1); 

        if (!PushDHCPOption(opts, DHO_DHCP_SERVER_IDENTIFIER, &adapter.adapter_ip, sizeof(adapter.adapter_ip))) {
            FreeDHCPOptions(opts);
            return;
        }

        if (r_dhcph->giaddr.s_addr == 0) {
            SendDHCP(&ether_addr_broadcast, &iatemp2, &in_addr_zero, opts,
                    (struct ether_addr *) &r_dhcph->chaddr, &in_addr_zero, &in_addr_zero, ntohl(r_dhcph->xid));
        } else {
            SendDHCP((struct ether_addr *) &eth->ether_shost, &r_dhcph->giaddr, &r_dhcph->giaddr, opts,
                    (struct ether_addr *) &r_dhcph->chaddr, &in_addr_zero, &in_addr_zero, ntohl(r_dhcph->xid));
        }
        return;
    }

    iatemp = offer.offer_ip;

    /* Message Type */
    ctemp = DHCPACK;
    opts = NewDHCPOptions(DHO_DHCP_MESSAGE_TYPE, &ctemp, 1); 
    
    if (!PushDHCPOption(opts, DHO_ROUTERS, &offer.gateway_ip.s_addr, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    if (!PushDHCPOption(opts, DHO_DOMAIN_NAME_SERVERS, &offer.dns_ip.s_addr, sizeof(itemp))) {
        FreeDHCPOptions(opts);
        return;
    }

    if (!PushDHCPOption(opts, DHO_DHCP_SERVER_IDENTIFIER, &adapter.adapter_ip, sizeof(adapter.adapter_ip))) {
        FreeDHCPOptions(opts);
        return;
    }

    if (r_dhcph->giaddr.s_addr == 0) {
        SendDHCP(&ether_addr_broadcast, &iatemp2, &in_addr_zero, opts,
                 (struct ether_addr *) &r_dhcph->chaddr, &offer.offer_ip, &in_addr_zero, ntohl(r_dhcph->xid));
    } else {
        SendDHCP((struct ether_addr *) &eth->ether_shost, &r_dhcph->giaddr, &r_dhcph->giaddr, opts,
                 (struct ether_addr *) &r_dhcph->chaddr, &offer.offer_ip, &in_addr_zero, ntohl(r_dhcph->xid));
    }

    FreeDHCPOptions(opts);
}
