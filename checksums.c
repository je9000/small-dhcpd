/*
 *  Copyright (c) 1998 - 2001 Mike D. Schiffman <mike@infonexus.com>
 *  Copyright (c) 1999, 2000 Dug Song <dugsong@monkey.org>
 *  Copyright (c) 2005, John Eaglesham
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "dhcpsrv.h"

int in_cksum(u_short *addr, int len)
{
    int sum;
    int nleft;
    u_short ans;
    u_short *w;

    sum = 0;
    ans = 0;
    nleft = len;
    w = addr;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(u_char *)(&ans) = *(u_char *)w;
        sum += ans;
    }
    return (sum);
}

int do_checksum(u_char *buf, int protocol, int len)
{
    struct ip *iph_p;
    int ip_hl;
    int sum;

    sum = 0;
    iph_p = (struct ip *)buf;
    ip_hl = iph_p->ip_hl << 2;

    /*
     *  Dug Song came up with this very cool checksuming implementation
     *  eliminating the need for explicit psuedoheader use.  Check it out.
     */
    switch (protocol)
    {
        /*
         *  Style note: normally I don't advocate declaring variables inside
         *  blocks of control, but it makes good sense here. -- MDS
         */
        case IPPROTO_UDP:
        {
            struct udphdr *udph_p =
                (struct udphdr *)(buf + ip_hl);

            udph_p->uh_sum = 0;
            sum = in_cksum((u_short *)&iph_p->ip_src, 8);
            sum += ntohs(IPPROTO_UDP + len);
            sum += in_cksum((u_short *)udph_p, len);
            udph_p->uh_sum = CKSUM_CARRY(sum);
            break;
        }
        /*case IPPROTO_ICMP:
        {
            struct libnet_icmp_hdr *icmph_p =
                (struct libnet_icmp_hdr *)(buf + ip_hl);

            icmph_p->icmp_sum = 0;
            sum = libnet_in_cksum((u_short *)icmph_p, len);
            icmph_p->icmp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }*/
        case IPPROTO_IP:
        {
            iph_p->ip_sum = 0;
            sum = in_cksum((u_short *)iph_p, len);
            iph_p->ip_sum = CKSUM_CARRY(sum);
            break;
        }
        default:
        {
            return (-1);
        }
    }
    return (1);
}
