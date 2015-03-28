#include "dhcpsrv.h"
#ifdef WIN32
 #include <Iphlpapi.h>
 #include <string.h>
#endif

#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#endif

int GetLocalMACAddress(struct in_addr associated_ip, char *dev, struct ether_addr *out) {

#ifdef WIN32
    char ip_str[16];
    char *t;
    IP_ADAPTER_INFO AdapterInfo[32];                    // Allocate information or up to 32 NICs
    DWORD dwBufLen = sizeof(AdapterInfo);                // Save memory size of buffer

    DWORD dwStatus = GetAdaptersInfo(                    // Call GetAdapterInfo
                      AdapterInfo,                        // [out] buffer to receive data
                      &dwBufLen                            // [in] size of receive data buffer
                     );

    t = inet_ntoa(associated_ip);
    if (t[0] == 0) return 0;
    memcpy(&ip_str, t, strlen(t) + 1);

    if(dwStatus == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;    // Pointer to current adapter info
        while (pAdapterInfo != NULL) {
            if ((pAdapterInfo->IpAddressList.IpAddress.String != NULL) &&
                (strstr(pAdapterInfo->IpAddressList.IpAddress.String, (char *) &ip_str) != NULL)) {
                memcpy(out, &pAdapterInfo->Address, ETHER_ADDR_LEN);
                return 1;
            }
            pAdapterInfo = pAdapterInfo->Next;                // Progress through
        }
    }
    return 0;
#endif
#ifdef linux
    int skfd = 0;
    struct ifreq ifr;

    strcpy(ifr.ifr_name, dev);
    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd < 0) return 0;
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
        close(skfd);
        return 0;
    }
    memcpy(out, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(skfd);
    return 1;
#endif

#ifdef __FreeBSD__
    int            mib[6];
    size_t      len;
    char            *buf;
    unsigned char        *ptr;
    struct if_msghdr    *ifm;
    struct sockaddr_dl    *sdl;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    if ((mib[5] = if_nametoindex(dev)) == 0) {
        return 0;
    }

    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        return 0;
    }

    if ((buf = malloc(len)) == NULL) {
        return 0;
    }

    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        return 0;
    }

    ifm = (struct if_msghdr *)buf;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    ptr = (unsigned char *)LLADDR(sdl);
    memcpy(out, ptr, ETHER_ADDR_LEN);
    
    return 1;

#endif

}
