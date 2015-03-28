#ifdef WIN32
#define NO_STRICT 
#define HAVE_DES_FCRYPT 
#define NO_HASH_SEED 
#define PERL_IMPLICIT_CONTEXT 
#define PERL_IMPLICIT_SYS
#define USE_PERLIO
#define PERL_MSVCRT_READFIX
#endif

#ifdef WIN32
/* A trick. Perl pulls in winsock.h, but pcap uses winsock2.h, which collides.
   So, define the "winsock already included" variable here and pull in
   winsock2, which has everything perl needs in it. This way, both libraries use
   winsock2. */
#define _WINSOCKAPI_
#include <winsock2.h>
#endif

#include <EXTERN.h>
#include <perl.h>
#include "perlback.h"
#include "dhcpsrv.h"

EXTERN_C void xs_init (pTHX);
EXTERN_C void boot_DynaLoader (pTHX_ CV* cv);

static PerlInterpreter *my_perl;

EXTERN_C void
xs_init(pTHX)
{
        char *file = __FILE__;
        dXSUB_SYS;

        /* DynaLoader is a special case */
        newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}

int back_dispatch_offer(struct ether_addr *client_address, struct in_addr *requested_ip,
                        struct in_addr *gateway_ip, u_int32_t TransactionID, struct back_dhcp_offer *offer)
{
    return back_dispatch_offer_stub("dhcp_offer", client_address, requested_ip, gateway_ip, TransactionID, offer);
}

int back_dispatch_offer_ack(struct ether_addr *client_address, struct in_addr *requested_ip,
                        struct in_addr *gateway_ip, u_int32_t TransactionID, struct back_dhcp_offer *offer)
{
    return back_dispatch_offer_stub("dhcp_offer_ack", client_address, requested_ip, gateway_ip, TransactionID, offer);
}

/* The offer lease time, IP address, and subnet mask are not used in Inform messages */
int back_dispatch_inform(struct ether_addr *client_address, struct in_addr *requested_ip,
                        struct in_addr *gateway_ip, u_int32_t TransactionID, struct back_dhcp_offer *offer)
{
    return back_dispatch_offer_stub("dhcp_inform", client_address, requested_ip, gateway_ip, TransactionID, offer);
}

int back_dispatch_offer_stub(char *function_name, struct ether_addr *client_address, struct in_addr *requested_ip,
                             struct in_addr *gateway_ip, u_int32_t TransactionID, struct back_dhcp_offer *offer)
{
    int r;
    char ea[18];
    STRLEN n_a;
    dSP;                                            /* initialize stack pointer      */
    ENTER;                                            /* everything created after here */
    SAVETMPS;                                        /* ...is a temporary variable.   */
    PUSHMARK(SP);                                    /* remember the stack pointer    */

    /* Ethernet addresses are 6 bytes. Add in room for deliminating 
       colons and the trailing NULL and you're at 18 characters. */
    EthAddrToString(((u_char *) client_address), (char *) &ea);

    /* Push them on in order */
    XPUSHs(sv_2mortal(newSVuv(TransactionID)));        /* push the base onto the stack  */
    XPUSHs(sv_2mortal(newSVpvn((char *) &ea, 17)));    /* push the base onto the stack  */
    XPUSHs(sv_2mortal(newSVpv(inet_ntoa(*requested_ip), 0))); /* newSVpv makes a copy */
    XPUSHs(sv_2mortal(newSVpv(inet_ntoa(*gateway_ip), 0)));   /* newSVpv makes a copy */

    PUTBACK;                                        /* make local stack pointer global */
    r = call_pv(function_name, G_ARRAY | G_EVAL);        /* call the function             */
    SPAGAIN;                                        /* refresh stack pointer         */

    if (SvTRUE(ERRSV)) {
        fprintf(stderr, "Error calling %s. %s\n", function_name, SvPV(get_sv("@", 0), n_a));
        PUTBACK;
        FREETMPS;                                    /* free that return value        */
        LEAVE;                                        /* ...and the XPUSHed "mortal" args.*/
        return 0;
    }

    if (r < BACK_DHCP_OFFER_RETURN_VALUES) {
        PUTBACK;
        FREETMPS;                                    /* free that return value        */
        LEAVE;                                        /* ...and the XPUSHed "mortal" args.*/
        return 0;
    }


    /* Pop results off the stack in reverse order */
    offer->lease_time = POPi;
    offer->dns_ip.s_addr = inet_addr(POPpbytex);
    offer->gateway_ip.s_addr = inet_addr(POPpbytex);
    offer->subnet_mask.s_addr = inet_addr(POPpbytex);
    offer->offer_ip.s_addr = inet_addr(POPpbytex);

    PUTBACK;
    FREETMPS;                                        /* free that return value        */
    LEAVE;                                            /* ...and the XPUSHed "mortal" args.*/
    return 1;
 }

void back_dispatch_release(struct ether_addr *client_address, struct in_addr *released_ip, 
                           struct in_addr *gateway_ip, u_int32_t TransactionID)
{
    char ea[18];
    STRLEN n_a;
    dSP;                                            /* initialize stack pointer      */
    ENTER;                                            /* everything created after here */
    SAVETMPS;                                        /* ...is a temporary variable.   */
    PUSHMARK(SP);                                    /* remember the stack pointer    */

    /* Ethernet addresses are 6 bytes. Add in room for deliminating 
       colons and the trailing NULL and you're at 18 characters. */
    EthAddrToString(((u_char *) client_address), (char *) &ea);

    /* Push them on in order */
    XPUSHs(sv_2mortal(newSVuv(TransactionID)));        /* push the base onto the stack  */
    XPUSHs(sv_2mortal(newSVpvn((char *) &ea, 17)));    /* push the base onto the stack  */
    XPUSHs(sv_2mortal(newSVpv(inet_ntoa(*released_ip), 0))); /* newSVpv makes a copy */
    XPUSHs(sv_2mortal(newSVpv(inet_ntoa(*gateway_ip), 0)));  /* newSVpv makes a copy */

    PUTBACK;                                        /* make local stack pointer global */
    call_pv("dhcp_release", G_VOID | G_EVAL);    /* call the function             */
    SPAGAIN;                                        /* refresh stack pointer         */

    if (SvTRUE(ERRSV)) {
        fprintf(stderr, "Error calling dhcp_release. %s\n", SvPV(get_sv("@", 0), n_a));
    }

    PUTBACK;
    FREETMPS;                                        /* free that return value        */
    LEAVE;                                            /* ...and the XPUSHed "mortal" args.*/
 }

void back_dispatch_decline(struct ether_addr *client_address, 
                           struct in_addr *gateway_ip, u_int32_t TransactionID)
{
    char ea[18];
    STRLEN n_a;
    dSP;                                            /* initialize stack pointer      */
    ENTER;                                            /* everything created after here */
    SAVETMPS;                                        /* ...is a temporary variable.   */
    PUSHMARK(SP);                                    /* remember the stack pointer    */

    /* Ethernet addresses are 6 bytes. Add in room for deliminating 
       colons and the trailing NULL and you're at 18 characters. */
    EthAddrToString(((u_char *) client_address), (char *) &ea);

    /* Push them on in order */
    XPUSHs(sv_2mortal(newSVuv(TransactionID)));        /* push the base onto the stack  */
    XPUSHs(sv_2mortal(newSVpvn((char *) &ea, 17)));    /* push the base onto the stack  */
    XPUSHs(sv_2mortal(newSVpv(inet_ntoa(*gateway_ip), 0)));  /* newSVpv makes a copy */

    PUTBACK;                                        /* make local stack pointer global */
    call_pv("dhcp_decline", G_VOID | G_EVAL);        /* call the function             */
    SPAGAIN;                                        /* refresh stack pointer         */

    if (SvTRUE(ERRSV)) {
        fprintf(stderr, "Error calling dhcp_decline. %s\n", SvPV(get_sv("@", 0), n_a));
    }

    PUTBACK;
    FREETMPS;                                        /* free that return value        */
    LEAVE;                                            /* ...and the XPUSHed "mortal" args.*/
}

int back_init(int argc, char **argv)
{
    // char *embedding[] = { "", "dhcpsrv.pl" }; 
    int r;

    PERL_SYS_INIT(&argc, &argv);
    my_perl = perl_alloc();

    if (my_perl == NULL) return 0;

    perl_construct(my_perl);
    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
    r = perl_parse(my_perl, xs_init, argc, argv, (char **)NULL);
    perl_run(my_perl);

    if (r != 0) return 0;
    return 1;
}

void back_free()
{
    perl_destruct(my_perl);
    perl_free(my_perl);
    PERL_SYS_TERM();
}
