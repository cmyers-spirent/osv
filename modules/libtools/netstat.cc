/*
 * Copyright (C) 2019 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <bsd/porting/netport.h>
#include <bsd/porting/route.h>

#include <bsd/sys/sys/sysctl.h>
#include <bsd/sys/sys/socket.h>
#include <bsd/sys/sys/socketvar.h>
#include <bsd/sys/netinet/in.h>
#include <bsd/sys/netinet/ip_var.h>
#include <bsd/sys/netinet/in_pcb.h>
#include <bsd/sys/netinet/tcp_var.h>
#include <bsd/sys/netinet/tcp_fsm.h>
#include <bsd/sys/netinet/udp.h>
#include <bsd/sys/netinet/udp_var.h>

#include <bsd/sys/compat/linux/linux.h>
#include <bsd/sys/compat/linux/linux_socket.h>

#include <errno.h>
#include <sys/sysctl.h>

#include "netstat.hh"


namespace osv {

static inline void format_ip(std::string &str, int family, void *addr)
{
    char ipstr[INET6_ADDRSTRLEN];
    if (inet_ntop(family, addr, ipstr, sizeof(ipstr)) == 0)
        str = "????";
    else
        str = ipstr;
}

static inline void format_tcp_state(std::string &str, int state)
{
    struct sn {
        int state;
        const char *name;
    } states [] = { 
        { TCPS_CLOSED, "CLOSED" },
        { TCPS_LISTEN, "LISTEN" },
        { TCPS_SYN_SENT, "SYN_SENT" },
        { TCPS_SYN_RECEIVED, "SYN_RECEIVED" },
        { TCPS_ESTABLISHED, "ESTABLISHED" },
        { TCPS_CLOSE_WAIT, "CLOSE_WAIT" },
        { TCPS_FIN_WAIT_1, "FIN_WAIT_1" },
        { TCPS_CLOSING, "CLOSING" },
        { TCPS_LAST_ACK, "LAST_ACK" },
        { TCPS_FIN_WAIT_2, "FIN_WAIT_2" },
        { TCPS_TIME_WAIT, "TIME_WAIT" }
    };

    for (auto&& s : states) {
        if (s.state == state) {
            str = s.name;
            return;
        } 
    }

    char buf[16];
    snprintf(buf, sizeof(buf), "state=%d?", state);
    str = buf;
}

static void format_proto(std::string &str, int proto, bool v6)
{
    if (proto == IPPROTO_TCP)
        str = v6 ? "tcp6" : "tcp";
    else if (proto == IPPROTO_UDP)
        str = v6 ? "udp6" : "udp";
    else {
        char buf[16];
        snprintf(buf, sizeof(buf), "proto=%d?", proto);
        str = buf;
    }
}

static int foreach_protocol_pcb(int proto, int proto_ctl, pcb_stats_fun fun)
{
    struct xinpgen *inpg;
    char *sp, *ep, *cp, *np;
    size_t needed = -1;
    int mib[4];
    char ipstr[INET6_ADDRSTRLEN];

    mib[0] = CTL_NET;
    mib[1] = PF_INET;
    mib[2] = proto;
    mib[3] = proto_ctl;

    if (osv_sysctl(mib, 4, NULL, &needed, NULL, 0) < 0) {
        fprintf(stderr, "PCBLIST sysctl failed to get buffer size\n");
        return errno;
    }

    std::vector<char> sp_buffer(needed);
    sp = &sp_buffer[0];
    if (osv_sysctl(mib, 4, sp, &needed, NULL, 0) < 0) {
        fprintf(stderr, "PCBLIST sysctl failed\n");
        return errno;
    }
    ep = sp + needed;

    inpg = (struct xinpgen *) sp;
    /* skip xinpgen structure at start of buffer */
    cp = ((char*) inpg) + inpg->xig_len;
    /* stop before 2nd xinpgen at end of buffer */
    ep = ep - inpg->xig_len;

    bool more = true;
    for (; cp < ep && more; cp = np)
    {
        struct pcb_stats stats;
        struct xsocket *xsocket = NULL;
        struct inpcb_stats *inpcb_stats = NULL;

        if (proto == IPPROTO_TCP)
        {
            struct xtcpcb *tcpcb = (struct xtcpcb *) cp;
            np = cp + tcpcb->xt_len;
            inpcb_stats = &tcpcb->xt_inp;
            xsocket = &tcpcb->xt_socket;
            format_tcp_state(stats.state, tcpcb->xt_tp.t_state);
        }
        else
        {
            struct xinpcb *inpcb = (struct xinpcb *) cp;
            np = cp + inpcb->xi_len;
            inpcb_stats = &inpcb->xi_inp;
            xsocket = &inpcb->xi_socket;
        }

        auto &conninfo = inpcb_stats->inp_inc;

        format_proto(stats.proto, proto, !!(conninfo.inc_flags & INC_ISIPV6));
        if (conninfo.inc_flags & INC_ISIPV6) {
            format_ip(stats.foreign_addr, LINUX_AF_INET6, &conninfo.inc_ie.ie_dependfaddr.ie6_foreign);
            format_ip(stats.local_addr, LINUX_AF_INET6, &conninfo.inc_ie.ie_dependladdr.ie6_local);
        } else {
            format_ip(stats.foreign_addr, LINUX_AF_INET, &conninfo.inc_ie.ie_dependfaddr.ie46_foreign.ia46_addr4);
            format_ip(stats.local_addr, LINUX_AF_INET, &conninfo.inc_ie.ie_dependladdr.ie46_local.ia46_addr4);
        }
        stats.foreign_port = ntohs(conninfo.inc_ie.ie_fport);
        stats.local_port = ntohs(conninfo.inc_ie.ie_lport);


        stats.txq_bytes = xsocket->so_snd.sb_cc;
        stats.rxq_bytes = xsocket->so_rcv.sb_cc;

        more = fun(stats);
    }

    return 0;
}

int foreach_tcp_session(pcb_stats_fun fun)
{
    return foreach_protocol_pcb(IPPROTO_TCP, TCPCTL_PCBLIST, fun);
}

int foreach_udp_session(pcb_stats_fun fun)
{
    return foreach_protocol_pcb(IPPROTO_UDP, UDPCTL_PCBLIST, fun);
}

int get_tcp_stats(struct tcpstat &stats)
{
    size_t needed = sizeof(stats);
    int mib[4];

    mib[0] = CTL_NET;
    mib[1] = PF_INET;
    mib[2] = IPPROTO_TCP;
    mib[3] = TCPCTL_STATS;

    if (osv_sysctl(mib, 4, &stats, &needed, NULL, 0) < 0) {
        fprintf(stderr, "TCPCTL_STATS sysctl failed\n");
        return errno;
    }

    return 0;
}

int get_udp_stats(struct udpstat &stats)
{
    size_t needed = sizeof(stats);
    int mib[4];

    mib[0] = CTL_NET;
    mib[1] = PF_INET;
    mib[2] = IPPROTO_UDP;
    mib[3] = UDPCTL_STATS;

    if (osv_sysctl(mib, 4, &stats, &needed, NULL, 0) < 0) {
        fprintf(stderr, "UDPCTL_STATS sysctl failed\n");
        return errno;
    }

    return 0;
}

}
