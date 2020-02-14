#include <stdlib.h>

#include <bsd/sys/sys/param.h>
#include <bsd/sys/sys/mbuf.h>
#include <bsd/sys/sys/queue.h>
#include <bsd/sys/net/if_dl.h>
#include <bsd/sys/net/if_var.h>
#include <bsd/sys/net/ethernet.h>
#include <bsd/sys/netinet/in.h>
#include <bsd/sys/netinet/ip6.h>
#include <bsd/sys/netinet6/in6.h>
#include <bsd/sys/netinet6/in6_var.h>
#include <bsd/sys/netinet/icmp6.h>
#include <bsd/sys/netinet6/scope6_var.h>
#include <bsd/sys/sys/mbuf.h>

#include <bsd/porting/networking.hh>
#include <bsd/porting/route.h>

#include <osv/debug.hh>
#include <osv/clock.hh>
#include <osv/debug.h>

// FIXME: inet_pton() is from musl which uses different AF_INET6
#define LINUX_AF_INET6 10

namespace osv {

static bool get_ipv6_link_local_addr(const std::string &if_name, struct in6_addr &addr)
{
    struct ifnet *ifp;
    struct bsd_ifaddr *ifa;
    bool found = false;

    if (if_name.empty()) {
        return false;
    }

    ifp = ifunit_ref(if_name.c_str());
    if (!ifp) {
        fprintf(stderr, "Unable to interface %s\n", if_name.c_str());
        return (ENOENT);
    }

    /* Find IPv6 link local to send solicit from */
    IF_ADDR_RLOCK(ifp);
    TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
            struct in6_ifaddr *ia;
            if (ifa->ifa_addr->sa_family != AF_INET6)
                    continue;

            ia = (struct in6_ifaddr *)ifa;

            if (IN6_IS_ADDR_LINKLOCAL(IA6_IN6(ia))) {
                addr = *IA6_IN6(ia);
                in6_clearscope(&addr);
                found = true;
                break;
            }
    }
    IF_ADDR_RUNLOCK(ifp);

    if_rele(ifp);
    return found;
}

int send_ipv6_router_solicit(const std::string &if_name)
{
    int error;
    struct bsd_sockaddr_in6 src_addr, dst_addr;
    struct ifnet *ifp;
    struct mbuf *m = NULL;
    const size_t icmp_len = sizeof(struct nd_router_solicit);
    struct ip6_hdr *ip6;
    struct nd_router_solicit * rs;
    char ip6bufs[INET6_ADDRSTRLEN];

    if (inet_pton(LINUX_AF_INET6, "ff02::2", &dst_addr.sin6_addr) != 1) {
        fprintf(stderr, "Failed to convert IPv6 address %s\n", "ff02::2");
        return (EINVAL);
    }
    dst_addr.sin6_family = AF_INET6;
    dst_addr.sin6_len = sizeof(dst_addr);

    if (if_name.empty()) {
        return (EINVAL);
    }

    /* IF Name */
    ifp = ifunit_ref(if_name.c_str());
    if (!ifp) {
        fprintf(stderr, "Unable to interface %s\n", if_name.c_str());
        return (ENOENT);
    }

    /* Find IPv6 link local to send solicit from */
    if (!get_ipv6_link_local_addr(if_name, src_addr.sin6_addr)) {
        fprintf(stderr, "Unable to find link local address for %s\n", if_name.c_str());
        error = EINVAL;
        goto out;
    }
    src_addr.sin6_family = AF_INET6;
    src_addr.sin6_len = sizeof(src_addr);

    m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    if (!m) {
        fprintf(stderr, "Error allocating mbuf\n");
        error = ENOMEM;
        goto out;
    }

    // Ethernet driver will add L2 header, so reserve leading space for it
    m->m_hdr.mh_data += sizeof(struct ether_header);
    // Set length in mbuf
    m->M_dat.MH.MH_pkthdr.len = m->m_hdr.mh_len = sizeof(struct ip6_hdr) + icmp_len;
    m->m_hdr.mh_flags |= M_MCAST;

    ip6 = mtod(m, struct ip6_hdr *);
    memset(ip6, 0, sizeof(*ip6));
    ip6->ip6_vfc = IPV6_VERSION;
    ip6->ip6_nxt = IPPROTO_ICMPV6;
    ip6->ip6_src = src_addr.sin6_addr;
    ip6->ip6_dst = dst_addr.sin6_addr;
    ip6->ip6_plen = htons(icmp_len);
    ip6->ip6_hlim = 255;
    rs = (struct nd_router_solicit *)(ip6 + 1);
    memset(rs, 0, sizeof (*rs));
    rs->nd_rs_hdr.icmp6_type = ND_ROUTER_SOLICIT;
    rs->nd_rs_hdr.icmp6_code = 0;
    rs->nd_rs_hdr.icmp6_cksum = 0;
    rs->nd_rs_hdr.icmp6_cksum = in6_cksum(m, IPPROTO_ICMPV6, sizeof(struct ip6_hdr), icmp_len);

    // Transmit the packet directly over Ethernet
    fprintf(stderr, "Sending router solicit message from %s %s\n",
            if_name.c_str(), ip6_sprintf(ip6bufs, &ip6->ip6_src));
    error = ifp->if_output(ifp, m, (struct bsd_sockaddr *)&dst_addr, NULL);
    if (error) {
        fprintf(stderr, "Error sending router solicit %d\n", error);
        m_free(m);
    }

out:
    if_rele(ifp);
    return (error);
}

int send_ipv6_router_solicit()
{
    struct ifnet* ifp;
    struct in6_addr linklocal_addr;
    int error = 0;
    IFNET_RLOCK();
    TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
        if ((ifp->if_flags & IFF_DYING) || (ifp->if_flags & IFF_LOOPBACK))
            continue;

        // Sender router solicit so router will send router advertisement for gateway IP
        if (get_ipv6_link_local_addr(ifp->if_xname, linklocal_addr)) {
            error = osv::send_ipv6_router_solicit(ifp->if_xname);
            if (error) break;
        }
    }
    IFNET_RUNLOCK();
    return error;
}

}