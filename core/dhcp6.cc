/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <list>

#include <stdlib.h>

#include <bsd/sys/sys/param.h>
#include <bsd/sys/sys/mbuf.h>
#include <bsd/sys/sys/queue.h>
#include <bsd/sys/net/if_dl.h>
#include <bsd/sys/net/if_var.h>
#include <bsd/sys/net/ethernet.h>
#include <bsd/sys/sys/mbuf.h>
#include <machine/in_cksum.h>

#include <bsd/porting/networking.hh>
#include <bsd/porting/route.h>

#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <ifaddrs.h>

#include <osv/debug.hh>
#include <osv/dhcp6.hh>
#include <osv/clock.hh>
#include <osv/debug.h>

#include <libc/network/__dns.hh>

#define dhcp6_tag "dhcp6"
#if 1
#define dhcp_d(...)   tprintf_d(dhcp6_tag, __VA_ARGS__)
#define dhcp_i(...)   tprintf_i(dhcp6_tag, __VA_ARGS__)
#define dhcp_w(...)   tprintf_w(dhcp6_tag, __VA_ARGS__)
#define dhcp_e(...)   tprintf_e(dhcp6_tag, __VA_ARGS__)
#else
#define dhcp_d(...)   do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define dhcp_i(...)   do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define dhcp_w(...)   do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define dhcp_e(...)   do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#endif

// FIXME: boost address_v6 is pulling in Linux headers....
#define BSD_AF_INET6 28
#define LINUX_AF_INET6 10

#ifndef IPV6_VERSION
#define IPV6_VERSION         0x60
#endif

// FIXME: issues including in6.h
struct bsd_sockaddr_in6 {
        uint8_t         sin6_len;       /* length of this struct */
        bsd_sa_family_t sin6_family;    /* AF_INET6 */
        in_port_t       sin6_port;      /* Transport layer port # */
        uint32_t        sin6_flowinfo;  /* IP6 flow information */
        struct in6_addr sin6_addr;      /* IP6 address */
        uint32_t        sin6_scope_id;  /* scope zone index */
};

int in6_cksum(struct mbuf *, u_int8_t, u_int32_t, u_int32_t);

using namespace boost::asio;

dhcp6::dhcp_worker net_dhcp6_worker;

u16 dhcp6_requested_options[] = {
    htons(dhcp6::DHCP_OPTION_DNS_SERVERS),
    htons(dhcp6::DHCP_OPTION_DOMAIN_LIST),
};

namespace osv
{
    void dhcp6_set_if_enable(const std::string &if_name, bool enable)
    {
        net_dhcp6_worker.set_if_enable(if_name, enable);
    }

    bool dhcp6_get_if_enable(const std::string &if_name, bool &enable)
    {
        return net_dhcp6_worker.get_if_enable(if_name, enable);
    }

    void dhcp6_set_if_stateless(const std::string &if_name, bool enable)
    {
        net_dhcp6_worker.set_if_stateless(if_name, enable);
    }

    bool dhcp6_get_if_stateless(const std::string &if_name, bool &enable)
    {
        return net_dhcp6_worker.get_if_stateless(if_name, enable);
    }
}

// Returns whether we hooked the packet
int dhcp6_hook_rx(struct mbuf* m)
{
    dhcp6::dhcp_mbuf dm(false, m);

    // Filter only valid dhcp packets
    if (!dm.is_valid_dhcp()) {
        return 0;
    }

    // Queue the packet
    net_dhcp6_worker.queue_packet(m);

    return 1;
}

// Disable DHCPv4 if not explicitly enabled/disabled and DHCPv6 is set
// Disable DHCPv6 if not explicitly enabled/disabled and DHCPv4 is set
// This allows for IPv4/IPv6 only configurations
void dhcp6_check_config()
{
    struct ifnet* ifp;
    IFNET_RLOCK();
    TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
        if ((ifp->if_flags & IFF_DYING) || (ifp->if_flags & IFF_LOOPBACK))
            continue;

        bool dhcp_enable, dhcp_enable_is_set;
        bool dhcp6_enable, dhcp6_enable_is_set;
        dhcp_enable_is_set = osv::dhcp_get_if_enable(ifp->if_xname, dhcp_enable);
        dhcp6_enable_is_set = osv::dhcp6_get_if_enable(ifp->if_xname, dhcp6_enable);
        if (!dhcp_enable_is_set && (dhcp6_enable_is_set && dhcp6_enable))
            osv::dhcp_set_if_enable(ifp->if_xname, false);
        if (!dhcp6_enable_is_set && (dhcp_enable_is_set && dhcp_enable))
            osv::dhcp6_set_if_enable(ifp->if_xname, false);
    }
    IFNET_RUNLOCK();
}

void dhcp6_start(bool wait)
{
    // Initialize the global DHCP worker
    net_dhcp6_worker.init();
    net_dhcp6_worker.start_thread();
    net_dhcp6_worker.start(wait);
}

// Send DHCP release, for example at shutdown.
void dhcp6_release()
{
    net_dhcp6_worker.release();
    net_dhcp6_worker.stop_thread();
}

void dhcp6_renew(bool wait)
{
    net_dhcp6_worker.renew(wait);
}

void dhcp6_shutdown()
{
    net_dhcp6_worker.stop_thread();
}

static std::string to_string(const osv::clock::uptime::time_point &tp) {
    auto duration = tp.time_since_epoch();
    auto msec = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
    std::stringstream os;
    os << msec.count();
    return os.str();
}


namespace dhcp6 {

    constexpr u16 min_ip_len = sizeof(struct ip6_hdr);
    constexpr u16 udp_len = sizeof(struct udphdr);
    constexpr u16 min_options_len = 4;
    constexpr u16 min_dhcp_len = sizeof(struct dhcp_packet) + min_options_len;

    const ip::address_v6 ipv6_zero = ip::address_v6::address_v6::from_string("::");
    const ip::address_v6 dhcpv6_multicast_addr = ip::address_v6::address_v6::from_string("ff02::1:2");

    osv::clock::uptime::time_point clock_zero = osv::clock::uptime::time_point();

    static std::map<dhcp_message_type,const char*> dhcp_message_type_name_by_id = {
        {DHCP_MT_SOLICIT, "DHCPv6_SOLICIT"},
        {DHCP_MT_ADVERTISE, "DHCPv6_ADVERTISE"},
        {DHCP_MT_REQUEST, "DHCPv6_REQUEST"},
        {DHCP_MT_CONFIRM, "DHCPv6_CONFIRM"},
        {DHCP_MT_RENEW, "DHCPv6_RENEW"},
        {DHCP_MT_REBIND, "DHCPv6_REBIND"},
        {DHCP_MT_REPLY, "DHCPv6_REPLY"},
        {DHCP_MT_RELEASE, "DHCPv6_RELEASE"},
        {DHCP_MT_DECLINE, "DHCPv6_DECLLINE"},
        {DHCP_MT_RECONFIGURE, "DHCPv6_RECONFIGURE"},
        {DHCP_MT_INFOREQUEST, "DHCPv6_INFOREQUEST"},
        {DHCP_MT_RELAYFORWARD, "DHCPv6_RELAYFORWARD"},
        {DHCP_MT_RELAYREPLY, "DHCPv6_RELAYREPLY"},
        {DHCP_MT_INVALID, "DHCPv6_INVALID"}
    };

    ///////////////////////////////////////////////////////////////////////////

    bool dhcp_socket::dhcp_send(dhcp_mbuf& packet)
    {
        struct bsd_sockaddr_in6 dst = {};
        struct mbuf *m = packet.get();
        struct ip6_hdr* ip6 = reinterpret_cast<struct ip6_hdr*>(mtod(m, u8*));

        if (IN6_IS_ADDR_MULTICAST(ip6->ip6_dst.s6_addr))
            m->m_hdr.mh_flags |= M_MCAST;

        dst.sin6_family = BSD_AF_INET6;
        dst.sin6_len = sizeof(dst);
        memcpy(&dst.sin6_addr, &ip6->ip6_dst, sizeof(dst.sin6_addr));

        // Transmit the packet directly over Ethernet
        int c;
        if (!_output_handler){
            c = _ifp->if_output(_ifp, packet.get(), (struct bsd_sockaddr *)&dst, NULL);
        }
        else {
            M_PREPEND(m, ETHER_HDR_LEN, M_DONTWAIT);
            if (m) {
                // For test purposes include ethernet header as would be appended by driver
                struct ether_header *eh = mtod(m, struct ether_header *);
                ip6 = reinterpret_cast<struct ip6_hdr*>(mtod(m, u8*) + sizeof(*eh));
                u8 dst_addr[6];
                eh->ether_type = htons(ETHERTYPE_IPV6);
                if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
                    dst_addr[0] = 0x33;
                    dst_addr[1] = 0x33;
                    dst_addr[2] = ip6->ip6_dst.s6_addr[12];
                    dst_addr[3] = ip6->ip6_dst.s6_addr[13];
                    dst_addr[4] = ip6->ip6_dst.s6_addr[14];
                    dst_addr[5] = ip6->ip6_dst.s6_addr[15];
                } else {
                    memset(dst_addr, 0, sizeof(dst_addr));
                }
                memcpy(eh->ether_dhost, dst_addr, sizeof (eh->ether_dhost));
                memcpy(eh->ether_shost, IF_LLADDR(_ifp), sizeof(eh->ether_shost));
                // Skip over the header when pased to dhcp output handler
                m->m_hdr.mh_data += sizeof(struct ether_header);

                // For unit tests, pass the rcvif so unit tests know which
                // interface to send back to
                m->M_dat.MH.MH_pkthdr.rcvif = _ifp;
                c = _output_handler(m);
            }
            else {
                dhcp_e("Error prepending Ethernet header to DHCPv6 packet!");
                c = 1;
            }
        }

        return (c == 0);
    }

    void dhcp_socket::set_output_handler(std::function<int (struct mbuf *)> handler)
    {
        _output_handler = handler;
    }

    ///////////////////////////////////////////////////////////////////////////

    dhcp_mbuf::dhcp_mbuf(bool attached, struct mbuf* m)
        : _attached(attached), _m(m), _ip_len(min_ip_len)
    {
        if (m == nullptr) {
            allocate_mbuf();
        }
    }

    dhcp_mbuf::~dhcp_mbuf()
    {
        if (_attached) {
            m_free(_m);
        }
    }

    void dhcp_mbuf::detach()
    {
        _attached = false;
    }

    struct mbuf* dhcp_mbuf::get()
    {
        return _m;
    }

    void dhcp_mbuf::set(struct mbuf* m)
    {
        _m = m;
    }

    bool dhcp_mbuf::is_valid_dhcp()
    {
        if (!decode_ip())
            return false;
    
        struct udphdr* udp = pudp();

        if (_m->m_hdr.mh_len < _ip_len + dhcp6::udp_len + dhcp6::min_dhcp_len) {
            return false;
        }

        if ((_ip_proto != IPPROTO_UDP) || (udp->uh_dport != ntohs(dhcp_client_port))) {
            return false;
        }

        // FIXME: checksums

        return true;
    }

    void dhcp_mbuf::allocate_mbuf()
    {
        _m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
        if (_m) {
            // Ethernet driver will add L2 header, so reserve leading space for it
            _m->m_hdr.mh_data += sizeof(struct ether_header);
        }
    }

    void dhcp_mbuf::compose_solicit(struct ifnet* ifp,
                                    u32 xid,
                                    u16 elapsed_time,
                                    const ip::address_v6 &client_ip,
                                    const dhcp_uid &client_id)
    {
        size_t dhcp_len = sizeof(struct dhcp_packet);
        struct dhcp_packet* pkt = pdhcp();

        // Header
        pkt->type = DHCP_MT_SOLICIT;
        set_xid(pkt->xid, xid);

        // Options
        u8* options_start = reinterpret_cast<u8*>(pkt+1);
        u8* options = options_start;

        // Add client ID option
        options = add_option(options, DHCP_OPTION_CLIENTID, client_id.get_size(), client_id.get_data());
        options = add_option(options, DHCP_OPTION_OPTIONREQUEST,
            sizeof(dhcp6_requested_options), (u8*)dhcp6_requested_options);
        options = add_ia_na_option(options, *(u32*)(IF_LLADDR(ifp) + 2), nullptr, 0, 0);

        options = add_elapsed_time_option(options, elapsed_time);

        dhcp_len += options - options_start;
        build_udp_ip_headers(dhcp_len, client_ip, dhcpv6_multicast_addr);
    }

    void dhcp_mbuf::compose_request(struct ifnet* ifp,
                                    u32 xid,
                                    u16 elapsed_time,
                                    const ip::address_v6 &client_ip,
                                    const ip::address_v6 &server_ip,
                                    const dhcp_uid &client_id,
                                    const dhcp_uid &server_id,
                                    std::string hostname)
    {
        size_t dhcp_len = sizeof(struct dhcp_packet);
        struct dhcp_packet* pkt = pdhcp();

        // Header
        pkt->type = DHCP_MT_REQUEST;
        set_xid(pkt->xid, xid);

        // Options
        u8* options_start = reinterpret_cast<u8*>(pkt+1);
        u8* options = options_start;

        options = add_option(options, DHCP_OPTION_CLIENTID, client_id.get_size(), client_id.get_data());
        options = add_option(options, DHCP_OPTION_SERVERID, server_id.get_size(), server_id.get_data());

        options = add_option(options, DHCP_OPTION_OPTIONREQUEST,
            sizeof(dhcp6_requested_options), (u8*)dhcp6_requested_options);
        // TODO: Not sure if IA_NA is required
        options = add_ia_na_option(options, *(u32*)(IF_LLADDR(ifp) + 2), nullptr, 0, 0);

        options = add_elapsed_time_option(options, elapsed_time);

        dhcp_len += options - options_start;

        build_udp_ip_headers(dhcp_len, client_ip, server_ip);
    }

    void dhcp_mbuf::compose_renew(struct ifnet* ifp,
                                  dhcp_message_type message_type,
                                  u32 xid,
                                  u16 elapsed_time,
                                  const ip::address_v6 &client_ip,
                                  const ip::address_v6 &server_ip,
                                  const dhcp_uid &client_id,
                                  const dhcp_uid &server_id,
                                  u32 ia_id,
                                  const ip::address_v6 &ia_addr,
                                  std::string hostname)
    {
        size_t dhcp_len = sizeof(struct dhcp_packet);
        struct dhcp_packet* pkt = pdhcp();

        // Header
        pkt->type = message_type;
        set_xid(pkt->xid, xid);

        // Options
        u8* options_start = reinterpret_cast<u8*>(pkt+1);
        u8* options = options_start;

        options = add_option(options, DHCP_OPTION_CLIENTID, client_id.get_size(), client_id.get_data());
        options = add_option(options, DHCP_OPTION_SERVERID, server_id.get_size(), server_id.get_data());

        options = add_option(options, DHCP_OPTION_OPTIONREQUEST,
            sizeof(dhcp6_requested_options), (u8*)dhcp6_requested_options);
        options = add_ia_na_option(options, ia_id, ia_addr.to_bytes().data(), 0, 0);

        options = add_elapsed_time_option(options, elapsed_time);

        dhcp_len += options - options_start;

        build_udp_ip_headers(dhcp_len, client_ip, server_ip);
    }

    void dhcp_mbuf::compose_release(struct ifnet* ifp,
                                    u32 xid,
                                    u16 elapsed_time,
                                    const ip::address_v6 &client_ip,
                                    const ip::address_v6 &server_ip,
                                    const dhcp_uid &client_id,
                                    const dhcp_uid &server_id,
                                    u32 ia_id,
                                    const boost::asio::ip::address_v6 &ia_addr)
    {
        size_t dhcp_len = sizeof(struct dhcp_packet);
        struct dhcp_packet* pkt = pdhcp();
        *pkt = {};

        pkt->type = DHCP_MT_RELEASE;
        set_xid(pkt->xid, xid);

        // Options
        u8* options_start = reinterpret_cast<u8*>(pkt+1);
        u8* options = options_start;

        options = add_option(options, DHCP_OPTION_CLIENTID, client_id.get_size(), client_id.get_data());
        options = add_option(options, DHCP_OPTION_SERVERID, server_id.get_size(), server_id.get_data());
        options = add_ia_na_option(options, ia_id, ia_addr.to_bytes().data(), 0, 0);
        options = add_elapsed_time_option(options, elapsed_time);

        dhcp_len += options - options_start;
        build_udp_ip_headers(dhcp_len, client_ip, server_ip);
    }

    bool dhcp_mbuf::decode_ip()
    {
        struct ip6_hdr* ip6 = pip6();
        int off = sizeof(*ip6);
        u8 nxt = ip6->ip6_nxt;

        // Parse IPv6 extension headers
        while (1) {
            struct ip6_ext *ip6e = NULL;
            int elen;
            switch(nxt) {
                case IPPROTO_DSTOPTS:
                case IPPROTO_ROUTING:
                case IPPROTO_HOPOPTS:
                case IPPROTO_FRAGMENT:
                case IPPROTO_ESP:
                    if (off + (int)sizeof(*ip6e) > _m->m_hdr.mh_len)
                        return false;
                    ip6e = (struct ip6_ext *)(mtod(_m, caddr_t) + off);
                    elen = (ip6e->ip6e_len + 1) << 3;
                    break;
                case IPPROTO_AH:
                    if (off + (int)sizeof(*ip6e) > _m->m_hdr.mh_len)
                        return false;
                    ip6e = (struct ip6_ext *)(mtod(_m, caddr_t) + off);
                    elen = (ip6e->ip6e_len + 1) << 2;
                    break;
                default:
                    _ip_proto = nxt;
                    _ip_len = off;
                    return true;
            }
            if (off + elen > _m->m_hdr.mh_len)
                return -1;
            off += elen;
            nxt = ip6e->ip6e_nxt;
        }
    }

    bool dhcp_mbuf::decode()
    {
        if (!decode_ip())
            return false;

        dhcp_i("Received %s message from DHCPv6 server: %s",
               dhcp_message_type_name_by_id[get_message_type()], get_ipv6_src_addr().to_string().c_str());

        return true;
    }

    const struct dhcp_option *dhcp_mbuf::find_option(u16 type) const
    {
        // Parse options
        const u8* end = mtod(_m, u8*) + _m->m_hdr.mh_len;
        return dhcp6::find_option(poptions(), end, type);
    }

    dhcp_message_type dhcp_mbuf::get_message_type()
    {
        return (dhcp_message_type) pdhcp()->type;
    }

    u32 dhcp_mbuf::get_xid()
    {
        u32 xid;
        dhcp6::get_xid(pdhcp()->xid, xid);
        return xid;
    }

    boost::asio::ip::address_v6 dhcp_mbuf::get_ipv6_src_addr() const
    {
	    ip::address_v6::bytes_type bytes;
        memcpy(&bytes, &pip6()->ip6_src, sizeof(bytes));
        return ip::address_v6(bytes);
    }

    boost::asio::ip::address_v6 dhcp_mbuf::get_ipv6_dst_addr() const
    {
	    ip::address_v6::bytes_type bytes;
        memcpy(&bytes, &pip6()->ip6_dst, sizeof(bytes));
        return ip::address_v6(bytes);
    }

    bool dhcp_mbuf::get_client_id(dhcp_uid &client_id) const
    {
        const struct dhcp_option *opt = find_option(DHCP_OPTION_CLIENTID);
        if (!opt)
            return false;
        client_id.set((const u8 *)(opt + 1), ntohs(opt->len));
        return true;
    }

    bool dhcp_mbuf::get_server_id(dhcp_uid &server_id) const
    {
        const struct dhcp_option *opt = find_option(DHCP_OPTION_SERVERID);
        if (!opt)
            return false;
        server_id.set((const u8 *)(opt + 1), ntohs(opt->len));
        return true;
    }

    bool dhcp_mbuf::get_unicast_addr(boost::asio::ip::address_v6 &addr) const
    {
        const struct dhcp_option *opt = find_option(DHCP_OPTION_UNICAST);
        if (!opt || ntohs(opt->len) != 16)
            return false;

        ip::address_v6::bytes_type bytes;
        const u8 *ip6_addr = (const u8*)(opt + 1);
        memcpy(&bytes, ip6_addr, sizeof(bytes));
        addr = ip::address_v6(bytes);
        return true;
    }

    bool dhcp_mbuf::get_status_code(dhcp_status_code &code, std::string &message) const
    {
        const struct dhcp_option *opt = find_option(DHCP_OPTION_STATUS_CODE);
        if (opt)
            return get_status_code(opt, code, message);
        return false;
    }

    bool dhcp_mbuf::get_status_code(const struct dhcp_option *opt, dhcp_status_code &code, std::string &message) const
    {
        struct dhcp_option hopt = { .type = ntohs(opt->type), .len = ntohs(opt->len) };
        if (hopt.type != DHCP_OPTION_STATUS_CODE)
            return false;

        const u8 *p = (const u8 *)(opt);
        const u8 *pend = (p + hopt.len);

        p += sizeof(*opt);
        code = (dhcp_status_code) ntohs(*(const u16 *)(p));
        p += sizeof(u16);
        message.clear();
        message.append((const char *)p, (const char *)pend);
        return true;
    }

    struct ip6_hdr* dhcp_mbuf::pip6()
    {
        return mtod(_m, struct ip6_hdr*);
    }

    struct udphdr* dhcp_mbuf::pudp()
    {
        return reinterpret_cast<struct udphdr*>(mtod(_m, u8*) + _ip_len);
    }

    struct dhcp_packet* dhcp_mbuf::pdhcp()
    {
        return reinterpret_cast<struct dhcp_packet*>(mtod(_m, u8*) + _ip_len + udp_len);
    }

    u8* dhcp_mbuf::poptions()
    {
        return (reinterpret_cast<u8*>(pdhcp()+1));
    }

    const struct ip6_hdr* dhcp_mbuf::pip6() const
    {
        return const_cast<dhcp_mbuf *>(this)->pip6();
    }

    const struct udphdr* dhcp_mbuf::pudp() const
    {
        return const_cast<dhcp_mbuf *>(this)->pudp();
    }

    const struct dhcp_packet* dhcp_mbuf::pdhcp() const
    {
        return const_cast<dhcp_mbuf *>(this)->pdhcp();
    }

    const u8* dhcp_mbuf::poptions() const
    {
        return const_cast<dhcp_mbuf *>(this)->poptions();
    }

    size_t dhcp_mbuf::get_options_len() const
    {
        return _m->m_hdr.mh_len - _ip_len + udp_len - sizeof(struct dhcp_packet);
    }

    void dhcp_mbuf::build_udp_ip_headers(size_t dhcp_len, const ip::address_v6 &src_addr, const ip::address_v6 &dest_addr)
    {
        struct ip6_hdr* ip6 = pip6();
        struct udphdr* udp = pudp();

        // Set length in mbuf
        _m->M_dat.MH.MH_pkthdr.len = _m->m_hdr.mh_len = min_ip_len + udp_len + dhcp_len;

        // IP
        memset(ip6, 0, sizeof(*ip6));
        ip6->ip6_vfc = IPV6_VERSION;
        ip6->ip6_nxt = IPPROTO_UDP;
        memcpy(&ip6->ip6_src, src_addr.to_bytes().data(), sizeof(ip6->ip6_src));
        memcpy(&ip6->ip6_dst, dest_addr.to_bytes().data(), sizeof(ip6->ip6_dst));
        ip6->ip6_plen = htons(udp_len + dhcp_len);

        // UDP
        memset(udp, 0, sizeof(*udp));
        udp->uh_sport = htons(dhcp_client_port);
        udp->uh_dport = htons(dhcp_server_port);
        udp->uh_ulen = htons(udp_len + dhcp_len);
        udp->uh_sum = 0;
        udp->uh_sum = in6_cksum(_m, IPPROTO_UDP, ((uintptr_t)udp - (uintptr_t)ip6), udp_len + dhcp_len);
    }

    ///////////////////////////////////////////////////////////////////////////

    dhcp_interface_state::dhcp_interface_state(dhcp_worker* worker, struct ifnet* ifp, bool stateless)
        : _state(DHCP_INIT), _stateless(stateless), _worker(worker), _ifp(ifp)
    {
        _sock = new dhcp_socket(ifp);
        _xid = 0;
        _client_addr = _server_addr = ipv6_zero;
        _ia_refresh_msg_type = DHCP_MT_INVALID;
        _unicast = false;

        _client_id.set_ll(HTYPE_ETHERNET, (u8*)IF_LLADDR(ifp), ETHER_ADDR_LEN);
        update_linklocal_addr();
    }

    dhcp_interface_state::~dhcp_interface_state()
    {
        delete _sock;
    }

    bool dhcp_interface_state::is_bound() const
    {
        return (_client_addr != ipv6_zero);
    }

    void dhcp_interface_state::update_linklocal_addr()
    {
        struct ifaddrs *ifaddr = NULL, *ifa;

        if (getifaddrs(&ifaddr) != 0) {
            dhcp_e("Unable to get link local IPv6 for %s.  getifaddrs() failed.", _ifp->if_xname);
            return;
        }

        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (strcmp(ifa->ifa_name, _ifp->if_xname) != 0)
                continue;
            if (ifa->ifa_addr->sa_family == LINUX_AF_INET6) {
                auto &ip6 = ((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
                if (IN6_IS_ADDR_LINKLOCAL(ip6.s6_addr)) {
                    break;
                }
            }
        }

        if (ifa) {
            auto &ip6 = ((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
            ip::address_v6::bytes_type bytes;
            memcpy(&bytes, &ip6, sizeof(bytes));
            _client_linklocal_addr = ip::address_v6(bytes);
            dhcp_i("DHCPv6 using link local IPv6 %s on %s", _client_linklocal_addr.to_string().c_str(), _ifp->if_xname);
            printf("DHCPv6 using link local IPv6 %s on %s\n", _client_linklocal_addr.to_string().c_str(), _ifp->if_xname);
        } else {
            dhcp_e("Unable to get link local IPv6 for %s. no link local IPv6 address found.", _ifp->if_xname);
        }
        freeifaddrs(ifaddr);   
    }

    double dhcp_interface_state::timeout_rand()
    {
        return -0.1 + (rand()/(RAND_MAX/(.2)));
    }

    /*
     * Retry timeout backoff algorithm.
     *
     * RFC 3315 Section 14 Reliability of Client Initiated Message Exchanges
     */
    void dhcp_interface_state::rexmit_init()
    {
        rexmit_init( osv::clock::uptime::now());
    }

    void dhcp_interface_state::rexmit_init(const osv::clock::uptime::time_point &start)
    {
        _rexmit_start_time = start;
        _rexmit.rt = _rexmit.irt  + (timeout_rand() * _rexmit.irt);
        _rexmit.rc = 0;
        _xid = generate_xid();
    }

    void dhcp_interface_state::rexmit_next()
    {
        if (_rexmit.mrt && _rexmit.rt > _rexmit.mrt)
            _rexmit.rt = _rexmit.mrt + (timeout_rand() * _rexmit.mrt);
        else
            _rexmit.rt = (2 * _rexmit.rt) + (timeout_rand() * _rexmit.rt);
        ++_rexmit.rc;
    }

    bool dhcp_interface_state::rexmit_ok() const
    {
        if (_rexmit.mrc && _rexmit.rc > _rexmit.mrc)
            return false;
        if (_rexmit.rc > 0 && _rexmit.mrd) {
            auto dt = osv::clock::uptime::now() - _rexmit_start_time;
            if (dt >= std::chrono::milliseconds(_rexmit.mrd))
                return false;
        }
        return true;
    }

    u16 dhcp_interface_state::rexmit_get_elapsed_time() const
    {
        if (_rexmit.rc == 0)
            return 0; // 1st transmission so elapsed time is 0

        auto dt = osv::clock::uptime::now() - _rexmit_start_time;
        auto msec = std::chrono::duration_cast<std::chrono::milliseconds>(dt).count(); 
        return (u16)std::min(msec/10, 0xffffL); // hundredths of a second (10^-2 seconds)
    }

    osv::clock::uptime::time_point dhcp_interface_state::rexmit_get_timeout() const
    {
        auto t = osv::clock::uptime::now() + std::chrono::milliseconds(_rexmit.rt);
        if (_rexmit.mrd)
            return std::min(t, _rexmit_start_time + std::chrono::milliseconds(_rexmit.mrd));
        return t;
    }

    void dhcp_interface_state::discover()
    {
        if (_state != DHCP_DISCOVER) {
            _state = DHCP_DISCOVER;
            _rexmit.irt = SOL_TIMEOUT * SEC2MSEC;
            _rexmit.mrt = SOL_MAX_RT * SEC2MSEC; 
            _rexmit.mrd = 0;
            _rexmit.mrc = 0;
            rexmit_init();
        } else {
            rexmit_next();
        }

        // Compose a dhcp solicit packet
        dhcp_mbuf dm(false);
        dm.compose_solicit(_ifp, _xid, rexmit_get_elapsed_time(), _client_linklocal_addr, _client_id);

        // Clear state
        _ia_id = 0;
        _client_addr = _server_addr = ipv6_zero;
        _unicast = false;
        _ia_refresh_msg_type = DHCP_MT_INVALID;

        dhcp_i("Sending DHCPv6 SOLICIT message with xid: [%d]",_xid);
        _sock->dhcp_send(dm);

        set_timeout(rexmit_get_timeout());
    }

    void dhcp_interface_state::request()
    {
        if (_state != DHCP_REQUEST) {
            _state = DHCP_REQUEST;
            _rexmit.irt = REQ_TIMEOUT * SEC2MSEC;
            _rexmit.mrt = REQ_MAX_RT * SEC2MSEC; 
            _rexmit.mrd = 0;
            _rexmit.mrc = REQ_MAX_RC;
            rexmit_init();
        } else {
            rexmit_next();
            if (_rexmit.rc > _rexmit.mrc) {
                cancel_timeout();
                discover();
                return;
            }
        }

        dhcp_mbuf dm_req(false);
        std::string hostname_str("");
        // TODO: Get hostname from received message options
        {
            char hostname[256];
            if (0 == gethostname(hostname, sizeof(hostname))) {
                hostname_str = hostname;
            }
        }
        auto &server_addr = _unicast ? _server_addr : dhcpv6_multicast_addr;
        dm_req.compose_request(_ifp,
                               _xid,
                               rexmit_get_elapsed_time(),
                               _client_linklocal_addr,
                               server_addr,
                               _client_id,
                               _server_id,
                               hostname_str);
        dhcp_i("Sending DHCPv6 REQUEST message with xid: [%d] to server IP: %s",
               _xid, server_addr.to_string().c_str());
        _sock->dhcp_send(dm_req);

        set_timeout(rexmit_get_timeout());
    }

    void dhcp_interface_state::check_ia()
    {
        if (_state != DHCP_BOUND) {
            dhcp_e("%s(): only supported when in bound state", __FUNCTION__);
            discover();
            return;
        }
    
        auto now = osv::clock::uptime::now();
        if (now > _ia_valid_time) {
            expired();
            return;
        }
        auto dt = std::chrono::duration_cast<std::chrono::seconds>(now - _ia_rx_time).count();
        if (dt >= _ia_t2) {
            rebind();
        } else if (dt >= _ia_t1) {
            renew();
        } else {
            dhcp_w("%s(): Timer fired too early!  now=%s rxtime=%s dt=%lu t1=%lu t2=%lu", __FUNCTION__,
                   to_string(now).c_str(), to_string(_ia_rx_time).c_str(),
                   dt, _ia_t1, _ia_t2);
            set_timeout(std::min(_ia_rx_time + std::chrono::seconds(_ia_t1),
                                 _ia_valid_time - std::chrono::milliseconds(100)));
        }
    }

    void dhcp_interface_state::release()
    {
        if(!is_bound()) {            
            return;
        }

        if (_state != DHCP_RELEASE) {
            _state = DHCP_RELEASE;
            _rexmit.irt = REL_TIMEOUT * SEC2MSEC;
            _rexmit.mrt = 0; 
            _rexmit.mrd = 0;
            _rexmit.mrc = REL_MAX_RC;
            rexmit_init();
        } else {
            rexmit_next();
            if (!rexmit_ok()) {
                _state = DHCP_INIT;
                release_ifaddr();
                // osv::set_dns_config({}, {});
                _server_addr = ipv6_zero;
                cancel_timeout();
                return;
            }
        }

        // Compose a dhcp release packet
        dhcp_mbuf dm(false);
        auto &server_addr = _unicast ? _server_addr : dhcpv6_multicast_addr;
        dm.compose_release(_ifp, _xid, rexmit_get_elapsed_time(), _client_linklocal_addr, server_addr, _client_id, _server_id,  _ia_id, _client_addr);

        dhcp_i("Sending DHCPv6 RELEASE message with xid: [%d] from client: %s to server: %s",
                _xid, _client_addr.to_string().c_str(), server_addr.to_string().c_str());
        _sock->dhcp_send(dm);
        set_timeout(rexmit_get_timeout());
    }

    void dhcp_interface_state::renew()
    {
        if (_ia_refresh_msg_type != DHCP_MT_RENEW) {
            _ia_refresh_msg_type = DHCP_MT_RENEW;
            _rexmit.irt = REN_TIMEOUT * SEC2MSEC;
            _rexmit.mrt = REN_MAX_RT * SEC2MSEC; 
            auto t2 = _ia_rx_time + std::chrono::seconds(_ia_t2);
            auto now = osv::clock::uptime::now();
            if (now >= t2) {
                rebind();
                return;
            }
            _rexmit.mrd = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - now).count();
            _rexmit.mrc = 0;
            rexmit_init(now);
        } else {
            rexmit_next();
            if (!rexmit_ok()) {
                rebind();
                return;
            }
        }

        // Compose a dhcp request packet
        dhcp_mbuf dm(false);
        std::string hostname_str("");
        char hostname[256];
        if (0 == gethostname(hostname, sizeof(hostname))) {
            hostname_str.assign(hostname);
        }
        auto &server_addr = _unicast ? _server_addr : dhcpv6_multicast_addr;
        dm.compose_renew(_ifp,
                         _ia_refresh_msg_type,
                         _xid,
                         rexmit_get_elapsed_time(),
                         _client_linklocal_addr,
                         server_addr,
                         _client_id,
                         _server_id,
                         _ia_id,
                         _client_addr,
                         hostname_str);

        // Send
        dhcp_i( "Sending DHCPv6 RENEW message with xid: [%d] from client: %s to server: %s in order to renew lease of: %s",
                _xid, _client_addr.to_string().c_str(), server_addr.to_string().c_str(), _client_addr.to_string().c_str());
        _sock->dhcp_send(dm);

        set_timeout(rexmit_get_timeout());
    }

    void dhcp_interface_state::rebind()
    {
        if (_ia_refresh_msg_type != DHCP_MT_REBIND) {
            _ia_refresh_msg_type = DHCP_MT_REBIND;
            _rexmit.irt = REB_TIMEOUT * SEC2MSEC;
            _rexmit.mrt = REB_MAX_RT * SEC2MSEC; 
            auto now = osv::clock::uptime::now();
            if (now >= _ia_valid_time) {
                expired();
                return;
            }
            _rexmit.mrd = std::chrono::duration_cast<std::chrono::milliseconds>(_ia_valid_time - now).count();
            _rexmit.mrc = 0;
            rexmit_init();
        } else {
            rexmit_next();
            if (!rexmit_ok()) {
                expired();
                return;
            }
        }

        // Compose a dhcp request packet
        dhcp_mbuf dm(false);
        std::string hostname_str("");
        char hostname[256];
        if (0 == gethostname(hostname, sizeof(hostname))) {
            hostname_str.assign(hostname);
        }
        dm.compose_renew(_ifp,
                         _ia_refresh_msg_type,
                         _xid,
                         rexmit_get_elapsed_time(),
                         _client_linklocal_addr,
                         dhcpv6_multicast_addr,
                         _client_id,
                         _server_id,
                         _ia_id,
                         _client_addr,
                         hostname_str);

        // Send
        dhcp_i("Sending DHCPv6 REBIND message with xid: [%d] from client: %s to server: %s in order to rebind lease of: %s",
               _xid, _client_addr.to_string().c_str(), _server_addr.to_string().c_str(), _client_addr.to_string().c_str());
        _sock->dhcp_send(dm);

        set_timeout(rexmit_get_timeout());
    }

    void dhcp_interface_state::expired()
    {
        auto now = osv::clock::uptime::now();
        dhcp_e("%s(): IA expired before it could be renewed. %s > %s", __FUNCTION__,
               to_string(now).c_str(),
               to_string(_ia_valid_time).c_str());
        release_ifaddr();
        discover();
    }

    void dhcp_interface_state::process_packet(struct mbuf* m)
    {
        dhcp_mbuf dm(true, m);

        if (!dm.decode()) {
            dhcp_w("Unable to decode DHCPv6 packet");
            return;
        }

        // Validate transaction id
        if (dm.get_xid() != _xid) {
            dhcp_w("Got packet with wrong transaction ID (%d, %d)", _xid, dm.get_xid());
            return;
        }

        ///////////////////
        // State Machine //
        ///////////////////

        if (_state == DHCP_DISCOVER) {
            discover_process_packet(dm);
        } else if (_state == DHCP_REQUEST) {
            request_process_packet(dm);
        } else if (_state == DHCP_BOUND) {
            bound_process_packet(dm);
        } else if (_state == DHCP_RELEASE) {
            release_process_packet(dm);
        }
    }

    void dhcp_interface_state::discover_process_packet(dhcp_mbuf &dm)
    {
        if (dm.get_message_type() != DHCP_MT_ADVERTISE) {
            dhcp_w("Not offer packet in discover state, type = %d", dm.get_message_type());
            return;
        }

        dhcp_uid client_id;

        if (!dm.get_client_id(client_id)) {
            dhcp_w("Client ID not found in message, type = %d", dm.get_message_type());
            return;
        }
        if (client_id != _client_id) {
            dhcp_w("Client ID does not match expected");
            return;
        }

        // FIXME: According to RFC 3315 17.1.2 client is supposed to collect all advertise messages
        //        before selecting server

        if (!dm.get_server_id(_server_id)) {
            dhcp_w("Server ID not found in message, type = %d", dm.get_message_type());
            return;
        }
        // Get unicast option and address
        _unicast = dm.get_unicast_addr(_server_addr);
        request();
    }

    void dhcp_interface_state::request_process_packet(dhcp_mbuf &dm) {
        process_reply(dm);
    }

    void dhcp_interface_state::bound_process_packet(dhcp_mbuf &dm) {
        process_reply(dm);
    }

    void dhcp_interface_state::release_process_packet(dhcp_mbuf &dm) {
        process_reply(dm);
    }

    void dhcp_interface_state::process_reply(dhcp_mbuf &dm)
    {
        if (dm.get_message_type() != DHCP_MT_REPLY) {            
            dhcp_w("Not reply packet in request state, type = %d", dm.get_message_type());
            return;
        }

        dhcp_uid client_id;
        dhcp_uid server_id;

        if (!dm.get_client_id(client_id)) {
            dhcp_w("Client ID not found in message, type = %d", dm.get_message_type());
            return;
        }
        if (client_id != _client_id) {
            dhcp_w("Client ID does not match expected");
            return;
        }

        if (!dm.get_server_id(server_id)) {
            dhcp_w("Server ID option not found in message, type = %d", dm.get_message_type());
            return;
        }
        if (server_id != _server_id) {
            dhcp_w("Server ID does not match expected");
            return;
        }

        auto ia_na_opt = dm.find_option(DHCP_OPTION_IA_NA);
        if (!ia_na_opt) {
            dhcp_w("IA_NA option not found in message, type = %d", dm.get_message_type());
            return;
        }
        const u8 *p = (const u8 *)(ia_na_opt + 1);
        u16 ia_na_len = ntohs(ia_na_opt->len);
        u32 ia_id = ntohl(*(u32*)p);
        p += sizeof(u32);
        u32 ia_t1 = ntohl(*(u32*)p);
        p += sizeof(u32);
        u32 ia_t2 = ntohl(*(u32*)p);
        p += sizeof(u32);

        const u8 * ia_na_subopt = p;

        auto ia_addr_opt = dhcp6::find_option(ia_na_subopt,
                                              (const u8 *)ia_na_opt + ia_na_len + sizeof(struct dhcp_option),
                                              DHCP_OPTION_IAADDR);
        if (!ia_addr_opt) {
            dhcp_w("IA address not found in IA_NA");
            return;
        }
        u16 ia_addr_len = ntohs(ia_addr_opt->len);
        p = (const u8 *)(ia_addr_opt + 1);

	    ip::address_v6::bytes_type bytes;
        memcpy(&bytes, p, sizeof(bytes));
        auto client_addr = ip::address_v6(bytes);
        p += sizeof(bytes);
        u32 preferred_lifetime = ntohl(*(u32*)p);
        p += sizeof(u32);
        u32 valid_lifetime = ntohl(*(u32*)p);
        p += sizeof(u32);
        const u8 *ia_addr_subopt = p;

        if (preferred_lifetime > valid_lifetime || valid_lifetime == 0) {
            bool releasing = (_state == DHCP_RELEASE);
            // RFC3315 22.6 - Client discards any addresses for which preferred lifetime is > valid lifetime.
            if (is_bound() &&  _client_addr == client_addr) {
                release_ifaddr();
                _state = DHCP_INIT;
                _server_addr = ipv6_zero;
                cancel_timeout();
                if (!releasing)
                    discover();
            }
            return;
        }

        dhcp_status_code status_code;
        std::string status_message;
        if (dm.get_status_code(status_code, status_message) && status_code != DHCP_STATUS_SUCCESS)
        {
            dhcp_w("Server responded with error code %d.  %s", (int)status_code, status_message.c_str());
            release_ifaddr();
            _state = DHCP_INIT;
            _server_addr = ipv6_zero;
            cancel_timeout();
            discover();
            return;
        }

        auto ia_na_status = dhcp6::find_option(ia_na_subopt,
                                               (const u8 *)ia_na_opt + ia_na_len + sizeof(struct dhcp_option),
                                               DHCP_OPTION_STATUS_CODE);
        if (ia_na_status && dm.get_status_code(ia_na_status, status_code, status_message) && status_code != DHCP_STATUS_SUCCESS) {
            dhcp_w("Server responded with error code %d.  %s", (int)status_code, status_message.c_str());
            release_ifaddr();
            _state = DHCP_INIT;
            _server_addr = ipv6_zero;
            cancel_timeout();
            discover();
            return;
        }
    
        auto ia_addr_status = dhcp6::find_option(ia_addr_subopt,
                                                 (const u8 *)ia_addr_opt + ia_addr_len + sizeof(struct dhcp_option),
                                                 DHCP_OPTION_STATUS_CODE);
        if (ia_addr_status && dm.get_status_code(ia_addr_status, status_code, status_message) && status_code != DHCP_STATUS_SUCCESS) {
            dhcp_w("Server responded with error code %d.  %s", (int)status_code, status_message.c_str());
            release_ifaddr();
            _state = DHCP_INIT;
            _server_addr = ipv6_zero;
            cancel_timeout();
            discover();
            return;
        }

        _server_id = server_id;
        _ia_id = ia_id;
        _ia_rx_time = osv::clock::uptime::now();
        _ia_t1 = ia_t1;
        _ia_t2 = ia_t2;
        _ia_valid_time = _ia_rx_time + std::chrono::seconds(valid_lifetime);

        if (_ia_t1 == 0) {
            _ia_t1 = preferred_lifetime * .5;
            if (_ia_t1 == 0) _ia_t1 = 1;
        }
        if (_ia_t2 == 0) {
            _ia_t2 = preferred_lifetime * .8;
        }
        if (_ia_t2 <= _ia_t1) {  // Shouldn't happen, except in unit tests
            _ia_t2 = valid_lifetime - 1;
        }

        dhcp_i("Server acknowledged IP %s for interface %s with time to lease in seconds: %d",
               client_addr.to_string().c_str(), _ifp->if_xname, valid_lifetime);

        if (_client_addr != client_addr) {
            if (!is_bound()) {
                release_ifaddr();
            }
            const char *prefix_len = "128";

            _client_addr = client_addr;

            printf("%s: %s\n",
                    _ifp->if_xname,
                    _client_addr.to_string().c_str());
            dhcp_i("Configuring %s: ip %s/%s",
                    _ifp->if_xname, _client_addr.to_string().c_str(),  prefix_len);

            int err = osv::if_add_addr(_ifp->if_xname, _client_addr.to_string().c_str(), prefix_len);
            if (err != 0) {
                dhcp_e("Failed to add %s to %s.  Error %d",
                       _client_addr.to_string().c_str(), _ifp->if_xname, err);
            }

    #if 0
            osv::set_dns_config(dm.get_dns_ips(), std::vector<std::string>());
            if (dm.get_hostname().size()) {
                sethostname(dm.get_hostname().c_str(), dm.get_hostname().size());
                dhcp_i("Set hostname to: %s", dm.get_hostname().c_str());
            }
    #endif
        }

        _state = DHCP_BOUND;
        _ia_refresh_msg_type = DHCP_MT_INVALID;
        set_timeout(std::min(_ia_rx_time + std::chrono::seconds(_ia_t1),
                             _ia_valid_time - std::chrono::milliseconds(100)));
    }

    void dhcp_interface_state::release_ifaddr()
    {
        if (!is_bound()) {
            return;
        }

        dhcp_i("Deleting %s: ip %s",
                _ifp->if_xname, _client_addr.to_string().c_str());
        std::string netmask;
        int err = osv::if_del_addr(_ifp->if_xname, _client_addr.to_string().c_str(), netmask);
        if (err != 0) {
            dhcp_e("Failed to delete %s from %s.  Error %d",
                    _client_addr.to_string().c_str(), _ifp->if_xname, err);
        }
        _client_addr = ipv6_zero;
    }

    void dhcp_interface_state::set_timeout(const osv::clock::uptime::time_point &expiration)
    {
        _timer_expiration = expiration;
        _worker->notify_timer_added();
    }

    void dhcp_interface_state::cancel_timeout()
    {
        // Don't need to notify worker because it will skip zero time anyway
        _timer_expiration = clock_zero;
    }

    osv::clock::uptime::time_point dhcp_interface_state::timer_expiration_check(const osv::clock::uptime::time_point &now)
    {
        if (_timer_expiration != clock_zero && now > _timer_expiration)
        {
            _timer_expiration = clock_zero;
            handle_timeout();
        }
        return _timer_expiration;
    }
    
    void dhcp_interface_state::handle_timeout()
    {
        if (_state == DHCP_DISCOVER) {
            discover();
        }
        else if (_state == DHCP_REQUEST) {
            request();
        }
        else if (_state == DHCP_BOUND) {
            check_ia();
        }
    }

    void dhcp_interface_state::set_output_handler(std::function<int (struct mbuf *)> handler)
    {
        if (_sock)
            _sock->set_output_handler(handler);
    }

    ///////////////////////////////////////////////////////////////////////////

    dhcp_worker::dhcp_worker()
        : _dhcp_thread(nullptr), _have_ip(false), _waiter(nullptr)
    {

    }

    dhcp_worker::~dhcp_worker()
    {
        if (_dhcp_thread) {
            stop_thread();
        }

        auto it = _universe.begin();
        while (it != _universe.end()) {
            dhcp_interface_state *state = it->second;
            it = _universe.erase(it);
            delete state;
        }
    }

    void dhcp_worker::set_if_enable(const std::string &if_name, bool enable)
    {
        _if_config[if_name].enable = enable;
    }

    bool dhcp_worker::get_if_enable(const std::string &if_name, bool &enable)
    {
        enable = true;  // Default is enabled
        auto it = _if_config.find(if_name);
        if (it == _if_config.end()) {
            return false;
        }
        enable = it->second.enable;
        return true;
    }

    void dhcp_worker::set_if_stateless(const std::string &if_name, bool enable)
    {
        _if_config[if_name].stateless = enable;
    }

    bool dhcp_worker::get_if_stateless(const std::string &if_name, bool &enable)
    {
        enable = false;  // Default is disabled
        auto it = _if_config.find(if_name);
        if (it == _if_config.end()) {
            return false;
        }
        enable = it->second.stateless;
        return true;
    }

    void dhcp_worker::init()
    {
        struct ifnet *ifp = nullptr;
        bool if_enable;
        bool stateless;

        // Allocate a state for each interface
        IFNET_RLOCK();
        TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
            if (get_if_enable(ifp->if_xname, if_enable) && if_enable == false)
                continue;
            dhcp_i("%s Creating interface on %s", __FUNCTION__, ifp->if_xname);
 
            if ( (!(ifp->if_flags & IFF_DYING)) &&
                 (!(ifp->if_flags & IFF_LOOPBACK)) ) {
                get_if_stateless(ifp->if_xname, stateless);
                _universe.insert(std::make_pair(ifp,
                    new dhcp_interface_state(this, ifp, stateless)));
            }
        }
        IFNET_RUNLOCK();
    }

    void dhcp_worker::start_thread()
    {
        // Create the worker thread
        _dhcp_thread = sched::thread::make([&] { dhcp_worker_fn(); });
        _dhcp_thread->set_name("dhcp6");
        _dhcp_thread->start();
    }

    void dhcp_worker::stop_thread()
    {
        if (!_dhcp_thread)
            return;

        dhcp_control_msg *msg  = new dhcp_control_msg();
        msg->type = DHCP_CONTROL_STOP;
        send_control_msg(msg);

        dhcp_i("Waiting for DHCPv6 worker thread to exit...");
        _dhcp_thread->join();
        dhcp_i("DHCPv6 worker thread exited");

        delete _dhcp_thread;
        _dhcp_thread = nullptr;

        // Purge packet and control message queue
        while(!_rx_packets.empty()) {
            auto m = _rx_packets.front();
            _rx_packets.pop_front();
            m_free(m);
        }
        while(!_control_msg_queue.empty()) {
            auto msg = _control_msg_queue.front();
            _control_msg_queue.pop_front();
            delete msg;
        }
    }

    void dhcp_worker::_send_and_wait(bool wait, dhcp_control_msg_type msg_type)
    {
        if (_universe.empty())
            return;

        // When doing renew, we still have IP, but want to reuse the flag.
        _have_ip = false;
        do {
            // Send discover or renew packets!
            // This should be done in worker thread to avoid race conditions
            struct dhcp_control_msg *msg = new dhcp_control_msg();
            if (!msg) {
                dhcp_e("Failed to allocate control message for type %s", (int)msg_type);
                usleep(1);
                continue;
            }
            msg->type = msg_type;
            send_control_msg(msg);

            if (wait) {
                dhcp_i("Waiting for IPv6 from DHCPv6...");
                _waiter = sched::thread::current();

                sched::timer t(*sched::thread::current());
                using namespace osv::clock::literals;
                t.set(3_s);

                sched::thread::wait_until([&]{ return _have_ip || t.expired(); });
                _waiter = nullptr;
            }
        } while (!_have_ip && wait);
    }

    void dhcp_worker::start(bool wait)
    {
        if (_universe.empty())
            return;

        _send_and_wait(wait, DHCP_CONTROL_DISCOVER);
    }

    void dhcp_worker::release()
    {
        if (!_running) {
            dhcp_w("DHCPv6 is not running");
            return;
        }

        dhcp_control_msg *msg  = new dhcp_control_msg();
        if (!msg) {
            dhcp_e("Failed to allocate DHCP_CONTROL_RELEASE message");
            return;
        }
        msg->type = DHCP_CONTROL_RELEASE;
        send_control_msg(msg);
        _have_ip = false;
        // Wait a bit, so hopefully UDP release packets will be actually put on wire.
        usleep(1000);
    }

    void dhcp_worker::renew(bool wait)
    {
        _send_and_wait(wait, DHCP_CONTROL_RENEW);
    }

    void dhcp_worker::dhcp_worker_fn()
    {
        std::list<struct mbuf *> packets;
        std::list<dhcp_control_msg *> control_msgs;
        _running = true;

        while (_running) {
            auto now = osv::clock::uptime::now();
            auto expiration = timer_expiration_check(now);

            WITH_LOCK(_lock) {
                if (expiration == clock_zero) {
                    sched::thread::wait_until(_lock, [&] {
                        return (!_rx_packets.empty() || !_control_msg_queue.empty());
                    });
                } else {
                    sched::timer timer(*sched::thread::current());
                    timer.set(expiration);

                    sched::thread::wait_until(_lock, [&] {
                        return (!_rx_packets.empty() || !_control_msg_queue.empty() || timer.expired());
                    });
                }

                // Get packets for handling
                while (!_rx_packets.empty()) {
                    auto m = _rx_packets.front();
                    _rx_packets.pop_front();
                    packets.push_back(m);
                }
                // Get control messages
                while (!_control_msg_queue.empty()) {
                    auto m = _control_msg_queue.front();
                    _control_msg_queue.pop_front();
                    control_msgs.push_back(m);
                }
            }

            for (auto m : packets)
            {
                auto it = _universe.find(m->M_dat.MH.MH_pkthdr.rcvif);
                if (it == _universe.end()) {
                    // This could happen if DHCP isn't enabled on the interface
                    bool enable;
                    get_if_enable(m->M_dat.MH.MH_pkthdr.rcvif->if_xname, enable);
                    if (enable)
                        dhcp_e("Couldn't find interface state for DHCPv6 packet!");
                    m_free(m);
                    continue;
                }

                it->second->process_packet(m);

                // Check if we got an ip
                if (it->second->is_bound()) {
                    _have_ip = true;
                    if (_waiter) {
                        _waiter->wake();
                    }
                }
            }
            packets.clear();

            for (auto msg : control_msgs)
            {
                process_control_msg(msg);
                delete msg;
            }
            control_msgs.clear();
        }
    }

    void dhcp_worker::queue_packet(struct mbuf* m)
    {
        if (!_dhcp_thread) {
            /*
            With staticaly assigned IP, dhcp_worker::init() isn't called,
            and (injected) packets can/should be ignored.
            */
            dhcp_w("Ignoring inbound packet");
            return;
        }

        WITH_LOCK (_lock) {
            _rx_packets.push_back(m);
        }

        _dhcp_thread->wake();
    }

    osv::clock::uptime::time_point dhcp_worker::get_next_timer_expiration()
    {
        osv::clock::uptime::time_point expiration = clock_zero;
        for (auto &it: _universe) {
            auto t = it.second->get_timer_expiration();
            if (t > expiration)
                expiration = t;
        }
        return expiration;
    }

    osv::clock::uptime::time_point dhcp_worker::timer_expiration_check(const osv::clock::uptime::time_point& now)
    {
        osv::clock::uptime::time_point expiration = clock_zero;
        for (auto &it: _universe) {
            auto t = it.second->timer_expiration_check(now);
            if (t >= expiration)
                expiration = t;
        }
        return expiration;
    }

    void dhcp_worker::send_control_msg(dhcp_control_msg *msg)
    {
        if (!_dhcp_thread) {
            delete msg;
            return;
        }

        WITH_LOCK (_lock) {
            _control_msg_queue.push_back(msg);
        }

        if (sched::thread::current() != _dhcp_thread)
            _dhcp_thread->wake();
    }

    void dhcp_worker::process_control_msg(dhcp_control_msg *msg)
    {
        // This should be done from the worker thread
        switch(msg->type)
        {
            case DHCP_CONTROL_STOP:
                _running = false;
                break;
            case DHCP_CONTROL_DISCOVER:
                    for (auto &it: _universe) {
                        it.second->discover();
                    }
                break;
            case DHCP_CONTROL_RENEW:
                    for (auto &it: _universe) {
                        it.second->renew();
                    }
                break;
            case DHCP_CONTROL_RELEASE:
                    for (auto &it: _universe) {
                        it.second->release();
                    }
                break;
            case DHCP_CONTROL_TIMER_ADDED:
                break;
        }
    }

    void dhcp_worker::notify_timer_added()
    {
        dhcp_control_msg *msg  = new dhcp_control_msg();
        msg->type = DHCP_CONTROL_TIMER_ADDED;
        send_control_msg(msg);
    }

    void dhcp_worker::set_output_handler(std::function<int (struct mbuf *)> handler)
    {
        WITH_LOCK (_lock) {
            for (auto &it: _universe) {
                it.second->set_output_handler(handler);
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    u32 generate_xid()
    {
        return (rand() & 0xffffff);
    }

    u8* add_option(u8* pos, u16 type, u16 len, const u8* buf)
    {
        struct dhcp_option *opt = (struct dhcp_option *)pos;
        opt->type = htons(type);
        opt->len = htons(len);
        memcpy((u8*)(opt + 1), buf, len);
        return pos + sizeof(*opt) + len;
    }

    u8* add_elapsed_time_option(u8 *options, u16 elapsed)
    {
        struct dhcp_option *opt = (struct dhcp_option *) options;
        u8 *p = (u8*)(opt + 1);
    
        opt->type = htons(DHCP_OPTION_ELAPSED_TIME);
        opt->len = htons(2);
        *((u16*)p) = htons(elapsed);
        p += sizeof(u16);

        return p;
    }

    u8* add_ia_na_option(u8 *options, u32 ia_id, const u8* addr, u32 preferred_lifetime, u32 valid_lifetime)
    {
        struct dhcp_option *opt = (struct dhcp_option*) options;
        u8 *p = (u8 *)(opt + 1);
        u32 t1 = 0, t2 =0;

        opt->type = htons(DHCP_OPTION_IA_NA);
        opt->len = 0;

        // Use last 4 bytes of hw address for IAID
        *(u32*)p = htonl(ia_id);
        p += sizeof(u32);
        *(u32*)p = htonl(t1);
        p += sizeof(u32);
        *(u32*)p = htonl(t2);
        p += sizeof(u32);

        if (addr) {
            struct dhcp_option *addr_opt = (struct dhcp_option *)p;

            addr_opt->type = htons(DHCP_OPTION_IAADDR);
            addr_opt->len = htons(sizeof(struct in6_addr) + sizeof(u32) + sizeof(u32));
            p += sizeof(*addr_opt);
            memcpy(p, addr, 16);
            p += 16;
            *(u32 *)p = htonl(preferred_lifetime);
            p += 4;
            *(u32 *)p = htonl(valid_lifetime);
            p += 4;
        }
        opt->len = htons(p - (u8 *)opt - sizeof (*opt));

        return p;
    }

    u8* add_unicast_option(u8 *options, const u8 *addr)
    {
        struct dhcp_option *opt = (struct dhcp_option *) options;
        u8 *p = (u8*)(opt + 1);

        opt->type = htons(DHCP_OPTION_ELAPSED_TIME);
        opt->len = htons(16);
        memcpy(p, addr, 16);
        p += 16;

        return p;
    }

    const struct dhcp_option *find_option(const u8* start, const u8* end, u16 type)
    {
        const u8 *p = start;

        while (p < end) {
            const struct dhcp_option *nopt = (const struct dhcp_option *)p;
            struct dhcp_option  hopt = { .type = ntohs(nopt->type), .len = ntohs(nopt->len) };
            p += sizeof(*nopt);
            if ((p + hopt.len) > end) {
                dhcp_w("Error parsing message options.  Option length exceeds message length.");
                break;
            }
            if (hopt.type == type)
                return nopt;
            p += hopt.len;
        }
        return nullptr;
    }

}
