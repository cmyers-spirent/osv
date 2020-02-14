/*
 * Copyright (C) 2017 ScyllaDB
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#define BOOST_TEST_MODULE tst-dhcp6

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <vector>
#include <thread>
#include <chrono>
#if 0
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
#include <osv/latch.hh>
#include <boost/test/unit_test.hpp>
#include <boost/interprocess/sync/interprocess_semaphore.hpp>
#include <boost/scope_exit.hpp>

#include <bsd/sys/sys/param.h>
#include <bsd/porting/netport.h>
#include <bsd/sys/sys/mbuf.h>

#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <osv/dhcp6.hh>

using namespace boost::asio;

u16 dhcp6_requested_options[] = {
    htons(dhcp6::DHCP_OPTION_DNS_SERVERS),
    htons(dhcp6::DHCP_OPTION_DOMAIN_LIST),
};

void set_rcvif(struct mbuf *reply, const struct mbuf *req)
{
    reply->M_dat.MH.MH_pkthdr.rcvif = req->M_dat.MH.MH_pkthdr.rcvif;
}

struct mbuf * dhcp6_create_advertise_msg(const u8 *ip6_src, const u8 *ip6_dst, u32 xid,
                                         dhcp6::dhcp_uid &server_id, dhcp6::dhcp_uid &client_id,
                                         u32 ia_id, const u8 *ia_addr,
                                         u32 preferred_lifetime, u32 valid_lifetime,
                                        bool unicast_supported)
{
    auto m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    if (!m)
        return m;

    // Save space for ethernet header
    m->m_hdr.mh_data += sizeof(struct ether_header);

    auto ip6 = mtod(m, struct ip6_hdr *);
    auto udp = (struct udphdr *)(ip6 + 1);
    auto dhcp = (struct dhcp6::dhcp_packet *)(udp + 1);
    size_t dhcp_len = sizeof(dhcp6::dhcp_packet);

    dhcp->type = dhcp6::DHCP_MT_ADVERTISE;
    dhcp6::set_xid(dhcp->xid, xid);

    auto options_start = (u8 *)(dhcp + 1);
    auto options = options_start;

    options = dhcp6::add_option(options, dhcp6::DHCP_OPTION_SERVERID, server_id.get_size(), server_id.get_data());
    options = dhcp6::add_option(options, dhcp6::DHCP_OPTION_CLIENTID, client_id.get_size(), client_id.get_data());
    options = dhcp6::add_option(options, dhcp6::DHCP_OPTION_OPTIONREQUEST,
        sizeof(dhcp6_requested_options), (u8*)dhcp6_requested_options);
    options = dhcp6::add_ia_na_option(options, ia_id, ia_addr, preferred_lifetime, valid_lifetime);
    options = dhcp6::add_elapsed_time_option(options, 0);
    if (unicast_supported)
        options = dhcp6::add_unicast_option(options, ip6_src);

    dhcp_len += options - options_start;

    memset(ip6, 0, sizeof(*ip6));
    ip6->ip6_vfc = 0x60;
    memcpy(&ip6->ip6_src, ip6_src, sizeof(ip6->ip6_src));
    memcpy(&ip6->ip6_dst, ip6_dst, sizeof(ip6->ip6_dst));
    ip6->ip6_nxt = IPPROTO_UDP;
    ip6->ip6_plen = htons(sizeof(*ip6) + sizeof(*udp) + dhcp_len);

    memset(udp, 0, sizeof(*udp));
    udp->uh_sport = htons(dhcp6::dhcp_server_port);
    udp->uh_dport = htons(dhcp6::dhcp_client_port);
    udp->uh_ulen = htons(sizeof(*udp) + dhcp_len);

    m->M_dat.MH.MH_pkthdr.len = m->m_hdr.mh_len = sizeof(*ip6) + sizeof(*udp) + dhcp_len;

    return m;
}

struct mbuf * dhcp6_create_reply_msg(const u8 *ip6_src, const u8 *ip6_dst, u32 xid,
                                     dhcp6::dhcp_uid &server_id, dhcp6::dhcp_uid &client_id,
                                     u32 ia_id, const u8 *ia_addr,
                                     u32 preferred_lifetime, u32 valid_lifetime)
{
    auto m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES);
    if (!m)
        return m;

    // Save space for ethernet header
    m->m_hdr.mh_data += sizeof(struct ether_header);

    auto ip6 = mtod(m, struct ip6_hdr *);
    auto udp = (struct udphdr *)(ip6 + 1);
    auto dhcp = (struct dhcp6::dhcp_packet *)(udp + 1);
    size_t dhcp_len = sizeof(dhcp6::dhcp_packet);

    dhcp->type = dhcp6::DHCP_MT_REPLY;
    dhcp6::set_xid(dhcp->xid, xid);

    auto options_start = (u8 *)(dhcp + 1);
    auto options = options_start;

    options = dhcp6::add_option(options, dhcp6::DHCP_OPTION_SERVERID, server_id.get_size(), server_id.get_data());
    options = dhcp6::add_option(options, dhcp6::DHCP_OPTION_CLIENTID, client_id.get_size(), client_id.get_data());
    options = dhcp6::add_option(options, dhcp6::DHCP_OPTION_OPTIONREQUEST,
        sizeof(dhcp6_requested_options), (u8*)dhcp6_requested_options);
    options = dhcp6::add_ia_na_option(options, ia_id, ia_addr, preferred_lifetime, valid_lifetime);
    options = dhcp6::add_elapsed_time_option(options, 0);

    dhcp_len += options - options_start;

    memset(ip6, 0, sizeof(*ip6));
    ip6->ip6_vfc = 0x60;
    memcpy(&ip6->ip6_src, ip6_src, sizeof(ip6->ip6_src));
    memcpy(&ip6->ip6_dst, ip6_dst, sizeof(ip6->ip6_dst));
    ip6->ip6_nxt = IPPROTO_UDP;
    ip6->ip6_plen = htons(sizeof(*ip6) + sizeof(*udp) + dhcp_len);

    memset(udp, 0, sizeof(*udp));
    udp->uh_sport = htons(dhcp6::dhcp_server_port);
    udp->uh_dport = htons(dhcp6::dhcp_client_port);
    udp->uh_ulen = htons(sizeof(*udp) + dhcp_len);

    m->M_dat.MH.MH_pkthdr.len = m->m_hdr.mh_len = sizeof(*ip6) + sizeof(*udp) + dhcp_len;

    return m;
}

// BOOST_REQUIRE doesn't work correctly in output handler, so just throwing a runtime_error instead
#define OUTPUT_HANDLER_ASSERT(expr, message) \
    if (!(expr)) throw std::runtime_error(message)

/*
 * Simple DHCPv6 server used for testing DHCPv6 client
 */
class dhcp6_test_server {
public:
    struct server_config {
        u8 server_hwaddr[ETHER_ADDR_LEN];
        ip::address_v6 server_addr;
        ip::address_v6 ia_addr;
        u32 preferred_lifetime;
        u32 valid_lifetime;
        bool unicast_supported;
        bool send_advertise;
        bool send_request_reply;
        bool send_renew_reply;
        bool send_rebind_reply;
    };

    struct server_stats {
        u32 total_packets;
        u32 valid_packets;
        u32 errored_packets;
        u32 rx_solicit;
        u32 rx_request;
        u32 rx_renew;
        u32 rx_rebind;
        u32 tx_advertise;
        u32 tx_reply;
    };

    dhcp6_test_server(dhcp6::dhcp_worker *worker) : _worker(nullptr) {
        set_default_config();
        clear_stats();
        if (worker) 
            attach_worker(worker);
    }

    void attach_worker(dhcp6::dhcp_worker *worker) {
        if (_worker)
            throw std::runtime_error("Can not attach_worker() because already attached");
        _worker = worker;
        if (_worker) {
            _worker->set_output_handler([ & ](struct mbuf *m) {
                return this->process_packet(m);
            });
        }
    }

    void detach_worker() {
        if (!_worker)
            return;
        _worker->set_output_handler(nullptr);
        _worker = nullptr;
    }

    int process_packet(struct mbuf *m) {
        bool valid = true;
        try {
            process_packet_with_exception(m);
        }
        catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            valid = false;
            ++_stats.errored_packets;
            m_print(m, -1);
        }
        ++_stats.total_packets;
        if (valid) ++_stats.valid_packets;

        m_free(m);

        return 0;
    }

    void set_default_config() {
        _config.server_addr = ip::address_v6::address_v6::from_string("fd00::1:1");
        _config.ia_addr = ip::address_v6::address_v6::from_string("fd00::1:2");
        const u8 server_hwaddr[] = { 0x00, 0x10, 0x00, 0x00, 0x00, 0x01 };
        memcpy(_config.server_hwaddr, server_hwaddr, sizeof(_config.server_hwaddr));
        _config.preferred_lifetime = 75;
        _config.valid_lifetime = 120;
        _config.unicast_supported = false;
        _config.send_advertise = true;
        _config.send_request_reply = true;
        _config.send_renew_reply = true;
        _config.send_rebind_reply = true;
    }

    const struct server_config& get_config() const {
         return _config;
    }

    void set_config(const server_config &config) {
        _config = config;
    }

    const struct server_stats& get_stats() const {
         return _stats;
    }

    void clear_stats() {
        memset(&_stats, 0, sizeof(_stats));
    }

    void dump_stats() const {
        std::cout << "total_packets: "    << _stats.total_packets
                  << " errored_packets: " << _stats.errored_packets
                  << " valid_packets: "   << _stats.valid_packets << std::endl;
        std::cout << "rx_solicit: "       << _stats.rx_solicit
                  << " rx_request: "      << _stats.rx_request
                  << " rx_renew: "        << _stats.rx_renew
                  << " rx_rebind: "       << _stats.rx_rebind
                  << " tx_advertise: "    << _stats.tx_advertise
                  << " tx_reply: "        << _stats.tx_reply << std::endl;
    }

private:
    // Note: mbuf doesn't get freed in this function
    void process_packet_with_exception(struct mbuf *m) {
        dhcp6::dhcp_uid server_id;
        server_id.set_ll(dhcp6::HTYPE_ETHERNET, _config.server_hwaddr, ETHER_ADDR_LEN);

        auto ip6 = mtod(m, struct ip6_hdr *);
        OUTPUT_HANDLER_ASSERT((ip6->ip6_vfc & 0xf0) == 0x60, "Invalid IPv6 vfc");
        OUTPUT_HANDLER_ASSERT(ip6->ip6_nxt == IPPROTO_UDP, "Unexpected IPv6 next protocol");
        auto udp = (struct udphdr *)(ip6 + 1);
        OUTPUT_HANDLER_ASSERT(udp->uh_sport == htons(dhcp6::dhcp_client_port), "Unexpected UDP source port");
        OUTPUT_HANDLER_ASSERT(udp->uh_dport == htons(dhcp6::dhcp_server_port), "Unexpected UDP dest port");
        auto dhcp = (struct dhcp6::dhcp_packet *)(udp + 1);
        u8 *options = (u8 *)(dhcp + 1);
        u8 *options_end = options + udp->uh_ulen - sizeof(*udp);
        u32 xid;
        dhcp6::get_xid(dhcp->xid, xid);

        dhcp6::dhcp_uid client_id;
        auto client_id_opt = dhcp6::find_option(options, options_end, dhcp6::DHCP_OPTION_CLIENTID);
        OUTPUT_HANDLER_ASSERT(client_id_opt, "Unable to find Client ID");
        client_id.set((const u8 *)(client_id_opt + 1), ntohs(client_id_opt->len));

        if (dhcp->type == dhcp6::DHCP_MT_SOLICIT) {
            ++_stats.rx_solicit;

            auto ia_na_opt = dhcp6::find_option(options, options_end, dhcp6::DHCP_OPTION_IA_NA);
            OUTPUT_HANDLER_ASSERT(ia_na_opt, "Unable to find IA_NA in Solicit");
            OUTPUT_HANDLER_ASSERT(m->m_hdr.mh_flags & M_MCAST, "M_MCAST flag was not set");
            OUTPUT_HANDLER_ASSERT(IN6_IS_ADDR_MULTICAST(ip6->ip6_dst.s6_addr), "IPv6 destination was not a multicast address");

            u32 ia_id = ntohl(*(u8*)(ia_na_opt + 1));
            if (_config.send_advertise && _worker) {
                auto reply = dhcp6_create_advertise_msg(_config.server_addr.to_bytes().data(), ip6->ip6_src.s6_addr, xid, server_id, client_id,
                                                        ia_id, _config.ia_addr.to_bytes().data(),
                                                        _config.preferred_lifetime, _config.valid_lifetime,
                                                        _config.unicast_supported);
                set_rcvif(reply, m);
                _worker->queue_packet(reply);
                ++_stats.tx_advertise;
            }
        }
        else if (dhcp->type == dhcp6::DHCP_MT_REQUEST) {
            ++_stats.rx_request;
            auto ia_na_opt = dhcp6::find_option(options, options_end, dhcp6::DHCP_OPTION_IA_NA);
            OUTPUT_HANDLER_ASSERT(ia_na_opt, "Unable to find IA_NA in Request");
            if (!_config.unicast_supported) {
                OUTPUT_HANDLER_ASSERT(m->m_hdr.mh_flags & M_MCAST, "M_MCAST flag was not set");
                OUTPUT_HANDLER_ASSERT(IN6_IS_ADDR_MULTICAST(ip6->ip6_dst.s6_addr), "IPv6 destination was not a multicast address");
            }
            u32 ia_id = ntohl(*(u8*)(ia_na_opt + 1));
            if (_config.send_request_reply && _worker) {
                auto reply = dhcp6_create_reply_msg(_config.server_addr.to_bytes().data(), ip6->ip6_src.s6_addr, xid, server_id, client_id,
                                                    ia_id, _config.ia_addr.to_bytes().data(),
                                                    _config.preferred_lifetime, _config.valid_lifetime);
                set_rcvif(reply, m);
                _worker->queue_packet(reply);                
                ++_stats.tx_reply;
            }
        }
        else if (dhcp->type == dhcp6::DHCP_MT_RENEW){
            ++_stats.rx_renew;
            auto ia_na_opt = dhcp6::find_option(options, options_end, dhcp6::DHCP_OPTION_IA_NA);
            OUTPUT_HANDLER_ASSERT(ia_na_opt, "Unable to find IA_NA in Renew");
            if (!_config.unicast_supported) {
                OUTPUT_HANDLER_ASSERT(m->m_hdr.mh_flags & M_MCAST, "M_MCAST flag was not set");
                OUTPUT_HANDLER_ASSERT(IN6_IS_ADDR_MULTICAST(ip6->ip6_dst.s6_addr), "IPv6 destination was not a multicast address");
            }
            u32 ia_id = ntohl(*(u8*)(ia_na_opt + 1));
            if (_config.send_renew_reply && _worker) {
                auto reply = dhcp6_create_reply_msg(_config.server_addr.to_bytes().data(), ip6->ip6_src.s6_addr, xid, server_id, client_id,
                                                    ia_id, _config.ia_addr.to_bytes().data(),
                                                    _config.preferred_lifetime, _config.valid_lifetime);
                set_rcvif(reply, m);
                _worker->queue_packet(reply);                
                ++_stats.tx_reply;
            }
        }
        else if (dhcp->type == dhcp6::DHCP_MT_REBIND){
            ++_stats.rx_rebind;
            auto ia_na_opt = dhcp6::find_option(options, options_end, dhcp6::DHCP_OPTION_IA_NA);
            OUTPUT_HANDLER_ASSERT(ia_na_opt, "Unable to find IA_NA in Rebind");
            OUTPUT_HANDLER_ASSERT(m->m_hdr.mh_flags & M_MCAST, "M_MCAST flag was not set");
            OUTPUT_HANDLER_ASSERT(IN6_IS_ADDR_MULTICAST(ip6->ip6_dst.s6_addr), "IPv6 destination was not a multicast address");
            u32 ia_id = ntohl(*(u8*)(ia_na_opt + 1));
            if (_config.send_rebind_reply && _worker) {
                auto reply = dhcp6_create_reply_msg(_config.server_addr.to_bytes().data(), ip6->ip6_src.s6_addr, xid, server_id, client_id,
                                                    ia_id, _config.ia_addr.to_bytes().data(),
                                                    _config.preferred_lifetime, _config.valid_lifetime);
                set_rcvif(reply, m);
                _worker->queue_packet(reply);                
                ++_stats.tx_reply;
            }
        }
    }

    dhcp6::dhcp_worker *_worker;
    struct server_config _config;
    struct server_stats _stats;
};

struct test_dhcp6_init {
    test_dhcp6_init() {
        BOOST_TEST_MESSAGE("test_dhcp6: setup");
        // Disable the stack DHCPv6 insteance
        // This shouldn't be required for tests to pass, but makes debugging easier
        // because trace code doesn't get interleaved
        dhcp6_shutdown();
    }
    ~test_dhcp6_init() {
        BOOST_TEST_MESSAGE("test_dhcp6: teardown");
    }
};
BOOST_FIXTURE_TEST_SUITE(s, test_dhcp6_init)

BOOST_AUTO_TEST_CASE(test_dhcp6_uid)
{
    dhcp6::dhcp_uid id;
    BOOST_REQUIRE_MESSAGE(id.get_type() == 0, "Unexpected initial type");
    BOOST_REQUIRE_MESSAGE(id.get_size() == 0, "Invalid initial length");

    u8 hw_addr[6] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    id.set_ll(1, hw_addr, sizeof(hw_addr));
    BOOST_REQUIRE_MESSAGE(id.get_type() == dhcp6::DUID_TYPE_LLADDR, "Unexepcted DUID type");
    BOOST_REQUIRE_MESSAGE(id.get_size() == 10, "Unexepcted DUID length");
    BOOST_REQUIRE_MESSAGE(htons(*(u16*)(id.get_data() + 2)) == 1, "hw type didn't match expected value");
    BOOST_REQUIRE_MESSAGE(memcmp(id.get_data() + 4, hw_addr, sizeof(hw_addr)) == 0,
                          "hw_addr didn't match expected value");
}

BOOST_AUTO_TEST_CASE(test_dhcp6_solicit_retry)
{
    std::unique_ptr<dhcp6::dhcp_worker> worker(new dhcp6::dhcp_worker);

    worker->init();

    // Server needs to be created after worker->init() or need to call attach_worker()
    dhcp6_test_server server(worker.get());
    auto config = server.get_config();
    config.send_advertise = false;
    server.set_config(config);

    worker->start_thread();
    worker->start(false);
    for (int i=0; i<10 && server.get_stats().rx_solicit !=2; ++i) {
        sleep(1);
    }

    worker->stop_thread();
    server.detach_worker();
    server.dump_stats();
    BOOST_REQUIRE_MESSAGE(server.get_stats().rx_solicit >= 2, "Didn't get enough solicit packets");
    BOOST_REQUIRE_MESSAGE(server.get_stats().errored_packets == 0, "Received some errored packets");
}

BOOST_AUTO_TEST_CASE(test_dhcp6_bind)
{
    std::unique_ptr<dhcp6::dhcp_worker> worker(new dhcp6::dhcp_worker);

    worker->init();

    // Server needs to be created after worker->init() or need to call attach_worker()
    dhcp6_test_server server(worker.get());

    worker->start_thread();
    worker->start(false);
    for (int i=0; i<10 && !worker->is_bound(); ++i) {
        sleep(1);
    }
    BOOST_REQUIRE_MESSAGE(worker->is_bound(), "Failed to bind");

    worker->stop_thread();
    server.detach_worker();
    server.dump_stats();
    BOOST_REQUIRE_MESSAGE(server.get_stats().rx_request >= 1, "Didn't get enough request packets");
    BOOST_REQUIRE_MESSAGE(server.get_stats().errored_packets == 0, "Received some errored packets");
}

BOOST_AUTO_TEST_CASE(test_dhcp6_bind_unicast)
{
    std::unique_ptr<dhcp6::dhcp_worker> worker(new dhcp6::dhcp_worker);

    worker->init();

    // Server needs to be created after worker->init() or need to call attach_worker()
    dhcp6_test_server server(worker.get());
    auto config = server.get_config();
    config.unicast_supported = true;
    server.set_config(config);

    worker->start_thread();
    worker->start(false);
    for (int i=0; i<10 && !worker->is_bound(); ++i) {
        sleep(1);
    }
    BOOST_REQUIRE_MESSAGE(worker->is_bound(), "Failed to bind");

    worker->stop_thread();
    server.detach_worker();
    server.dump_stats();
    BOOST_REQUIRE_MESSAGE(server.get_stats().rx_request >= 1, "Didn't get enough request packets");
    BOOST_REQUIRE_MESSAGE(server.get_stats().errored_packets == 0, "Received some errored packets");
}

BOOST_AUTO_TEST_CASE(test_dhcp6_renew)
{
    std::unique_ptr<dhcp6::dhcp_worker> worker(new dhcp6::dhcp_worker);

    worker->init();

    // Server needs to be created after worker->init() or need to call attach_worker()
    dhcp6_test_server server(worker.get());
    auto config = server.get_config();
    config.preferred_lifetime = 2;
    config.valid_lifetime = 3;
    server.set_config(config);

    worker->start_thread();
    worker->start(false);
    for (int i=0; i<10 && server.get_stats().rx_renew == 0; ++i) {
        sleep(1);
    }

    worker->stop_thread();
    server.detach_worker();
    server.dump_stats();
    BOOST_REQUIRE_MESSAGE(server.get_stats().rx_renew >= 1, "Didn't receive renew");
    BOOST_REQUIRE_MESSAGE(server.get_stats().rx_rebind == 0, "Received unexpected rebind");
    BOOST_REQUIRE_MESSAGE(server.get_stats().errored_packets == 0, "Received some errored packets");
}

BOOST_AUTO_TEST_CASE(test_dhcp6_rebind)
{
    std::unique_ptr<dhcp6::dhcp_worker> worker(new dhcp6::dhcp_worker);

    worker->init();

    // Server needs to be created after worker->init() or need to call attach_worker()
    dhcp6_test_server server(worker.get());
    auto config = server.get_config();
    config.send_renew_reply = false;
    config.preferred_lifetime = 4;
    config.valid_lifetime = 8;
    server.set_config(config);

    worker->start_thread();
    worker->start(false);
    for (int i=0; i<10 && server.get_stats().rx_rebind == 0; ++i) {
        sleep(1);
    }

    worker->stop_thread();
    server.detach_worker();
    server.dump_stats();
    BOOST_REQUIRE_MESSAGE(server.get_stats().rx_renew >= 1, "Didn't receive renew");
    BOOST_REQUIRE_MESSAGE(server.get_stats().rx_renew < 3, "Received too many renew packets");
    BOOST_REQUIRE_MESSAGE(server.get_stats().rx_rebind >= 1, "Didn't receive rebind");
    BOOST_REQUIRE_MESSAGE(server.get_stats().errored_packets == 0, "Received some errored packets");
}

BOOST_AUTO_TEST_SUITE_END()
