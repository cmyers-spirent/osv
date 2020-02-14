/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#ifndef __DHCP6_HH__
#define __DHCP6_HH__

#include <list>
#include <vector>

#include <osv/sched.hh>
#include <osv/mutex.h>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v6.hpp>

extern "C" {
void dhcp6_check_config();
void dhcp6_start(bool wait);
void dhcp6_release();
void dhcp6_renew(bool wait);
void dhcp6_shutdown();
}

namespace dhcp6 {

    constexpr u_short dhcp_client_port = 546;
    constexpr u_short dhcp_server_port = 547;

    constexpr u32 SEC2MSEC    = 1000;

    constexpr u32 SOL_TIMEOUT = 1;      // Initial solicit timeout
    constexpr u32 SOL_MAX_RT  = 120;    // Max solicit timeout
    constexpr u32 REQ_TIMEOUT = 1;      // Initial request timeout
    constexpr u32 REQ_MAX_RT  = 30;     // Max request timeout
    constexpr u32 REQ_MAX_RC  = 10;     // Max retry attempts
    constexpr u32 REN_TIMEOUT = 10;     // Initial renew timeout
    constexpr u32 REN_MAX_RT  = 600;    // Max renew timeout
    constexpr u32 REB_TIMEOUT = 10;     // Initial rebind timeout
    constexpr u32 REB_MAX_RT  = 600;    // Max rebind timeout
    constexpr u32 REL_TIMEOUT = 1;      // Initial release timeout
    constexpr u32 REL_MAX_RC  = 5;      // Max release attempts

    struct dhcp_packet {
        u8 type;		// Message type
        u8 xid[3];		// Transaction ID
    } __packed;

    struct dhcp_option {
        u16 type;       // Option type
        u16 len;        // Option length
    }  __packed;

    enum dhcp_control_msg_type {
        DHCP_CONTROL_STOP,
        DHCP_CONTROL_TIMER_ADDED,
        DHCP_CONTROL_DISCOVER,
        DHCP_CONTROL_RENEW,
        DHCP_CONTROL_RELEASE
    };

    struct dhcp_control_msg
    {
        dhcp_control_msg_type type;
    };

    enum dhcp_hw_type {
        HTYPE_ETHERNET = 1
    };

    enum dhcp_duid_type {
        DUID_TYPE_LLTIME = 1,
        DUID_TYPE_VENDOR_ID = 2,
        DUID_TYPE_LLADDR = 3,
        DUID_TYPE_UUID = 4
    };

    enum dhcp_option_code {
        DHCP_OPTION_CLIENTID = 1,
        DHCP_OPTION_SERVERID = 2,
        DHCP_OPTION_IA_NA = 3,
        DHCP_OPTION_IA_TA = 4,
        DHCP_OPTION_IAADDR = 5,
        DHCP_OPTION_OPTIONREQUEST = 6,
        DHCP_OPTION_PREFERENCE = 7,
        DHCP_OPTION_ELAPSED_TIME = 8,
        DHCP_OPTION_RELAY_MSG = 9,
        DHCP_OPTION_AUTH = 11,
        DHCP_OPTION_UNICAST = 12,
        DHCP_OPTION_STATUS_CODE = 13,
        DHCP_OPTION_RAPID_COMMIT = 14,
        DHCP_OPTION_USER_CLASS = 15,
        DHCP_OPTION_VENDOR_CLASS = 16,
        DHCP_OPTION_VENDOR_OPTS = 17,
        DHCP_OPTION_INTERFACE_ID = 18,
        DHCP_OPTION_RECONFIG_MSG = 19,
        DHCP_OPTION_RECONFIG_ACCEPT = 20,
        DHCP_OPTION_DNS_SERVERS = 23,
        DHCP_OPTION_DOMAIN_LIST = 24,
        DHCP_OPTION_IA_PD = 25,
        DHCP_OPTION_IA_PREFIX = 26,
        DHCP_OPTION_NIS_SERVERS = 27,
        DHCP_OPTION_NISP_SERVERS = 28,
        DHCP_OPTION_NIS_DOMAIN_NAME = 29,
        DHCP_OPTION_NISP_DOMAIN_NAME = 30,
        DHCP_OPTION_SNTP_SERVERS = 31,
        DHCP_OPTION_INFO_REFRESH_TIME = 32,
        DHCP_OPTION_CLIENT_FQDN = 39,
        DHCP_OPTION_SOL_MAX_RT = 82,
        DHCP_OPTION_INF_MAX_RT = 83,
    };

    enum dhcp_message_type {
        DHCP_MT_SOLICIT = 1,
        DHCP_MT_ADVERTISE = 2,
        DHCP_MT_REQUEST = 3,
        DHCP_MT_CONFIRM = 4,
        DHCP_MT_RENEW = 5,
        DHCP_MT_REBIND = 6,
        DHCP_MT_REPLY = 7,
        DHCP_MT_RELEASE = 8,
        DHCP_MT_DECLINE = 9,
        DHCP_MT_RECONFIGURE = 10,
        DHCP_MT_INFOREQUEST = 11,
        DHCP_MT_RELAYFORWARD = 12,
        DHCP_MT_RELAYREPLY = 13,
        DHCP_MT_INVALID = 255
    };

    enum dhcp_status_code {
        DHCP_STATUS_SUCCESS = 0,
        DHCP_STATUS_UNSPEC_FAIL = 1,
        DHCP_STATUS_NOADDRSAVAIL = 2,
        DHCP_STATUS_NOBINDING = 3,
        DHCP_STATUS_NOTONLINK = 4,
        DHCP_STATUS_USEMULTICAST = 5,
    };

    ///////////////////////////////////////////////////////////////////////////

    class dhcp_uid {
    public:
        dhcp_uid() {}

        u16 get_type() const { 
            if (_data.size() < 2) return 0;
            return ntohs(*((u16*)&_data[0]));
        }

        void set_type(u16 type) {
            if (_data.size() < 2)
                _data.resize(2);
            *((u16*)&_data[0]) = htons(type);
        }
    
        size_t get_size() const { return _data.size(); }

        void set_size(size_t size) {
            _data.resize(size);
        }
    
        void set(const u8 *data, size_t size){
            _data.resize(size);
            memcpy(&_data[0], data, size);
        }
    
        void set_ll_time(u16 hw_type, const u8* ll_addr, size_t ll_size, u32 time){
            set_size(sizeof(u16) + sizeof(hw_type) + sizeof(time) + ll_size);
            set_type(DUID_TYPE_LLTIME);
            *((u16 *)&_data[2]) = htons(hw_type);
            *((u32 *)&_data[4]) = htonl(time);
            memcpy(&_data[8], ll_addr, ll_size);
        }

        void set_ll(u16 hw_type, const u8* ll_addr, size_t ll_size){
            set_size(sizeof(u16) + sizeof(hw_type) + ll_size);
            set_type(DUID_TYPE_LLADDR);
            *((u16 *)&_data[2]) = htons(hw_type);
            memcpy(&_data[4], ll_addr, ll_size);
        }

        u8* get_data() { return &_data[0]; }
        const u8* get_data() const { return &_data[0]; }
    
        friend bool operator==(const dhcp_uid &a, const dhcp_uid &b) {
            return (a._data == b._data);
        }
        friend bool operator!=(const dhcp_uid &a, const dhcp_uid &b) {
            return (a._data != b._data);
        }

    private:
        std::vector<u8> _data;
    };

    ///////////////////////////////////////////////////////////////////////////

    // Representing a DHCP packet, wraps mbuf
    class dhcp_mbuf {
    public:
        typedef std::tuple<boost::asio::ip::address_v6, boost::asio::ip::address_v6, boost::asio::ip::address_v6> route_type;

        dhcp_mbuf(bool attached = true, struct mbuf* m = nullptr);
        ~dhcp_mbuf();

        // mbuf memory management related functions
        void detach();
        struct mbuf* get();
        void set(struct mbuf* m);

        void compose_solicit(struct ifnet* ifp,
                             u32 xid, u16 elapsed_time,
                             const boost::asio::ip::address_v6 &client_ip,
                             const dhcp_uid &client_id);
        void compose_request(struct ifnet* ifp,
                             u32 xid, u16 elapsed_time,
                             const boost::asio::ip::address_v6 &client_ip,
                             const boost::asio::ip::address_v6 &server_ip,
                             const dhcp_uid &client_id,
                             const dhcp_uid &server_id,
                             std::string hostname);
        void compose_renew(struct ifnet* ifp,
                           dhcp_message_type message_type,
                           u32 xid, u16 elapsed_time,
                           const boost::asio::ip::address_v6 &client_ip,
                           const boost::asio::ip::address_v6 &server_ip,
                           const dhcp_uid &client_id,
                           const dhcp_uid &server_id,
                           u32 ia_id,
                           const boost::asio::ip::address_v6 &ia_addr,
                           std::string hostname);
        void compose_release(struct ifnet* ifp,
                             u32 xid, u16 elapsed_time,
                             const boost::asio::ip::address_v6 &client_ip,
                             const boost::asio::ip::address_v6 &server_ip,
                             const dhcp_uid &client_id,
                             const dhcp_uid &server_id,
                             u32 ia_id,
                             const boost::asio::ip::address_v6 &ia_addr);

        /* Decode packet */
        bool is_valid_dhcp();
        bool decode_ip();
        bool decode();

        dhcp_message_type get_message_type();
        u32 get_xid();
        boost::asio::ip::address_v6 get_ipv6_src_addr() const;
        boost::asio::ip::address_v6 get_ipv6_dst_addr() const;

        bool get_client_id(dhcp_uid & client_id) const;
        bool get_server_id(dhcp_uid & client_id) const;

        bool get_unicast_addr(boost::asio::ip::address_v6 &addr) const;

        const struct dhcp_option *find_option(u16 type) const;

        bool get_status_code(dhcp_status_code &code, std::string &message) const;
        bool get_status_code(const struct dhcp_option *opt, dhcp_status_code &code, std::string &message) const;


    private:

        // Pointers for building DHCP packet
        struct ip6_hdr* pip6();
        struct udphdr* pudp();
        struct dhcp_packet* pdhcp();
        u8* poptions();

        const struct ip6_hdr* pip6() const;
        const struct udphdr* pudp() const;
        const struct dhcp_packet* pdhcp() const;
        const u8* poptions() const;

        size_t get_options_len() const;

        // Packet assembly
        void build_udp_ip_headers(size_t dhcp_len,
                                  const boost::asio::ip::address_v6 &src_addr, const boost::asio::ip::address_v6 &dest_addr);

        // mbuf related
        void allocate_mbuf();
        bool _attached;
        struct mbuf* _m;
        u16 _ip_len;
        u8  _ip_proto;
    };

    ///////////////////////////////////////////////////////////////////////////

    //
    // DHCP socket
    //  TX for a selected interface
    //  RX is done via the hook
    //
    class dhcp_socket {
    public:
        dhcp_socket(struct ifnet* ifp): _ifp(ifp) { }
        bool dhcp_send(dhcp_mbuf& packet);

        void set_output_handler(std::function<int (struct mbuf *)> handler);

    private:
        struct ifnet* _ifp;
        std::function<int (struct mbuf *)> _output_handler;  // Used for unit tests
    };

    ///////////////////////////////////////////////////////////////////////////

    class dhcp_worker;

    class dhcp_interface_state {
    public:
        enum state {
            DHCP_INIT,
            DHCP_DISCOVER,
            DHCP_REQUEST,
            DHCP_BOUND,
            DHCP_RELEASE,
        };

        dhcp_interface_state(dhcp_worker *worker, struct ifnet* ifp, bool stateless);
        ~dhcp_interface_state();

        bool is_bound() const;
        void discover();
        void request();
        void release();
        void renew();
        void rebind();
        void expired();
        void check_ia();

        void process_packet(struct mbuf*);
        void discover_process_packet(dhcp_mbuf &dm);
        void request_process_packet(dhcp_mbuf &dm);
        void bound_process_packet(dhcp_mbuf &dm);
        void release_process_packet(dhcp_mbuf &dm);
        void handle_timeout();

        void process_reply(dhcp_mbuf &dm);

        osv::clock::uptime::time_point get_timer_expiration() { return _timer_expiration; }
        osv::clock::uptime::time_point timer_expiration_check(const osv::clock::uptime::time_point &now);

        void set_output_handler(std::function<int (struct mbuf *)> handler);

    private:
        void update_linklocal_addr();
        void set_timeout(const osv::clock::uptime::time_point &expiration);
        void cancel_timeout();
        double timeout_rand();

        void rexmit_init();
        void rexmit_init(const osv::clock::uptime::time_point &start);
        void rexmit_next();
        bool rexmit_ok() const;
        u16 rexmit_get_elapsed_time() const;
        osv::clock::uptime::time_point rexmit_get_timeout() const;

        void release_ifaddr();

        state _state;
        bool _stateless;
        dhcp_worker* _worker;
        struct ifnet* _ifp;
        dhcp_socket* _sock;
        osv::clock::uptime::time_point _timer_expiration;

        boost::asio::ip::address_v6 _client_linklocal_addr;
        boost::asio::ip::address_v6 _client_addr;
        boost::asio::ip::address_v6 _server_addr;
        dhcp_uid _client_id;
        dhcp_uid _server_id;
        u32 _ia_id;
        u32 _ia_t1;
        u32 _ia_t2;
        osv::clock::uptime::time_point _ia_rx_time;
        osv::clock::uptime::time_point _ia_valid_time;
        osv::clock::uptime::time_point _rexmit_start_time;
        dhcp_message_type _ia_refresh_msg_type;
        bool _unicast;

        // Transaction id
        u32 _xid;

        struct retransmit_state {            
            u32 irt;
            u32 mrt; 
            u32 mrd;
            u32 mrc;
            u32 rt;
            u32 rc;
        };

        struct retransmit_state _rexmit;
    };

    ///////////////////////////////////////////////////////////////////////////

    class dhcp_worker {
    public:
        dhcp_worker();
        ~dhcp_worker();

        void set_if_enable(const std::string &if_name, bool enable);
        bool get_if_enable(const std::string &if_name, bool &enable);
        void set_if_stateless(const std::string &if_name, bool enable);
        bool get_if_stateless(const std::string &if_name, bool &enable);

        // Initializing a state per interface
        void init();

        // Check if worker thread is running
        bool is_running() const { return _running; }
        // Check if bound an IPv6 address
        bool is_bound() const { return _have_ip; }
    
        // Start the worker thread
        void start_thread();
        // Stop the worker thread
        void stop_thread();

        // Send discover packets
        void start(bool wait);
        // Send release packet for all DHCP IPs.
        void release();
        void renew(bool wait);

        void dhcp_worker_fn();
        void process_control_msg(dhcp_control_msg *msg);
        void queue_packet(struct mbuf* m);

        // Send control message to the worker thread
        void send_control_msg(dhcp_control_msg *msg);

        osv::clock::uptime::time_point get_next_timer_expiration();
        osv::clock::uptime::time_point timer_expiration_check(const osv::clock::uptime::time_point &now);

        void notify_timer_added();

        void set_output_handler(std::function<int (struct mbuf *)> handler);

#if 1 // FIXME: Debug
        sched::thread * get_waiter() { return _waiter; }
#endif

    private:
        struct dhcp6_if_config {
            dhcp6_if_config() : enable(true), stateless(false) { }
            bool enable;
            bool stateless;
        };

        sched::thread * _dhcp_thread;

        mutex _lock;
        std::map<std::string, struct dhcp6_if_config> _if_config;
        std::list<struct mbuf*> _rx_packets;
        std::map<struct ifnet*, dhcp_interface_state*> _universe;
        std::list<dhcp_control_msg*> _control_msg_queue;

        bool _running;

        // Wait for IP
        bool _have_ip;
        sched::thread * _waiter;
        void _send_and_wait(bool wait, dhcp_control_msg_type msg_type);
    };

    ///////////////////////////////////////////////////////////////////////////
    u32 generate_xid();

    inline void set_xid(u8 *xid, u32 val) {
        xid[0] = val & 0xff;
        xid[1] = (val >> 8) & 0xff;
        xid[2] = (val >> 16) & 0xff;
    }

    inline void get_xid(const u8 *xid, u32 &val) {
        val = ((u32)xid[2] << 16) | ((u32)xid[1] << 8) | xid[0];
    }

    // Writes a new option to pos, returns new pos
    u8* add_option(u8* pos, u16 type, u16 len, const u8* buf);

    u8* add_elapsed_time_option(u8 *options, u16 elapsed);

    u8* add_ia_na_option(u8 *options, u32 ia_id, const u8* addr, u32 preferred_lifetime, u32 valid_lifetime);

    u8* add_unicast_option(u8 *options, const u8* addr);

    const struct dhcp_option *find_option(const u8* start, const u8* end, u16 type);

} // namespace dhcp6

#endif // !__DHCP6_HH__
