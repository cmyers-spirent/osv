/*
 * Copyright (c) 2015 Spirent Communications, Inc.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
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
 */

#include "vmw-tools.hh"
#include "vmw-rpc.hh"

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cpuid.hh>
#include <osv/clock.hh>
#include <osv/debug.h>
#include <osv/power.hh>
#include <osv/prio.hh>
#include <osv/shutdown.hh>
#include <osv/version.hh>

using namespace osv::clock::literals;

namespace vmw {

#define tools_tag "vmw-tools"
#define tools_d(...)    tprintf_d(tools_tag, __VA_ARGS__)
#define tools_i(...)    tprintf_i(tools_tag, __VA_ARGS__)
#define tools_w(...)    tprintf_w(tools_tag, __VA_ARGS__)
#define tools_e(...)    tprintf_e(tools_tag, __VA_ARGS__)

    /***
     * Callbacks
     ***/
    class tools_reset : public tools_callback {
        std::string key() { return "reset"; }
        void operator()(vmw::rpc::connection *connection)
        {
            vmw::rpc::send(connection, "OK ATR toolbox");
        }
    };

    class tools_ping : public tools_callback {
        std::string key() { return "ping"; }
        void operator()(vmw::rpc::connection *connection)
        {
            tools::update_uptime();
            vmw::rpc::send(connection, vmw::rpc::reply_ok);
        }
    };

    class tools_statechange_callback : public tools_callback {
    public:
        std::string capability() { return "tools.capability.statechange "; }
        void set_state(vmw::rpc::state state)
        {
            vmw::rpc::request("tools.os.statechange.status 1 " + std::to_string(state));
        }
    };

    class tools_reboot : public tools_statechange_callback {
    public:
        std::string key() { return "OS_Reboot"; }
        void operator()(vmw::rpc::connection *connection)
        {
            tools_w("VMware host requested reboot\n");
            set_state(vmw::rpc::state::reboot);
            vmw::rpc::send(connection, vmw::rpc::reply_ok);
            osv::reboot();
            tools_e("VMware guest reboot failed\n");
        }
    };

    class tools_halt : public tools_statechange_callback {
        std::string key() { return "OS_Halt"; }
        void operator()(vmw::rpc::connection *connection) __attribute__((noreturn))
        {
            tools_w("VMware host requested halt\n");
            set_state(vmw::rpc::state::halt);
            vmw::rpc::send(connection, vmw::rpc::reply_ok);
            osv::shutdown();
        }
    };

    class tools_suspend : public tools_statechange_callback {
        std::string key() { return "OS_Suspend"; }
        void operator()(vmw::rpc::connection *connection)
        {
            tools_w("VMware host requested suspend\n");
            set_state(vmw::rpc::state::suspend);
            vmw::rpc::send(connection, vmw::rpc::reply_ok);
        }
    };

    class tools_resume : public tools_statechange_callback {
        std::string key() { return "OS_Resume"; }
        void operator()(vmw::rpc::connection *connection)
        {
            tools_w("VMware guest resuming from suspend\n");

            tools::update_hostname();
            tools::update_os_info();

            set_state(vmw::rpc::state::resume);
            vmw::rpc::send(connection, vmw::rpc::reply_ok);
        }
    };

    class tools_poweron : public tools_statechange_callback {
        std::string key() { return "OS_PowerOn"; }
        void operator()(vmw::rpc::connection *connection)
        {
            tools_w("VMware guest powered on\n");
            set_state(vmw::rpc::state::poweron);
            vmw::rpc::send(connection, vmw::rpc::reply_ok);
        }
    };

    /***
     * Broadcast IP is a little more involved that the others...
     ***/
    class tools_broadcastIP : public tools_callback {
    public:
        std::string key() { return "Set_Option broadcastIP 1"; }

        struct _socket {
            _socket(int domain, int type, int proto = 0)
            {
                fd = socket(domain, type, proto);
            }

            ~_socket()
            {
                close(fd);
            }
            int fd;
        };

        std::string get_first_ip_address()
        {
            struct _socket socket(AF_INET, SOCK_DGRAM, 0);
            struct ifconf ifconfig;
            std::vector<char> buffer;

            memset(&ifconfig, 0, sizeof(ifconfig));
            if (ioctl(socket.fd, SIOCGIFCONF,
                      reinterpret_cast<caddr_t>(&ifconfig),
                      sizeof(ifconfig)) != 0) {
                return "";
            }

            /* Get enough space for the full config */
            buffer.reserve(ifconfig.ifc_len);
            ifconfig.ifc_buf = buffer.data();

            if (ioctl(socket.fd, SIOCGIFCONF,
                      reinterpret_cast<caddr_t>(&ifconfig),
                      sizeof(ifconfig)) != 0) {
                return "";
            }

            size_t nb_interfaces = ifconfig.ifc_len / sizeof(struct ifreq);

            for (size_t i = 0; i <= nb_interfaces; i++) {
                struct ifreq *ifr = &ifconfig.ifc_req[i];

                /* Skip the loopback interface */
                std::string ifname(ifr->ifr_name);
                if (ifname.find("lo") != std::string::npos)
                    continue;

                /* Retreive INET address of non-loopback interface */
                if (ioctl(socket.fd, SIOCGIFADDR,
                          reinterpret_cast<caddr_t>(ifr),
                          sizeof(*ifr)) != 0) {
                    continue;
                }

                struct sockaddr_in *addr = reinterpret_cast<struct sockaddr_in *>(&ifr->ifr_addr);

                return inet_ntoa(addr->sin_addr);
            }

            /* safe default */
            return "127.0.0.1";
        }

        void operator()(vmw::rpc::connection *connection)
        {
            auto ipaddr = get_first_ip_address();
            if (ipaddr.length()) {
                vmw::rpc::request("info-set guestinfo.ip " + ipaddr);
                vmw::rpc::send(connection, vmw::rpc::reply_ok);
            } else {
                vmw::rpc::send(connection, "ERROR Unable to find guest IP address");
            }
        }
    };

    /***
     * Tools driver
     ***/
    tools::tools(std::initializer_list<vmw::tools_callback *> callbacks)
        : _do_tclo_ping(true)
    {
        mutex_init(&_lock);

        for (auto& callback : callbacks) {
            if (callback->has_capability())
                _capabilities.emplace(callback->capability());

            _callback_map.insert(std::make_pair(callback->key(),
                                                std::unique_ptr<vmw::tools_callback>(callback)));
        }

        vmw::rpc::request("tools.capability.hgfs_server toolbox 1");
        update_os_info();

        WITH_LOCK(_lock) {
            _tclo_monitor_task = new async::timer_task(
                _lock,
                [this]() { this->tclo_monitor(); } );
            _tclo_monitor_task->reschedule(1_s);
        }

        debugf("VMware tools: %d callbacks registered\n", _callback_map.size());
    }

    tools::~tools()
    {
        vmw::rpc::request("tools.capability.hgfs_server toolbox 0");

        WITH_LOCK(_lock) {
            _tclo_monitor_task->cancel();
        }
    }

    hw_driver* tools::probe()
    {
        if (!processor::features().vmware)
            return nullptr;  /* definitely no */

        try {
            /* Verify that the RPC channel is open */
            vmw::rpc::message probe1(vmw::rpc::command::get_speed,
                                     vmw::rpc::subcommand::probe,
                                     ~vmw::rpc::magic);
            probe1();

            vmw::rpc::message probe2(vmw::rpc::command::get_mem_size,
                                     vmw::rpc::subcommand::probe,
                                     ~vmw::rpc::magic);
            probe2();

            /*
             * We can apparently communicate with the host.
             * Load the tools driver
             */
            return new tools({
                    new vmw::tools_reset(),
                    new vmw::tools_ping(),
                    new vmw::tools_reboot(),
                    new vmw::tools_halt(),
                    new vmw::tools_suspend(),
                    new vmw::tools_resume(),
                    new vmw::tools_poweron(),
                    new vmw::tools_broadcastIP()
             });
        }
        catch(const std::runtime_error &e) {
            return nullptr;
        }
    }

    void tools::tclo_monitor()
    {
        auto delay = 1_s;

        try {
            if (!_tclo) {
                _tclo.reset(new vmw::rpc::connection(vmw::rpc::tclo));
            }

            if (_do_tclo_ping) {
                vmw::rpc::ping(_tclo.get());
                _do_tclo_ping = false;
            }

            std::string msg = vmw::rpc::recv(_tclo.get());

            if (!msg.length()) {
                _do_tclo_ping = true;
            } else {
                tools_d("TCLO channel received: \"%s\" (length = %d)\n", msg.c_str(), msg.length());

                if (msg.compare("Capabilities_Register") == 0) {
                    tclo_register_capabilities();
                } else {
                    auto item = _callback_map.find(msg);
                    if (item != _callback_map.end()) {
                        auto& callback = item->second;
                        callback->operator()(_tclo.get());
                    } else {
                        vmw::rpc::send(_tclo.get(), "ERROR Unknown command");
                        tools_i("No callback found for \"%s\"\n", msg.c_str());
                    }
                }

                delay = 0_s;
            }
        }
        catch(const std::runtime_error &e) {
            _tclo.reset();
            tools_e("TCLO monitor error: %s\n", e.what());
        }

        WITH_LOCK(_lock) {
            _tclo_monitor_task->reschedule(delay);
        }
    }

    void tools::tclo_register_capabilities()
    {
        vmw::rpc::request("vmx.capability.unified_loop toolbox");
        vmw::rpc::request("tools.set.version " + std::to_string(vmw::rpc::version));

        for ( auto cap : _capabilities )
            vmw::rpc::request(cap);

        update_uptime();
        vmw::rpc::send(_tclo.get(), vmw::rpc::reply_ok);
    }

    void tools::update_os_info()
    {
        struct utsname ubuf;
        if (uname(&ubuf) == -1) {
            tools_e("vmw::tools::update_guest_info uname call failed: %s\n",
                    strerror(errno));
            return;
        }

        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) != 0) {
            tools_e("vmw::tools::update_guest_info gethostname call failed: %s\n",
                    strerror(errno));
            return;
        }

        vmw::rpc::request(set_guest_info_string(vmw::rpc::guestinfo::dns_name,
                                                { hostname }));

        vmw::rpc::request(set_guest_info_string(vmw::rpc::guestinfo::os_name,
                                                { "other-64" }));

        vmw::rpc::request(set_guest_info_string(vmw::rpc::guestinfo::os_name_full,
                                                { "OSv", osv::version().c_str(),
                                                        static_cast<const char *>(ubuf.machine) }));
    }

    void tools::update_hostname()
    {
        struct utsname ubuf;
        if (uname(&ubuf) == -1) {
            tools_e("vmw::tools::update_guest_info uname call failed: %s\n",
                    strerror(errno));
            return;
        }

        vmw::rpc::request(set_guest_info_string(vmw::rpc::guestinfo::dns_name,
                                                { ubuf.nodename }));
    }

    void tools::update_uptime()
    {
        auto now = osv::clock::uptime::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        /* VMware wants hundredths of a second */
        uptime *= 100;

        vmw::rpc::request(set_guest_info_string(vmw::rpc::guestinfo::uptime,
                                                { std::to_string(uptime) }));
    }


} /* namespace vmw */
