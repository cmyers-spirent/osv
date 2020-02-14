/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#ifndef __NETWORKING_H__
#define __NETWORKING_H__

#include <osv/types.h>
#include <sys/cdefs.h>
#include <string>
#include <functional>

namespace osv {
    void for_each_if(std::function<void (std::string)> func);
    /* Interface Functions */
    int if_set_mtu(std::string if_name, u16 mtu);
    int start_if(std::string if_name, std::string ip_addr,
        std::string mask_addr);
    int stop_if(std::string if_name, std::string ip_addr);
    int ifup(std::string if_name);
    std::string if_ip(std::string if_name);

    int if_add_addr(std::string if_name, std::string ip_addr, std::string netmask);
    int if_del_addr(std::string if_name, std::string ip_addr, std::string netmask);

    void dhcp_set_if_enable(const std::string &if_name, bool enable);
    bool dhcp_get_if_enable(const std::string &if_name, bool &enable);

    // Modules like cloud-init don't have easy way to find if INET6 is enabled
    // so these functions are always present and stubbed as noop in
    // networking.cc
    void dhcp6_set_if_enable(const std::string &if_name, bool enable);
    bool dhcp6_get_if_enable(const std::string &if_name, bool &enable);
    void dhcp6_set_if_stateless(const std::string &if_name, bool enable);
    bool dhcp6_get_if_enable(const std::string &if_name, bool &enable);

#ifdef INET6
    int set_ipv6_accept_rtadv(bool enable);
    bool get_ipv6_accept_rtadv(void);
    int set_ipv6_auto_linklocal(bool enable);
    bool get_ipv6_auto_linklocal(void);
    int send_ipv6_router_solicit(const std::string &ifname);
    int send_ipv6_router_solicit();
#endif
}

#endif /* __NETWORKING_H__ */
