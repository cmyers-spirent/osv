/*
 * Copyright (C) 2014 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <bsd/porting/networking.hh>
#include <bsd/porting/route.h>
#include <osv/debug.hh>

#include "network-module.hh"
#include <boost/asio/ip/address.hpp>
#include <boost/algorithm/string.hpp>

#include <ifaddrs.h>
#include <api/netpacket/packet.h>

#include "libc/network/__dns.hh"

static int mac_str_to_addr(const std::string &str, uint8_t *addr)
{
    int values[6];

    if (sscanf(str.c_str(), "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return -1;
    }

    for (int i=0; i<6; ++i) {
        addr[i] = values[i];
    }
    return 0;
}

int if_rename(const std::string &ifname, const std::string &new_ifname)
{
    struct ifreq req;
    int sock;
    int result = 0;

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname.c_str(), sizeof(req.ifr_name)-1);
    strncpy(req.ifr_newname, new_ifname.c_str(), sizeof(req.ifr_newname)-1);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        debug("cloud-init: %s error.  socket() failed.  %s\n", __FUNCTION__, strerror(errno));
        return -1;
    }

    if (ioctl(sock, SIOCSIFNAME, &req) < 0) {
        debug("cloud-init: %s error.  ioctl() SIOSIFNAME failed.  %s\n", __FUNCTION__, strerror(errno));
        result = -1;
    }
    close(sock);
    return result;
}

int if_set_mac(const std::string &ifname, const std::string &mac_addr)
{
    struct ifreq req;
    int sock;
    int result = 0;

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname.c_str(), sizeof(req.ifr_name)-1);

    if (mac_str_to_addr(mac_addr, (uint8_t* )req.ifr_hwaddr.sa_data) < 0) {
        debug("cloud-init: %s error.  Invalid MAC %s\n", __FUNCTION__, mac_addr.c_str());
        return -1;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        debug("cloud-init: %s error.  socket() failed.  %s\n", __FUNCTION__, strerror(errno));
        return -1;
    }
    if (ioctl(sock, SIOCSIFHWADDR, &req) < 0) {
        debug("cloud-init: %s error. ioctl() SIOCSIFHWADDR failed.  %s\n", __FUNCTION__, strerror(errno));
        result = -1;
    }
    close(sock);
    return result;
}

int if_find_name_by_mac(const std::string &mac_addr, std::string &ifname)
{
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;
    uint8_t hwaddr[6];
    int result = -1;

    if (mac_str_to_addr(mac_addr, hwaddr) < 0) {
        debug("cloud-init: %s error.  Invalid MAC %s\n", __FUNCTION__, mac_addr.c_str());
        return -1;
    }

    if (getifaddrs(&ifaddr) == -1) {
        debug("cloud-init: %s error.  getifaddrs() failed: %s\n", __FUNCTION__, strerror(errno));
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        struct sockaddr_ll *sa = (struct sockaddr_ll*)ifa->ifa_addr;
        if (sa->sll_halen != 6)
            continue;
        if (memcmp(hwaddr, sa->sll_addr, 6) != 0)
            continue;
        ifname = ifa->ifa_name;
        result = 0;
        break;
    }

    freeifaddrs(ifaddr);
    return result;
}

void network_module::configure_interface(const YAML::Node& node, network_module::config_state& state)
{
    if (node["type"]) {
        std::string type = node["type"].as<std::string>();
        if (type == "physical") {
            configure_physical_interface(node, state);
        }
    }
}

void network_module::configure_physical_interface(const YAML::Node& node, network_module::config_state& state)
{
    std::string if_name;
    std::string mac_addr;

    if (node["name"]) {
        if_name = node["name"].as<std::string>();
        if (state.configured_interfaces.find(if_name) != state.configured_interfaces.end()) {
            debug("cloud-init: %s error.  interface %s included in configuration multiple times\n", __FUNCTION__, if_name.c_str());
            return;
        }
    }
    if (node["mac_address"]) {
        // Find interface with MAC address
        mac_addr = node["mac_address"].as<std::string>();
        std::string fname;
        if_find_name_by_mac(mac_addr, fname);
        if (fname != "") {
            // Found interface matching the MAC address
            if (if_name != "" && fname != if_name) {
                // Different name specified so try to rename the interface
                if (if_rename(fname, if_name) != 0) {
                    debug("cloud-init: %s error.  Failed to rename interface %s to %s\n", __FUNCTION__, fname.c_str(), if_name.c_str());
                    if_name = fname;
                } else {
                    // Update the physical interface list
                    auto iter = std::find(state.physical_interfaces.begin(), state.physical_interfaces.end(), fname);
                    if (iter != state.physical_interfaces.end()) {
                        (*iter) = if_name;
                    }
                }
            } else {
                // No name specified so use existing interface name
                if_name = fname; 
            }
        } else {
            // No interface matching the MAC address
            if (if_name == "") {
                debug("cloud-init: %s error.  Failed to find interface with MAC address %s\n", __FUNCTION__, mac_addr.c_str());
                return;
            }
#if 0 // Setting MAC is not supported
            // Set interface MAC
            if_set_mac(if_name, mac_addr);
#endif
        }
    }
    if (if_name == "") {
        // Unable to find matching interface
        for (auto &tmp_if : state.physical_interfaces) {
            if (state.configured_interfaces.find(tmp_if) != state.configured_interfaces.end())
                continue;
            if_name = tmp_if;
            break;
        }
        if (if_name == "") {
            debug("cloud-init: %s error.  Interface name not specified.\n", __FUNCTION__);
            return;
        }
    } else {
        // Validate interface name is okay to use
        if (std::find(state.physical_interfaces.begin(), state.physical_interfaces.end(), if_name) == state.physical_interfaces.end()) {
            debug("cloud-init: %s error.  Interface %s not found\n", __FUNCTION__, if_name.c_str());
            return;
        }
    }

    state.configured_interfaces.insert(if_name);

    if (node["mtu"]) {
        // Configure MTU
        int err;
        int mtu = node["mtu"].as<int>();
        if ((err = osv::if_set_mtu(if_name, mtu)) != 0){
            debug("cloud-init: %s errror.  Failed to set %s mtu %d. err=%d\n", __FUNCTION__, if_name.c_str(), mtu, err);
        }
    }
    if (node["subnets"]) {
        for (auto& subnet : node["subnets"]) {
            std::string subnet_type;
            if (subnet["type"]) {
                subnet_type = subnet["type"].as<std::string>();
            } else {
                subnet_type = "static";
            }
            if (subnet_type == "static" ||
                subnet_type == "static6") {
                if (!subnet["address"]) {
                    continue;
                }
                // TODO: Disable DHCP per interface
                // dhcp_release();
                std::string address = subnet["address"].as<std::string>();
                std::string netmask;
                std::vector<std::string> addr_prefix;
                bool ipv6 = false;

                boost::split(addr_prefix, address, boost::is_any_of("/"), boost::token_compress_on);
                if (addr_prefix.size() == 2) {
                    address = addr_prefix[0];
                    netmask = addr_prefix[1];
                } else {
                    if (subnet["netmask"]) {
                        netmask = subnet["netmask"].as<std::string>();
                    }
                }

                try {
                    boost::asio::ip::address addr;
                    ipv6 = boost::asio::ip::address::from_string(address).is_v6();
                } catch(std::exception const &ex) {
                    debug("cloud-init: %s error.  Not a valid IP address %s\n",
                          __FUNCTION__, address.c_str());
                    continue;
                }

                // Add address to interface
                if (osv::if_add_addr(if_name, address, netmask) != 0) {
                    debug("cloud-init: %s error.  Failed adding address %s/%s to interface %s\n",
                          __FUNCTION__,
                          address.c_str(), netmask.c_str(), if_name.c_str());
                    continue;
                }

                // Set environment variable telling loader not to start DHCP
                setenv("USE_STATIC_IP", "True", 1);

                if (subnet["gateway"]) {
                    std::string gateway = subnet["gateway"].as<std::string>();
                    std::string network = ipv6 ? "::" : "0.0.0.0";
                    std::string netmask = ipv6 ? "::" : "0.0.0.0";

                    osv_route_add_network(network.c_str(),
                                          netmask.c_str(),
                                          gateway.c_str());
                }

                if (subnet["routes"]) {
                    for (auto& route : subnet["routes"]) {
                        if (route["gateway"]) {
                            std::string gateway = node["gateway"].as<std::string>();
                            std::string network;
                            std::string netmask;
                            if (route["network"]) {
                                network = route["network"].as<std::string>();
                            } else {
                                network = ipv6 ? "::" : "0.0.0.0";
                            }
                            if (route["netmask"]) {
                                netmask = route["netmask"].as<std::string>();
                            } else {
                                netmask = ipv6 ? "::" : "0.0.0.0";
                            }

                            osv_route_add_network(network.c_str(),
                                                  netmask.c_str(),
                                                  gateway.c_str());
                        }
                    }
                }
                if (subnet["dns_nameservers"]) {
                    auto& dns_servers = subnet["dns_nameservers"].as<std::vector<std::string>>();
                    state.dns_servers.insert(state.dns_servers.end(),
                                             dns_servers.begin(),
                                             dns_servers.end());
                }
            }
            else if (subnet_type == "dhcp") {
                // TODO: Enable DHCP per interface
                // dhcp_start(true)
            }
            else if (subnet_type == "nameserver") {
                if (!subnet["address"])
                    continue;
                auto& dns_servers = subnet["address"].as<std::vector<std::string>>();
                state.dns_servers.insert(state.dns_servers.end(),
                                         dns_servers.begin(),
                                         dns_servers.end());
            }
        }
    }
}

void network_module::handle(const YAML::Node& doc)
{
    if (doc["version"]) {
        int version = doc["version"].as<int>();
        if (version != 1) {
            debug("cloud-init: version %d is not supported\n", version);
            return;
        }
    }

    if (doc["config"]) {
        const YAML::Node &config = doc["config"];
        network_module::config_state state;

        init_config_state(state);
        for (auto& ifc_node : config) {
            configure_interface(ifc_node, state);
        }

        // Configure DNS servers
        if (!state.dns_servers.empty()) {
            std::set<std::string> dns_server_set;
            std::vector<boost::asio::ip::address> dns_servers;
            for (auto t : state.dns_servers) {
                if (dns_server_set.find(t) != dns_server_set.end())
                    continue; // Skip duplicates
                auto addr = boost::asio::ip::address::from_string(t);
                dns_servers.push_back(addr);
                dns_server_set.insert(t);
            }
            osv::set_dns_config(dns_servers, std::vector<std::string>());
        }
    }
}

void network_module::init_config_state(network_module::config_state& state)
{
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;

    state.physical_interfaces.clear();
    state.configured_interfaces.clear();
    state.dns_servers.clear();
    
    if (getifaddrs(&ifaddr) == -1) {
        debug("cloud-init: %s failed.  getifaddrs() failed: %s\n", __FUNCTION__, strerror(errno));
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        state.physical_interfaces.push_back(ifa->ifa_name);
    }

    freeifaddrs(ifaddr);
}

