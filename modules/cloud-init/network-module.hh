/*
 * Copyright (C) 2014 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#ifndef CLOUDINIT_NETWORK_HH_
#define CLOUDINIT_NETWORK_HH_

#include "cloud-init.hh"

#include <fstream>
#include <vector>
#include <set>

class network_module : public init::config_module
{
public:

    virtual void handle(const YAML::Node& doc) override;

    virtual std::string get_label()
    {
        return "network";
    }

private:

    class config_state 
    {
    public:
        std::set<std::string> configured_interfaces;
        std::vector<std::string> physical_interfaces;
        std::vector<std::string> dns_servers;
    };
    static void init_config_state(config_state& state);
    static void configure_interface(const YAML::Node& node, config_state& state);
    static void configure_physical_interface(const YAML::Node& node, config_state& state);

};

#endif
