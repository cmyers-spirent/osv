#ifndef _OSV_CLOUD_INIT_OVF_DATASOURCE_HH
#define _OSV_CLOUD_INIT_OVF_DATASOURCE_HH

#include "data-source.hh"

#include <string>
#include <unordered_map>

class ovf: public data_source {
public:
    virtual ~ovf() {}

    virtual std::string launch_index();
    virtual std::string reservation_id();
    virtual std::string external_ip();
    virtual std::string internal_ip();
    virtual std::string external_hostname();
    virtual std::string get_user_data();
    virtual std::string get_name();

    /**
     * Returns when this data source is probed successsfuly.
     * Throws exception upon failure.
     */
    virtual void probe();

private:
    std::unordered_map<std::string, std::string> _properties;

    void parse_xml(std::istream &);

    std::string base64_decode(const std::string &);

    static const std::string mgmt_if;
    static const std::string ipv4_key;
    static const std::string ipv4_netmask_key;
    static const std::string ipv4_gateway_key;
    static const std::string ipv6_key;
    static const std::string ipv6_netmask_key;
    static const std::string ipv6_gateway_key;

    bool maybe_config_interface();
};

#endif
