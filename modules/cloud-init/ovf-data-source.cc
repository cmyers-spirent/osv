#include <unordered_map>
#include <string>

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/optional.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <bsd/porting/networking.hh>
#include <bsd/porting/route.h>
#include <osv/debug.hh>
#include <osv/vmw-rpc.hh>

#include "ovf-data-source.hh"

using boost::property_tree::ptree;

const std::string ovf::mgmt_if     = "eth0";
const std::string ovf::ipv4_key      = "ip_address";
const std::string ovf::ipv4_netmask_key = "subnet_mask";
const std::string ovf::ipv4_gateway_key = "default_gateway";
const std::string ovf::ipv6_key      = "ipv6_address";
const std::string ovf::ipv6_netmask_key = "ipv6_subnet_mask";
const std::string ovf::ipv6_gateway_key = "ipv6_default_gateway";

std::string ovf::launch_index()
{
    throw std::runtime_error("Launch index not supported on OVF.");
}

std::string ovf::reservation_id()
{
    throw std::runtime_error("Reservation ID not supported on OVF.");
}

std::string ovf::external_ip()
{
    return vmw::rpc::info::request("guestinfo.ip");
}

std::string ovf::internal_ip()
{
    return vmw::rpc::info::request("guestinfo.ip");
}

std::string ovf::external_hostname()
{
    throw std::runtime_error("External hostname not supported on OVF.");
}

std::string ovf::get_user_data()
{
    auto ud = _properties.find("user-data");
    if (ud != _properties.end()) {
        return base64_decode(ud->second);
    } else {
        return "";
    }
}

std::string ovf::get_name()
{
    return "VMware";
}

void ovf::probe()
{
    std::istringstream xml(vmw::rpc::info::request("guestinfo.ovfEnv"));
    parse_xml(xml);
    maybe_config_interface();
}

void ovf::parse_xml(std::istream &xml)
{
    ptree pt;
    boost::property_tree::read_xml(xml, pt);

    for (auto child: pt.get_child("Environment")) {
        if (child.first == "PropertySection") {
            for (auto prop: child.second) {
                boost::optional<std::string> key =
                    prop.second.get_optional<std::string>("<xmlattr>.oe:key");
                boost::optional<std::string> value =
                    prop.second.get_optional<std::string>("<xmlattr>.oe:value");

                if (key && value) {
                    _properties.emplace(key.get(), value.get());
                }
            }
        }
    }
}

std::string ovf::base64_decode(const std::string &s)
{
    using namespace boost::archive::iterators;
    typedef transform_width<binary_from_base64<const char *>, 8, 6> base64_decoder;

    std::ostringstream os;
    size_t size = s.size();

    while (size && s[size - 1] == '=')
        --size;

    if (!size)
        return std::string();

    std::copy(base64_decoder(s.data()),
              base64_decoder(s.data() + size),
              std::ostream_iterator<char>(os));

    return os.str();
}

bool ovf::maybe_config_interface()
{
   /* Check for IP, netmask, and gateway */
    auto end = _properties.end();
    auto ipv4 = _properties.find(ipv4_key);
    auto ipv4_netmask = _properties.find(ipv4_netmask_key);
    auto ipv4_gateway = _properties.find(ipv4_gateway_key);
    auto ipv6 = _properties.find(ipv6_key);
    auto ipv6_netmask = _properties.find(ipv6_netmask_key);
    auto ipv6_gateway = _properties.find(ipv6_gateway_key);

    if (ipv4 != end && ipv4_netmask != end) {
        auto err = osv::if_add_addr(mgmt_if, ipv4->second, ipv4_netmask->second);
        if (err) {
            debug("Unable to configure " + std::string(mgmt_if)
                  + " with ip_address " + ipv4->second
                  + " and subnet_mask " + ipv4_netmask->second
                  + ": " + strerror(err) + "\n");
            return false;
        } else {
            debug("Configured " + ipv4->second + "/" + ipv4_netmask->second
                  + " on " + std::string(mgmt_if) + ".\n");
        }

        if (ipv4_gateway != end) {
            /* XXX: we don't know if this void function succeeds or not... :(  */
            osv_route_add_network("0.0.0.0",
                                  "0.0.0.0",
                                  ipv4_gateway->second.c_str());
        }
    }

    if (ipv6 != end && ipv6_netmask != end) {
        auto err = osv::if_add_addr(mgmt_if, ipv6->second, ipv6_netmask->second);
        if (err) {
            debug("Unable to configure " + std::string(mgmt_if)
                  + " with ip_address " + ipv6->second
                  + " and subnet_mask " + ipv6_netmask->second
                  + ": " + strerror(err) + "\n");
            return false;
        } else {
            debug("Configured " + ipv6->second + "/" + ipv6_netmask->second
                  + " on " + std::string(mgmt_if) + ".\n");
        }

        if (ipv6_gateway != end) {
            /* XXX: we don't know if this void function succeeds or not... :(  */
            osv_route_add_network("::",
                                  "::",
                                  ipv6_gateway->second.c_str());
        }
    }

    return true;  /* we set something... */
}
