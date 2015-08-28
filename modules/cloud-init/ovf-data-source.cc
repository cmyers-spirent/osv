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
const std::string ovf::ip_key      = "ip_address";
const std::string ovf::netmask_key = "subnet_mask";
const std::string ovf::gateway_key = "default_gateway";

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
    auto ip = _properties.find(ip_key);
    auto netmask = _properties.find(netmask_key);
    auto gateway = _properties.find(gateway_key);
    auto end = _properties.end();

    if (ip != end && netmask != end) {
        auto err = osv::start_if(mgmt_if, ip->second, netmask->second);
        if (err) {
            debug("Unable to configure " + std::string(mgmt_if)
                  + " with ip_address " + ip->second
                  + " and subnet_mask " + netmask->second
                  + ": " + strerror(err) + "\n");
            return false;
        } else {
            debug("Configured " + ip->second + "/" + netmask->second
                  + " on " + std::string(mgmt_if) + ".\n");
        }

        if (gateway != end) {
            /* XXX: we don't know if this void function succeeds or not... :(  */
            osv_route_add_network("0.0.0.0",
                                  "0.0.0.0",
                                  gateway->second.c_str());
        }
    }

    return true;  /* we set something... */
}
