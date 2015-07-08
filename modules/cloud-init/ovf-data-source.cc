#include <unordered_map>
#include <string>

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/optional.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/property_tree/ptree.hpp>

extern "C"
{
typedef char Bool;
#include "vmGuestLib/rpcout.h"
}

#include "ovf-data-source.hh"

using boost::property_tree::ptree;

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
    return rpc_query("guestinfo.ip");
}

std::string ovf::internal_ip()
{
    return rpc_query("guestinfo.ip");
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
    return "OVF";
}

void ovf::probe()
{
    std::istringstream xml(rpc_query("guestinfo.ovfEnv"));
    parse_xml(xml);
}

std::string ovf::rpc_query(std::string s)
{
    std::unique_ptr<char> reply;
    char *replybuf = reply.get();
    int err = 0;

    if ((err = RpcOut_sendOne(&replybuf, NULL, "info-get %s", s.c_str())) == 0) {
        std::ostringstream error_msg("RPC call failed: ");
        error_msg << (replybuf ? replybuf : "nullptr");
        throw std::runtime_error(error_msg.str());
    }

    return replybuf;
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
