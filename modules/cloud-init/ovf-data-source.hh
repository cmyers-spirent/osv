#ifndef _OSV_CLOUD_INIT_OVF_DATASOURCE_HH
#define _OSV_CLOUD_INIT_OVF_DATASOURCE_HH

#include <string>
#include "data-source.hh"

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

    std::string rpc_query(std::string);
    void parse_xml(std::istream &);

    std::string base64_decode(const std::string &);
};

#endif
