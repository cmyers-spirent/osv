#ifndef _OSV_VMW_RPC_H_
#define _OSV_VMW_RPC_H_

#include "drivers/vmw-rpc.hh"

#include <string>

namespace vmw {
namespace rpc {

class info {
public:
    static std::string request(std::string req)
    {
        auto response = vmw::rpc::request("info-get " + req);

        /* RPC response format is "0" | "1 <data>" */
        if (response.length() > 2 && response[0] == '1') {
            return response.erase(0,2);
        } else {
            return "";
        }
    }
};

} /* namespace rpc */
} /* namespace vmw */

#endif /* _OSV_VMW_RPC_H_ */
