#ifndef _VMW_TOOLS_H_
#define _VMW_TOOLS_H_

#include "drivers/driver.hh"
#include "vmw-rpc.hh"

#include "osv/async.hh"
#include "osv/mutex.h"

#include <initializer_list>
#include <memory>
#include <set>
#include <unordered_map>

namespace vmw {

class tools_callback {
public:
    virtual ~tools_callback() {};
    virtual std::string key() = 0;
    virtual std::string capability() { return ""; }
    virtual bool        has_capability() { return capability().length() > 0; }
    virtual void operator()(vmw::rpc::connection *connection) = 0;
};

class tools : public hw_driver {
public:
    tools(std::initializer_list<vmw::tools_callback *> callbacks);
    ~tools();

    std::string get_name() const { return "VMware Tools"; };

    void dump_config() {};

    static hw_driver* probe();
    static void register_tools(tools *t);

    /* Unfortunately, some callbacks need access to these methods */
    static void update_hostname();
    static void update_os_info();
    static void update_uptime();

    template <typename T>
    static std::string set_guest_info_string(vmw::rpc::guestinfo info,
                                      std::initializer_list<T> list)
    {
        constexpr const char *prefix = "SetGuestInfo  ";
        std::ostringstream s;
        s << prefix << std::to_string(info);

        for (auto item : list) {
            s << ' ' << item;
        }

        return s.str();
    }

private:
    mutex _lock;

    bool _do_tclo_ping;

    std::unordered_map<std::string, std::unique_ptr<tools_callback>> _callback_map;
    std::set<std::string> _capabilities;

    std::unique_ptr<vmw::rpc::connection> _tclo;
    async::timer_task *_tclo_monitor_task;

    void tclo_monitor();
    void tclo_register_capabilities();
};

} /* namespace vmw */

#endif /* _VMW_TOOLS_H_ */
