/*
 * Copyright (c) 2015 Spirent Communications, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

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
