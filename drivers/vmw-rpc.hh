/*
 * Copyright (c) 2007 David Crawshaw <david@zentus.com>
 * Copyright (c) 2008 David Gwynne <dlg@openbsd.org>
 * Copyright (c) 2015 Spirent Communications, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _VMW_RPC_H_
#define _VMW_RPC_H_

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace vmw {
namespace rpc {

/* various magic numbers */
const uint32_t magic         = 0x564d5868;
const uint32_t rpci          = 0x49435052;
const uint32_t tclo          = 0x4f4c4354;
const uint32_t enhanced_data = 0x00010000;
const uint32_t flag_cookie   = 0x80000000;
const uint32_t version       = 0x7fffffff;

enum port {
    cmd = 0x5658,
    rpc = 0x5659
};

/* RPC commands, passed on ECX.LOW */
enum command {
    get_speed         = 0x0001,
    apm               = 0x0002,
    get_mousepos      = 0x0004,
    set_mousepos      = 0x0005,
    get_clipboard_len = 0x0006,
    get_clipboard     = 0x0007,
    set_clipboard_len = 0x0008,
    set_clipboard     = 0x0009,
    get_version       = 0x000a,
    get_devinfo       = 0x000b,
    dev_addremove     = 0x000c,
    get_gui_options   = 0x000d,
    set_gui_options   = 0x000e,
    get_screen_size   = 0x000f,
    get_hwver         = 0x0011,
    popup_osnotfound  = 0x0012,
    get_bios_uuid     = 0x0013,
    get_mem_size      = 0x0014,
    do_rpc            = 0x001e,
    get_time_full     = 0x002e
};

/* RPC subcommands, passed on ECX.HIGH */
enum subcommand {
    open       = 0x0000,
    set_length = 0x0001,
    set_data   = 0x0002,
    get_length = 0x0003,
    get_data   = 0x0004,
    get_end    = 0x0005,
    close      = 0x0006,
    probe      = 0xffff
};

/* RPC reply flags */
enum reply {
    success             = 0x01,
    do_recv             = 0x02,
    closed              = 0x04,
    unsent              = 0x08,
    checkpoint          = 0x10,
    poweroff            = 0x20,
    timeout             = 0x040,
    reply_highbandwidth = 0x80
};

/* Guest 'states' */
enum state {
    halt    = 0x01,
    reboot  = 0x02,
    poweron = 0x03,
    resume  = 0x04,
    suspend = 0x05
};

/* RPC information keys */
enum guestinfo {
    dns_name        = 0x01,
    ip_address      = 0x02,
    disk_free_space = 0x03,
    build_number    = 0x04,
    os_name_full    = 0x05,
    os_name         = 0x06,
    uptime          = 0x07,
    memory          = 0x08,
    ip_address_v2   = 0x09
};

/* Standard RPC responses */
constexpr const char *reply_ok = "OK ";
constexpr const char *reply_error = "ERROR Unknown command";

class connection {
public:
    connection(uint32_t magic);
    ~connection();

    uint16_t channel;
    uint32_t cookie1;
    uint32_t cookie2;

private:
    bool open(uint32_t magic);
    bool close();
};

class message {
public:
    enum Send {send};
    enum Recv {recv};

    /* Convenient access to the various bits inside an x86 CPU register */
    union x86_register {
        x86_register() { quad = 0x0; };
        struct {
            uint16_t low;
            uint16_t high;
        } words;
        uint32_t dword;
        struct {
            uint32_t low;
            uint32_t high;
        } dwords;
        uint64_t quad;
    } __attribute__((packed));

    /*
     * RPC messages are passed to/from the host via CPU registers.
     * A full message uses all of the registers in this 'stack' frame
     */
    struct frame {
        x86_register rax;
        x86_register rbx;
        x86_register rcx;
        x86_register rdx;
        x86_register rsi;
        x86_register rdi;
        x86_register rbp;
    } __attribute__((packed));

    message(vmw::rpc::command cmd,
            vmw::rpc::subcommand scmd,
            uint32_t data,
            vmw::rpc::connection *conn = nullptr);

    message(Recv,
            const char *data, uint32_t length,
            vmw::rpc::connection *conn = nullptr);

    message(Send,
            const char *data, uint32_t length,
            vmw::rpc::connection *conn = nullptr);

    void operator()() { if (_exec) { return _exec(_frame); } };

    struct frame _frame;

private:
    std::function<void (struct frame &frame)> _exec;

    static void dump_frame(struct frame &frame);

    static void send_cmd(struct frame &frame);
    static void get_data(struct frame &frame);
    static void send_data(struct frame &frame);
};

/* Basic RPC operations */
void              ping(vmw::rpc::connection *connection);
void              send(vmw::rpc::connection *connection, std::string message);
std::string       recv(vmw::rpc::connection *connection);
std::vector<char> recv_raw(vmw::rpc::connection *connection);

/* Complete RPC operations, e.g. send + receive */
std::string       request(const std::string r);
std::vector<char> request_raw(const std::string r);

} /* namespace rpc */
} /* namespace vmw */

#endif /* _VMW_RPC_H_ */
