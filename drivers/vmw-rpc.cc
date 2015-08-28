#include <vector>

#include <osv/debug.h>

#include "vmw-rpc.hh"

#define VMW_BACKDOOR_OP(op, frame)                                      \
    __asm__ __volatile__(                                               \
        "pushq %%rbp"           "\n\t"                                  \
        "pushq %%rax"           "\n\t"                                  \
        "movq 48(%%rax), %%rbp" "\n\t"                                  \
        "movq 40(%%rax), %%rdi" "\n\t"                                  \
        "movq 32(%%rax), %%rsi" "\n\t"                                  \
        "movq 24(%%rax), %%rdx" "\n\t"                                  \
        "movq 16(%%rax), %%rcx" "\n\t"                                  \
        "movq  8(%%rax), %%rbx" "\n\t"                                  \
        "movq   (%%rax), %%rax" "\n\t"                                  \
        op "\n\t"                                                       \
        "xchgq %%rax, (%%rsp)"  "\n\t"                                  \
        "movq %%rbp, 48(%%rax)" "\n\t"                                  \
        "movq %%rdi, 40(%%rax)" "\n\t"                                  \
        "movq %%rsi, 32(%%rax)" "\n\t"                                  \
        "movq %%rdx, 24(%%rax)" "\n\t"                                  \
        "movq %%rcx, 16(%%rax)" "\n\t"                                  \
        "movq %%rbx,  8(%%rax)" "\n\t"                                  \
        "popq 0x00(%%rax)"      "\n\t"                                  \
        "popq %%rbp"            "\n\t"                                  \
        : : "a" (frame)                                                 \
        : "rbx", "rcx", "rdx", "rsi", "rdi", "cc", "memory"             \
        )

namespace vmw {
namespace rpc {

#define rpc_tag "vmw-rpc"
#define rpc_d(...)    tprintf_d(rpc_tag, __VA_ARGS__)
#define rpc_i(...)    tprintf_i(rpc_tag, __VA_ARGS__)
#define rpc_w(...)    tprintf_w(rpc_tag, __VA_ARGS__)
#define rpc_e(...)    tprintf_e(rpc_tag, __VA_ARGS__)

    /***
     * Message methods
     ***/
    message::message(vmw::rpc::command cmd,
                     vmw::rpc::subcommand scmd,
                     uint32_t data,
                     vmw::rpc::connection *conn)
    {
        _frame.rax.dword          = vmw::rpc::magic;
        _frame.rbx.dword          = data;
        _frame.rcx.words.low      = cmd;
        _frame.rcx.words.high     = scmd;
        _frame.rdx.words.low      = vmw::rpc::port::cmd;

        if (conn) {
            _frame.rdx.words.high = conn->channel;
            _frame.rsi.dword      = conn->cookie1;
            _frame.rdi.dword      = conn->cookie2;
        }

        _exec = &message::send_cmd;
    }

    message::message(Send,
                     const char *data, uint32_t length,
                     vmw::rpc::connection *conn)
    {
        _frame.rax.dword          = vmw::rpc::magic;
        _frame.rbx.dword          = vmw::rpc::enhanced_data;
        _frame.rcx.dword          = length;
        _frame.rdx.words.low      = vmw::rpc::port::rpc;
        _frame.rsi.quad           = reinterpret_cast<uintptr_t>(data);

        if (conn) {
            _frame.rdx.words.high = conn->channel;
            _frame.rbp.dword      = conn->cookie1;
            _frame.rdi.dword      = conn->cookie2;
        }

        _exec = &message::send_data;
    }

    message::message(Recv,
                     const char *data, uint32_t length,
                     vmw::rpc::connection *conn)
    {
        _frame.rax.dword          = vmw::rpc::magic;
        _frame.rbx.dword          = vmw::rpc::enhanced_data;
        _frame.rcx.dword          = length;
        _frame.rdx.words.low      = vmw::rpc::port::rpc;
        _frame.rdi.quad           = reinterpret_cast<uintptr_t>(data);

        if (conn) {
            _frame.rdx.words.high = conn->channel;
            _frame.rsi.dword      = conn->cookie1;
            _frame.rbp.dword      = conn->cookie2;
        }

        _exec = &message::get_data;
    }

    void message::dump_frame(struct frame &frame)
    {
        rpc_d("Begin frame dump...\n");
        rpc_d("eax = %08x\n", frame.rax.dword);
        rpc_d("ebx = %08x\n", frame.rbx.dword);
        rpc_d("ecx = %08x\n", frame.rcx.dword);
        rpc_d("edx = %08x\n", frame.rdx.dword);
        rpc_d("esi = %08x\n", frame.rsi.dword);
        rpc_d("edi = %08x\n", frame.rdi.dword);
        rpc_d("ebp = %08x\n", frame.rbp.dword);
        rpc_d("... End frame dump\n");
    };

    void message::send_cmd(struct frame &frame)
    {
        /* store for debug output */
        uint16_t cmd  = frame.rcx.words.low;
        uint16_t scmd = frame.rcx.words.high;

        VMW_BACKDOOR_OP("inl %%dx, %%eax;", &frame);

        if ((frame.rcx.words.high & vmw::rpc::reply::success) == 0) {
            dump_frame(frame);
            throw std::runtime_error("vmw::rpc::message::send_cmd ("
                                     + std::to_string(cmd) + "|"
                                     + std::to_string(scmd) + ") failed");
        }
    }

    void message::send_data(struct frame &frame)
    {
        /* store a pointer in case we need it */
        const char *data = reinterpret_cast<const char *>(frame.rsi.quad);
        rpc_d("send: channel = %d, data = %s\n", frame.rdx.words.high, data);

        VMW_BACKDOOR_OP("cld;\n\trep outsb;", &frame);

        if (frame.rbx.dword != vmw::rpc::enhanced_data) {
            dump_frame(frame);
            throw std::runtime_error("vmw::rpc::message::send_data ("
                                     + std::string(data) + ") failed");
        }
    }

    void message::get_data(struct frame &frame)
    {
        VMW_BACKDOOR_OP("cld;\n\trep insb;", &frame);

        if (frame.rbx.dword != vmw::rpc::enhanced_data) {
            dump_frame(frame);
            throw std::runtime_error("vmw::rpc::message::get_data failed");
        }

        rpc_d("recv: channel = %d, data = %s\n", frame.rdx.words.high,
              reinterpret_cast<const char *>(frame.rdi.quad));
    }

    /***
     * Connection methods
     ***/
    connection::connection(uint32_t magic)
    {
        open(magic);
    }

    connection::~connection()
    {
        try {
            close();
        }
        catch(...) {};
    }

    bool connection::open(uint32_t magic)
    {
        auto open = vmw::rpc::message(vmw::rpc::command::do_rpc,
                                      vmw::rpc::subcommand::open,
                                      magic | vmw::rpc::flag_cookie,
                                      this);

        open();

        channel = open._frame.rdx.words.high;
        cookie1 = open._frame.rsi.dword;
        cookie2 = open._frame.rdi.dword;

        return true;
    }

    bool connection::close()
    {
        auto close = vmw::rpc::message(vmw::rpc::command::do_rpc,
                                       vmw::rpc::subcommand::close,
                                       0, this);

        close();

        channel = cookie1 = cookie2 = 0;
        return true;
    }

    /***
     * RPC operations
     ***/
    void ping(vmw::rpc::connection *connection)
    {
        auto ping = vmw::rpc::message(vmw::rpc::command::do_rpc,
                                      vmw::rpc::subcommand::set_length,
                                      0, connection);

        ping();
    }

    void send(vmw::rpc::connection *connection, std::string message)
    {
        auto set_length = vmw::rpc::message(vmw::rpc::command::do_rpc,
                                            vmw::rpc::subcommand::set_length,
                                            message.length(), connection);

        set_length();

        if (message.length() == 0)
            return;

        auto send_data = vmw::rpc::message(message::send,
                                           message.c_str(), message.length(),
                                           connection);

        send_data();
    }

    std::string recv(vmw::rpc::connection *connection)
    {
        std::string empty("");

        auto get_length = vmw::rpc::message(vmw::rpc::command::do_rpc,
                                            vmw::rpc::subcommand::get_length,
                                            0, connection);

        get_length();

        if ((get_length._frame.rcx.words.high & vmw::rpc::reply::do_recv) == 0)
            return empty;

        uint32_t msg_len = get_length._frame.rbx.dword;
        uint16_t msg_key = get_length._frame.rdx.words.high;
        std::vector<char> incoming;
        incoming.reserve(msg_len + 1);

        auto get_data = vmw::rpc::message(message::recv,
                                          incoming.data(), msg_len,
                                          connection);

        get_data();

        incoming[msg_len] = '\0';

        auto ack = vmw::rpc::message(vmw::rpc::command::do_rpc,
                                     vmw::rpc::subcommand::get_end,
                                     msg_key, connection);

        ack();

        return std::string(incoming.data());
    }

    std::string request(std::string r)
    {
        vmw::rpc::connection conn(vmw::rpc::rpci);
        send(&conn, r);
        return recv(&conn);
    }

    std::string request(const char *r)
    {
        return request(std::string(r));
    }

} /* namespace rpc */
} /* namespace vmw */
