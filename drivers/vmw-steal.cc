#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <vector>

#include <boost/variant.hpp>

#include <rpc/types.h>
#include <rpc/xdr.h>

#include "cpuid.hh"
#include "cpu-steal.hh"
#include "vmw-rpc.hh"

#include <osv/debug.hh>
#include <osv/prio.hh>

#define steal_tag "vmw-steal"
#define steal_d(...)    tprintf_d(steal_tag, __VA_ARGS__)
#define steal_i(...)    tprintf_i(steal_tag, __VA_ARGS__)
#define steal_w(...)    tprintf_w(steal_tag, __VA_ARGS__)
#define steal_e(...)    tprintf_e(steal_tag, __VA_ARGS__)

/*
 * VMware's steal data can (apparently) only be accessed via an RPC call
 * that retrieves every supported stat the hypervisor has.  The guestlib
 * namespace contains the basics to retrieve all of the hypervisors stats, but
 * we only make use of the steal related metrics for now.  We can break this
 * code out into its own module later, if needed.
 */
namespace vmw {
namespace guestlib {
    constexpr const size_t  rpc_string_length = 512;
    constexpr const size_t  rpc_version = 3;
    constexpr const char   *rpc_stats_query = "guestlib.info.get 3";

    using stat_value = boost::variant<uint64_t, std::string>;

    struct stat_header {
        uint32_t version;
        uint64_t session_id;
        uint32_t size;
        char data[0];
    } __attribute__ ((packed));

    enum stat_id {
        reserved = 0,
        cpu_reservation_mhz,
        cpu_limit_mhz,
        cpu_shares,
        cpu_used_ms,
        host_mhz,
        mem_reservation_mb,
        mem_limit_mb,
        mem_shares,
        mem_mapped_mb,
        mem_active_mb,
        mem_overhead_mb,
        mem_ballooned_mb,
        mem_swapped_mb,
        mem_shared_mb,
        mem_shared_saved_mb,
        mem_used_mb,
        elapsed_ms,
        resource_pool_path,
        cpu_stolen_ms,
        mem_target_size_mb,
        host_cpu_num_cores,
        host_cpu_used_ms,
        host_mem_swapped_mb,
        host_mem_shared_mb,
        host_mem_used_mb,
        host_mem_phys_mb,
        host_mem_phys_free_mb,
        host_mem_kern_ovhd_mb,
        host_mem_mapped_mb,
        host_mem_unmapped_mb,
        mem_zipped_mb,
        mem_zipsaved_mb,
        mem_llswapped_mb,
        mem_swap_target_mb,
        mem_balloon_target_mb,
        mem_balloon_max_mb,
        resource_pool_path_long,
        max_statistic_id
    };

    /***
     * Generic XDR retrieval methods
     ***/
    template <typename T>
    T get_xdr_data(XDR *xdrs);

    template<>
    int32_t get_xdr_data<int32_t>(XDR *xdrs)
    {
        int32_t data;
        if (xdr_int32_t(xdrs, &data) == 0) {
            throw std::runtime_error("Could not retrieve int32_t from XDR data");
        }

        return data;
    }

    template<>
    uint32_t get_xdr_data<uint32_t>(XDR *xdrs)
    {
        uint32_t data;
        if (xdr_uint32_t(xdrs, &data) == 0) {
            throw std::runtime_error("Could not retrieve uint32_t from XDR data");
        }

        return data;
    }

    template<>
    uint64_t get_xdr_data<uint64_t>(XDR *xdrs)
    {
        uint64_t data;
        if (xdr_uint64_t(xdrs, &data) == 0) {
            throw std::runtime_error("Could not retrieve uint64_t from XDR data");
        }

        return data;
    }

    template<>
    std::string get_xdr_data<std::string>(XDR *xdrs)
    {
        std::vector<char> data;
        data.resize(rpc_string_length);
        char *p = data.data();
        if (xdr_string(xdrs, &p, rpc_string_length) == 0) {
            throw std::runtime_error("Could not retrieve string from XDR data");
        }

        return std::string(data.begin(), data.end());
    }

    /*
     * VMware guestlib statistics consist of three XDR encoded components
     * 1. 4 byte id
     * 2. 4 byte boolean
     * 3. x byte value (depends on type)
     * The sender and receiver always send data in a fixed order of incrementing
     * ID values.  New values are added to the end with the expectation that the
     * guest will stop parsing data when it hits an ID it doesn't recognize.
     *
     * The statistic object is just a wrapper for retrieving and accessing the
     * ID/validty/value tuple from the XDR data.
     */
    class statistic {
    public:
        virtual ~statistic() {};
        virtual void operator()(XDR *xdrs) = 0;
        virtual enum stat_id get_id() = 0;
        virtual bool is_valid() = 0;
        virtual stat_value get_value() = 0;
    };

    template <typename T>
    class statistic_impl : public statistic {
    public:
        statistic_impl(enum stat_id id)
            : _id(id)
            , _valid(false)
            , _value(0)
        {};

        void operator()(XDR *xdrs)
        {
            enum stat_id xdr_id = static_cast<enum stat_id>(get_xdr_data<int32_t>(xdrs));
            if (xdr_id != _id) {
                std::ostringstream err;
                err << "ID mismatch (Looking for " << _id << " but found "
                    << xdr_id << ")" << std::endl;
                throw std::runtime_error(err.str());
            }

            _valid = get_xdr_data<int32_t>(xdrs) ? true : false;
            _value = get_xdr_data<T>(xdrs);
        }

        enum stat_id get_id() { return _id; }
        bool is_valid() { return _valid; }
        stat_value get_value() { return _value; }

    private:
        enum stat_id _id;
        bool _valid;
        stat_value _value;
    };

    class xdr_stats_parser {
    public:
        xdr_stats_parser(std::initializer_list<statistic *> stats)
        {
            for (auto &s : stats)
                _stats.push_back(std::unique_ptr<statistic>(s));
        }

        void parse(std::vector<char> xdr_data)
        {
            struct stat_header *hdr = reinterpret_cast<struct stat_header *>(xdr_data.data());
            if (hdr->version != rpc_version) {
                std::ostringstream err;
                err << "Stats version mismatch (Expected v" << rpc_version
                    << " but received v" << hdr->version << ")";
                throw std::runtime_error(err.str());
            }

            steal_d("header version = %d, session id = %lu, length = %u\n",
                    hdr->version, hdr->session_id, hdr->size);

            struct xdr_stream x(hdr->data, hdr->size);
            int32_t count = get_xdr_data<uint32_t>(&x.stream);
            steal_d("XDR data contains %d stats\n", count);

            _stats_map.clear();

            for (auto& stat : _stats) {
                if (--count < 0)
                    break;  /* we're out of stats */

                stat->operator()(&x.stream);
                if (stat->is_valid()) {
                    _stats_map.insert(std::make_pair(stat->get_id(),
                                                     stat->get_value()));
                }
            }
        }

        stat_value get_statistic(enum stat_id id)
        {
            if (_stats_map.find(id) != _stats_map.end()) {
                return _stats_map[id];
            } else {
                return stat_value(0);
            }
        }

        void dump()
        {
            for (auto item : _stats_map) {
                std::cout << "id = " << item.first
                          << " value = " << item.second << std::endl;
            }
        }

    private:
        std::map<enum stat_id, stat_value> _stats_map;
        std::vector<std::unique_ptr<statistic>> _stats;

        struct xdr_stream {
            xdr_stream(char *data, size_t length)
            {
                xdrmem_create(&stream, data, length, XDR_DECODE);
            }

            ~xdr_stream()
            {
                xdr_destroy(&stream);
            }

            XDR stream;
        };
    };

#define STAT(Type,Enum) statistic_impl<Type>(Enum)
    xdr_stats_parser *get_stats_parser()
    {
        return new xdr_stats_parser({
                new STAT(uint32_t, cpu_reservation_mhz),
                new STAT(uint32_t, cpu_limit_mhz),
                new STAT(uint32_t, cpu_shares),
                new STAT(uint64_t, cpu_used_ms),
                new STAT(uint32_t, host_mhz),
                new STAT(uint32_t, mem_reservation_mb),
                new STAT(uint32_t, mem_limit_mb),
                new STAT(uint32_t, mem_shares),
                new STAT(uint32_t, mem_mapped_mb),
                new STAT(uint32_t, mem_active_mb),
                new STAT(uint32_t, mem_overhead_mb),
                new STAT(uint32_t, mem_ballooned_mb),
                new STAT(uint32_t, mem_swapped_mb),
                new STAT(uint32_t, mem_shared_mb),
                new STAT(uint32_t, mem_shared_saved_mb),
                new STAT(uint32_t, mem_used_mb),
                new STAT(uint64_t, elapsed_ms),
                new STAT(std::string, resource_pool_path),
                new STAT(uint64_t, cpu_stolen_ms),
                new STAT(uint64_t, mem_target_size_mb),
                new STAT(uint32_t, host_cpu_num_cores),
                new STAT(uint64_t, host_cpu_used_ms),
                new STAT(uint64_t, host_mem_swapped_mb),
                new STAT(uint64_t, host_mem_shared_mb),
                new STAT(uint64_t, host_mem_used_mb),
                new STAT(uint64_t, host_mem_phys_mb),
                new STAT(uint64_t, host_mem_phys_free_mb),
                new STAT(uint64_t, host_mem_kern_ovhd_mb),
                new STAT(uint64_t, host_mem_mapped_mb),
                new STAT(uint64_t, host_mem_unmapped_mb),
                new STAT(uint32_t, mem_zipped_mb),
                new STAT(uint32_t, mem_zipsaved_mb),
                new STAT(uint32_t, mem_llswapped_mb),
                new STAT(uint32_t, mem_swap_target_mb),
                new STAT(uint32_t, mem_balloon_target_mb),
                new STAT(uint32_t, mem_balloon_max_mb)
        });
    }
#undef STAT

} /* namespace guestlib */
} /* namespace vmw */

class vmwsteal : public cpu_steal {
public:
    vmwsteal();
    ~vmwsteal() {};

    static bool probe();
    uint64_t stolen();

private:
    std::unique_ptr<vmw::guestlib::xdr_stats_parser> _parser;
    uint64_t _steal_start;

    std::vector<char> get_stats_data();
    uint64_t get_steal_ns();
};

vmwsteal::vmwsteal()
    : _steal_start(0)
{
    _parser.reset(vmw::guestlib::get_stats_parser());
    _steal_start = get_steal_ns();
}

bool vmwsteal::probe()
{
    if (!processor::features().vmware)
        return false;  /* definitely no */

    /* Check to see if we can actually retrieve stats */
    try {
        std::string response = vmw::rpc::request(vmw::guestlib::rpc_stats_query);
        if (response.front() == '1')
            return true;
        else
            return false;
    }
    catch(...) { return false; }
}

uint64_t vmwsteal::stolen()
{
    return (get_steal_ns() - _steal_start);
}

std::vector<char> vmwsteal::get_stats_data()
{
    std::vector<char> stats = vmw::rpc::request_raw(vmw::guestlib::rpc_stats_query);

    /* Response should be of the form "1 <data>" */
    if (stats.front() != '1' || stats.size() <= 2) {
        stats.clear();  /* nothing worth returning */
        return stats;
    }

    /* trim non-data component */
    stats.erase(stats.begin(), stats.begin() + 2);

    return stats;
}

uint64_t vmwsteal::get_steal_ns()
{
    _parser->parse(get_stats_data());
    uint64_t steal_ms = boost::get<uint64_t>(
        _parser->get_statistic(vmw::guestlib::cpu_stolen_ms));

    return (steal_ms * 1000);
}

static __attribute__((constructor(init_prio::clock))) void setup_vmwsteal()
{
    if (vmwsteal::probe()) {
        cpu_steal::register_cpu_steal(new vmwsteal);
    }
}
