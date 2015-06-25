#include <chrono>

#include "cpuid.hh"
#include "cpu-steal.hh"
#include "msr.hh"

#include <osv/barrier.hh>
#include <osv/mmu.hh>
#include <osv/percpu.hh>
#include <osv/prio.hh>
#include <osv/sched.hh>

struct kvm_steal_time {
    uint64_t steal;
    uint32_t version;
    uint32_t flags;
    uint32_t pad[12];
} __attribute__((packed));  /* 64 bytes */

class kvmsteal : public cpu_steal {
public:
    kvmsteal();
    ~kvmsteal();

    static bool probe();
    uint64_t stolen();

private:
    /*
     * per-cpu steal time struct
     * Note: The KVM steal struct requires 64 byte alignment
     */
    dynamic_percpu<struct kvm_steal_time, 64> _steal;
    std::unique_ptr<sched::cpu::notifier> _notifier;

    void init_on_cpu();
    void halt_on_cpu();

    uint64_t read_steal_time(struct kvm_steal_time *);
};

kvmsteal::kvmsteal()
{
    _notifier.reset(new sched::cpu::notifier([&] { init_on_cpu(); }));
}

kvmsteal::~kvmsteal()
{
    for (auto cpu : sched::cpus) {
        processor::wrmsr(msr::KVM_STEAL_TIME,
                         mmu::virt_to_phys(_steal.for_cpu(cpu)));
    }
}

bool kvmsteal::probe()
{
    if (processor::features().kvm_steal_time) {
        return true;
    }

    return false;
}

uint64_t kvmsteal::stolen()
{
    uint64_t total_steal_time = 0;

    for (auto cpu : sched::cpus) {
        total_steal_time += read_steal_time(_steal.for_cpu(cpu));
    }

    return total_steal_time;
}

void kvmsteal::init_on_cpu()
{
    memset(&*_steal, 0, sizeof(*_steal));
    processor::wrmsr(msr::KVM_STEAL_TIME, mmu::virt_to_phys(&*_steal) | 1);
}

uint64_t kvmsteal::read_steal_time(struct kvm_steal_time *s)
{
    uint32_t v1, v2;
    uint64_t time;

    do {
        v1 = s->version;
        barrier();
        time = s->steal;
        barrier();
        v2 = s->version;
    } while ((v1 & 1) || (v1 != v2));

    return time;
}

static __attribute__((constructor(init_prio::clock))) void setup_kvmsteal()
{
    if (kvmsteal::probe()) {
        cpu_steal::register_cpu_steal(new kvmsteal);
    }
}
