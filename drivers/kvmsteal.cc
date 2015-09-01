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
