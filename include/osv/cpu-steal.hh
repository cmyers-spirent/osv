#ifndef OSV_CPU_STEAL_HH_
#define OSV_CPU_STEAL_HH_

#include <drivers/cpu-steal.hh>
#include <chrono>

namespace osv {

    namespace sched {

        class steal_time {
        public:
            static std::chrono::nanoseconds stolen() {
                uint64_t stolen = 0;
                auto cs = cpu_steal::get();
                if (cs) {
                    stolen = cs->stolen();
                }

                return std::chrono::nanoseconds(stolen);
            }
        };
    };
};

#endif
