#ifndef CPU_STEAL_HH_
#define CPU_STEAL_HH_

#include <osv/types.h>

class cpu_steal {
public:
    virtual ~cpu_steal() {};

    static void register_cpu_steal(cpu_steal *cs);

    /**
     * Get a pointer to the concrete instance of the cpu_steal class.
     *
     * This may be null on platforms that don't have a method force
     * retrieving this information.
     * \return a pointer to a concrete class instance
     */
    static cpu_steal *get() __attribute__((no_instrument_function));

    /**
     * Get the current accumulated steal time, in nanoseconds.
     */
    virtual uint64_t stolen() = 0;

private:
    static cpu_steal *_cs;
};

#endif
