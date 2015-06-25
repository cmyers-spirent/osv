#include <assert.h>
#include "cpu-steal.hh"

cpu_steal *cpu_steal::_cs = nullptr;

void cpu_steal::register_cpu_steal(cpu_steal *cs)
{
    assert(_cs == nullptr);
    _cs = cs;
}

cpu_steal * cpu_steal::get()
{
    return _cs;
}
