#ifndef _BSD_MALLOC_H
#define _BSD_MALLOC_H
#include <bsd/porting/mmu.h>
#include <bsd/porting/netport.h>
// just our malloc impl.
#include <malloc.h>
#include "param.h" // BSD malloc includes this, so some files do not.
                   // Also differentiate from include/api/sys/param.h
#include "priority.h"

#ifdef __FBSDID

enum bsd_malloc_arena {
    M_WHATEVER,
    M_DEVBUF,
    M_XENSTORE,
    M_XENBLOCKFRONT,
    M_XENBUS,
    M_TEMP,
};

// The BSD malloc has extra parameters, which we mostly ignore with two
// exceptions:
// 1) The M_XENBLOCKFRONT arena needs to be page aligned, since this allocation
//    is shared with the Xen hypervisor
// 2) Clients might want 0'd out memory, which we honor.
inline void* __bsd_malloc(size_t size, int arena, int flags)
{
    void *ptr = NULL;
    switch (arena) {
    case M_XENBLOCKFRONT:
        ptr = aligned_alloc(PAGE_SIZE, size);
        break;
    default:
        ptr = malloc(size);
    }

    if (!ptr)
        return ptr;
    if (flags & M_ZERO)
        memset(ptr, 0, size);
    return ptr;
}

#ifndef __cplusplus

#define malloc(x, y, z) __bsd_malloc(x, y, z)
#define free(x, y) free(x)
#define strdup(x, y) strdup(x)

#else

inline void *malloc(size_t size, int arena, int flags)
{
    return __bsd_malloc(size, arena, flags);
}

inline void free(void* obj, int flags)
{
    free(obj);
}

inline char* strdup(const char* s, int bsd_malloc_arena)
{
    return strdup(s);
}


#endif

#endif

#endif
