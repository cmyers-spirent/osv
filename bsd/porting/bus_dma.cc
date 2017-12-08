/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

// Simplified implementation of BSD's bus_dma interfaces
#include <bsd/porting/netport.h>
#include <bsd/porting/bus.h>
#include <bsd/porting/mmu.h>
#include <osv/align.hh>
#include <osv/pagealloc.hh>
#include <osv/trace.hh>

#include <stack>
#include <vector>
#include <tuple>

#define MAX_BPAGES 512

#ifndef PAGE_MASK
#define PAGE_MASK (PAGE_SIZE - 1)
#endif

TRACEPOINT(trace_bus_dmamap_load_enter, "tag = %p, map = %p, buf = %p, length = %u",
           void *, void *, void *, size_t);
TRACEPOINT(trace_bus_dmamap_load_segment, "tag = %p, map = %p, segment = %x, size = %u",
           void *, void *, size_t, size_t);
TRACEPOINT(trace_bus_dmamap_load_page_info, "tag = %p, map = %p, needed = %u, available = %u",
           void *, void *, size_t, size_t);

TRACEPOINT(trace_bus_dmamap_unload, "tag = %p, map = %p, bpages = %u", void *, void *, size_t);

TRACEPOINT(trace_bus_dmamap_bpage_pop, "tag = %p, page = %x, size = %u", void *, size_t, size_t);
TRACEPOINT(trace_bus_dmamap_bpage_push, "tag = %p, page = %x, size = %u", void *, size_t, size_t);

struct bus_dma_tag {
	bus_size_t	  alignment;
	bus_size_t	  maxsize;
	u_int		  nsegments;
	bus_size_t	  maxsegsz;
	int		  map_count;
	bus_dma_lock_t	 *lockfunc;
	void		 *lockfuncarg;
	bus_dma_segment_t *segments;
	/* The bpages stack is protected by the lockfunc/lockfuncarg above */
	std::stack<vm_offset_t, std::vector<vm_offset_t>> bpages;
};

typedef std::tuple<vm_offset_t, vm_offset_t, bus_size_t> bounce_page_t;
enum bounce_page_index {
	BOUNCE_BUFFER,
	DATA_BUFFER,
	DATA_BUFFER_LEN
};

struct bus_dmamap {
	std::vector<bounce_page_t> bpages;
};

void
busdma_lock_mutex(void *arg, bus_dma_lock_op_t op)
{
	struct mtx *dmtx;

	dmtx = (struct mtx *)arg;
	switch (op) {
	case BUS_DMA_LOCK:
		mtx_lock(dmtx);
		break;
	case BUS_DMA_UNLOCK:
		mtx_unlock(dmtx);
		break;
	default:
		panic("Unknown operation 0x%x for busdma_lock_mutex!", op);
	}
}

static inline vm_offset_t _get_bounce_page(bus_dma_tag_t dmat)
{
	auto bpage = dmat->bpages.top();
	dmat->bpages.pop();
	trace_bus_dmamap_bpage_pop(dmat, bpage, dmat->bpages.size());
	return bpage;
}

int
bus_dma_tag_create(bus_dma_tag_t parent, bus_size_t alignment,
		   bus_addr_t boundary, bus_addr_t lowaddr,
		   bus_addr_t highaddr, bus_dma_filter_t *filter,
		   void *filterarg, bus_size_t maxsize, int nsegments,
		   bus_size_t maxsegsz, int flags, bus_dma_lock_t *lockfunc,
		   void *lockfuncarg, bus_dma_tag_t *dmat)
{
	assert(lockfunc != NULL);

	bus_dma_tag_t newtag = new struct bus_dma_tag;
	if (!newtag)
		return -ENOMEM;

	newtag->alignment = alignment;
	newtag->maxsize = maxsize;
	newtag->nsegments = nsegments;
	newtag->maxsegsz = maxsegsz;
	newtag->map_count = 0;
	newtag->lockfunc = lockfunc;
	newtag->lockfuncarg = lockfuncarg;
	newtag->segments = NULL;

	*dmat = newtag;
	return 0;
}

int
bus_dma_tag_destroy(bus_dma_tag_t dmat)
{
	if (dmat != NULL) {
		if (dmat->map_count != 0) {
			return EBUSY;
		}
		while (!dmat->bpages.empty()) {
			memory::free_page(reinterpret_cast<void *>(_get_bounce_page(dmat)));
		}
		free(dmat);
	}

	return 0;
}

/*
 * Allocate a handle for mapping from kva/uva/physical
 * address space into bus device space.
 */
int
bus_dmamap_create(bus_dma_tag_t dmat, int flags, bus_dmamap_t *mapp)
{
	if (dmat->segments == NULL) {
		dmat->segments = new struct bus_dma_segment[dmat->nsegments];
		if (dmat->segments == NULL) {
			return ENOMEM;
		}
	}

	/*
	 * Bouncing might be required if the driver asks for an
	 * alignment that is stricter than 1.
	 */
	if (dmat->alignment > 1) {
		while (dmat->bpages.size() < MAX_BPAGES) {
			auto page = memory::alloc_page();
			if (page == nullptr) {
				return ENOMEM;
			}
			dmat->bpages.push(reinterpret_cast<vm_offset_t>(page));
		}
	}

	if ((*mapp = new struct bus_dmamap) == NULL) {
		return ENOMEM;
	}
	dmat->map_count++;
	return 0;
}

int
bus_dmamap_destroy(bus_dma_tag_t dmat, bus_dmamap_t map)
{
	for (auto &bpage : map->bpages) {
		auto bounce = std::get<BOUNCE_BUFFER>(bpage);
		dmat->bpages.push(bounce);
	}
	delete map;
	dmat->map_count--;
	return 0;
}


/* Figure out how many bounce pages we need for this buffer */
size_t _bus_dmamap_count_pages(bus_dma_tag_t dmat, vm_offset_t buf, bus_size_t buflen)
{
        vm_offset_t vaddr = buf;
        vm_offset_t vendaddr = vaddr + buflen;
        size_t bpages = 0;
        bus_size_t sg_len = 0;

        while (vaddr < vendaddr) {
                sg_len = PAGE_SIZE - (vaddr & PAGE_MASK);
                bus_addr_t paddr = pmap_kextract(vaddr);
                if (!align_check(paddr, dmat->alignment)) {
                        sg_len = align_up(sg_len, dmat->alignment);
                        bpages++;
                }
                vaddr += sg_len;
        }

        return bpages;
}

/*
 * Map the buffer buf into bus space using the dmamap map.
 */
int
bus_dmamap_load(bus_dma_tag_t dmat, bus_dmamap_t map, void *buf,
		bus_size_t buflen, bus_dmamap_callback_t *callback,
		void *callback_arg, int flags)
{
	unsigned int nsegs = 0;
	auto vaddr = reinterpret_cast<vm_offset_t>(buf);

	trace_bus_dmamap_load_enter(dmat, map, buf, buflen);

	dmat->lockfunc(dmat->lockfuncarg, BUS_DMA_LOCK);

	/* See if we need to use bounce pages */
	auto nb_bpages = _bus_dmamap_count_pages(dmat, vaddr, buflen);
	trace_bus_dmamap_load_page_info(dmat, map, nb_bpages, dmat->bpages.size());
	if (nb_bpages && nb_bpages > dmat->bpages.size()) {
		dmat->lockfunc(dmat->lockfuncarg, BUS_DMA_UNLOCK);
		return EINPROGRESS;
	}

	/* Proceed to populating the segments */
	while (buflen > 0) {
		auto paddr = pmap_kextract(vaddr);
		auto max_segsize = std::min(buflen, dmat->maxsegsz);
		auto segsize = PAGE_SIZE - (vaddr & PAGE_MASK);

		/* check alignment */
		if (align_check(paddr, dmat->alignment)) {
			/* alignment ok; use buffer as is */
			segsize = std::min(segsize, max_segsize);
			dmat->segments[nsegs].ds_addr = paddr;
			dmat->segments[nsegs++].ds_len = segsize;
			vaddr += segsize;
			buflen -= segsize;
			trace_bus_dmamap_load_segment(dmat, map, paddr, segsize);
		} else {
			/* We need to use a bounce buffer */
			segsize = std::min(align_up(segsize, dmat->alignment),
					   max_segsize);
			auto bpage = _get_bounce_page(dmat);
			assert(bpage);
			dmat->segments[nsegs].ds_addr = pmap_kextract(bpage);
			dmat->segments[nsegs++].ds_len = segsize;
			map->bpages.emplace_back(bpage, vaddr, segsize);
			vaddr += segsize;
			buflen -= segsize;
			trace_bus_dmamap_load_segment(dmat, map, pmap_kextract(bpage), segsize);
		}
	}
	assert(nsegs <= dmat->nsegments);
	dmat->lockfunc(dmat->lockfuncarg, BUS_DMA_UNLOCK);

	(*callback)(callback_arg, dmat->segments, nsegs, 0);
	return 0;
}

void
_bus_dmamap_unload(bus_dma_tag_t dmat, bus_dmamap_t map)
{
	trace_bus_dmamap_unload(dmat, map, map->bpages.size());
	dmat->lockfunc(dmat->lockfuncarg, BUS_DMA_LOCK);
	for (auto &bpage : map->bpages) {
		dmat->bpages.push(std::get<BOUNCE_BUFFER>(bpage));
		trace_bus_dmamap_bpage_push(dmat, std::get<BOUNCE_BUFFER>(bpage),
					    dmat->bpages.size());
	}
	dmat->lockfunc(dmat->lockfuncarg, BUS_DMA_UNLOCK);
	map->bpages.clear();
}

void
_bus_dmamap_sync(bus_dma_tag_t dmat, bus_dmamap_t map, bus_dmasync_op_t op)
{
	if (map == nullptr || map->bpages.empty())
		return;

	if ((op & BUS_DMASYNC_PREWRITE) != 0) {
		for (auto &bpage : map->bpages) {
			bcopy(reinterpret_cast<void *>(std::get<DATA_BUFFER>(bpage)),
			      reinterpret_cast<void *>(std::get<BOUNCE_BUFFER>(bpage)),
			      std::get<DATA_BUFFER_LEN>(bpage));
		}
	}

	if ((op & BUS_DMASYNC_POSTREAD) != 0) {
		for (auto &bpage : map->bpages) {
			bcopy(reinterpret_cast<void *>(std::get<BOUNCE_BUFFER>(bpage)),
			      reinterpret_cast<void *>(std::get<DATA_BUFFER>(bpage)),
			      std::get<DATA_BUFFER_LEN>(bpage));
		}
	}
}
