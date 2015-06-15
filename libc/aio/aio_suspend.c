#include <aio.h>
#include <errno.h>
#ifdef __OSV__
#include <atomic.h>
#include <osv/condvar.h>
#include <osv/mutex.h>
#include <pthread.h>
#else
#include "pthread_impl.h"
#endif


/* Due to the requirement that aio_suspend be async-signal-safe, we cannot
 * use any locks, wait queues, etc. that would make it more efficient. The
 * only obviously-correct algorithm is to generate a wakeup every time any
 * aio operation finishes and have aio_suspend re-evaluate the completion
 * status of each aiocb it was waiting on. */

static mutex_t aio_mutex = MUTEX_INITIALIZER;
static condvar_t aio_cv = CONDVAR_INITIALIZER;

void __aio_wake(void)
{
	mutex_lock(&aio_mutex);
	condvar_wake_all(&aio_cv);
	mutex_unlock(&aio_mutex);
}

int aio_suspend(const struct aiocb *const cbs[], int cnt, const struct timespec *ts)
{
	int i, first=1, ret=0;
	struct timespec at;
	uint64_t expiration=0;

	if (cnt<0) {
		errno = EINVAL;
		return -1;
	}

	for (;;) {
		for (i=0; i<cnt; i++) {
			if (cbs[i] && cbs[i]->__err != EINPROGRESS)
				return 0;
		}

		if (first && ts) {
			clock_gettime(CLOCK_MONOTONIC, &at);
			at.tv_sec += ts->tv_sec;
			if ((at.tv_nsec += ts->tv_nsec) >= 1000000000) {
				at.tv_nsec -= 1000000000;
				at.tv_sec++;
			}
			first = 0;
			expiration = at.tv_sec * 1000000000 + at.tv_nsec;
		}

		mutex_lock(&aio_mutex);
		ret = condvar_wait(&aio_cv, &aio_mutex, ts ? expiration : 0);
		mutex_unlock(&aio_mutex);

		if (ret == ETIMEDOUT) ret = EAGAIN;

		if (ret) {
			errno = ret;
			return -1;
		}
	}
}
