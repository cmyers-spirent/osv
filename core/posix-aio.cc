#include <aio.h>
#include <errno.h>
#include <sys/types.h>
#include <machine/atomic.h>

#include <chrono>
#include <queue>
#include <unordered_map>

#include <osv/barrier.hh>
#include <osv/bio.h>
#include <osv/condvar.h>
#include <osv/file.h>
#include <osv/mutex.h>
#include <osv/sched.hh>
#include <osv/vnode.h>
#include <osv/waitqueue.hh>

#include <osv/trace.hh>

/*
 * The private values inside the AIO control block are set/queried from
 * multiple thread contexts.  Unfortunately, we can't use the nice C++11
 * template stuff because we're dealing with C structs.  So we just create
 * our own templates using the GCC atomic builtins.
 */
template <typename T>
static inline void atomic_store(T *p, T v)
{
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
}

template <typename T>
static inline T atomic_load(T *p)
{
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

/*
 * Convenient wrapper struct for the underlying AIO control block.  This
 * allows us to keep the underlying file object associated with the
 * I/O request while we use it (which prevents the file descriptor
 * from becoming invalid while in use).
 */
struct aio_op {
    enum class state { none, cancelled, queued, running, completed };

    aio_op(struct aiocb *xcb, file *xfile)
        : cb(xcb)
        , file(xfile) {
        /* sanitize control block */
        set_error(EINPROGRESS);
        set_return(0);
    };

    ~aio_op() {};

    aio_op(const aio_op&) = delete;
    aio_op& operator=(const aio_op&) = delete;

    int     get_error() { return atomic_load(&cb->__err); };
    void    set_error(int error) { atomic_store(&cb->__err, error); };

    ssize_t get_return() { return atomic_load(&cb->__ret); };
    void    set_return(ssize_t ret) { atomic_store(&cb->__ret, ret); };

    struct aiocb *cb;
    struct file *file;
};

static struct aio_op *alloc_aio_op(struct aiocb *cb)
{
    struct file *fp = nullptr;
    int error = 0;

    /*
     * Retrieve the internal file object for this
     * operation's file descriptor.  This bumps the
     * reference count and guarantees we will be able
     * to use it for as long as we need.
     */
    if ((error = fget(cb->aio_fildes, &fp)) != 0) {
        errno = error;
        return nullptr;
    }

    auto op = new aio_op(cb, fp);
    if (!op)
        return nullptr;

    return op;
}

static void destroy_aio_op(struct aio_op *op)
{
    /* We need to drop the file after we destroy the op */
    auto fp = op->file;
    delete op;
    fdrop(fp);
}

/*
 * A simple queue to hold (and allow us to cancel) AIO requests before
 * they can be serviced.  Definitely not high performance.
 */
struct aio_queue {
    aio_queue() {};
    ~aio_queue() {};

    aio_queue(const aio_queue&) = delete;
    aio_queue& operator=(const aio_queue&) = delete;

    void push(struct aio_op *op) {
        SCOPE_LOCK(lock);
        queue.push_back(op);
        waitq.wake_one(lock);
    }

    struct aio_op *pop() {
        struct aio_op *op = nullptr;

        SCOPE_LOCK(lock);
        while (!op) {
            if (!queue.empty()) {
                op = queue.front();
                queue.pop_front();
            } else {
                waitq.wait(lock);
            }
        }

        return op;
    }

    /* Cancel all queued ops with a matching file descriptor */
    int cancel(int fildes) {
        size_t nb_matches = 0, nb_cancels = 0;

        SCOPE_LOCK(lock);

        for (auto op : queue) {
            auto cb = op->cb;
            if (fildes == cb->aio_fildes) {
                nb_matches++;
                if (op->get_error() == EINPROGRESS) {
                    op->set_error(ECANCELED);
                    nb_cancels++;
                }
            }
        }

        if (nb_cancels == 0) {
            return AIO_ALLDONE;
        }

        if (nb_matches == nb_cancels) {
            return AIO_CANCELED;
        }

        /* cancelled some but not all (cancels < matches) */
        return AIO_NOTCANCELED;
    }

    /* Cancel queued op that matches the control block */
    int cancel(struct aiocb *cancel_cb) {
        SCOPE_LOCK(lock);

        for (auto op : queue) {
            auto cb = op->cb;
            if (cancel_cb == cb) {
                auto status = op->get_error();
                if (status == ECANCELED || status == EINPROGRESS) {
                    op->set_error(ECANCELED);
                    return AIO_CANCELED;
                }
            }
        }

        /* Not queued... finished? */
        return AIO_ALLDONE;
    }

    std::deque<struct aio_op *> queue;
    mutex lock;
    waitqueue waitq;
};

/* Stuff needed for worker threads */
static aio_queue aio_worker_queue;
static bool need_workers = true;

/* Stuff needed for I/O synchronization */
static mutex   op_completed_lock;
static condvar op_completed;

/*
 * AIO worker function.  Just block on the queue and wait for requests
 * to service.  This is the slow-path.
 */
static void process_aio_queue(struct aio_queue *queue)
{
    for (;;) {
        ssize_t ret = 0;
        int err = 0;

        auto op = queue->pop();
        if (!op)
            continue;

        struct aiocb *cb = op->cb;

        if (op->get_error() != ECANCELED) {

            switch (cb->aio_lio_opcode) {
            case LIO_READ:
                if ((ret = pread(cb->aio_fildes, const_cast<void *>(cb->aio_buf),
                                 cb->aio_nbytes, cb->aio_offset)) < 0) {
                    err = errno;
                }
                break;
            case LIO_WRITE:
                if ((ret = pwrite(cb->aio_fildes, const_cast<void *>(cb->aio_buf),
                              cb->aio_nbytes, cb->aio_offset)) < 0) {
                    err = errno;
                }
                break;
            default:
                err = EINVAL;
            }

            op->set_return(ret);
            op->set_error(err);
        }

        /* No longer need the op */
        destroy_aio_op(op);

        WITH_LOCK(op_completed_lock) {}
        op_completed.wake_all();
    }
}

static void aio_init()
{
    for (size_t i = 0; i < sched::cpus.size(); i++) {
        std::string name("aio");
        name += std::to_string(i);
        auto t = new sched::thread([] { process_aio_queue(&aio_worker_queue); },
                                   sched::thread::attr().name(name));
        t->start();
    }

    need_workers = false;
}

TRACEPOINT(trace_aio_bio_completed, "");
TRACEPOINT(trace_aio_bio_completed_ret, "");

/*
 * For vnode backed devices, we queue the AIO requests directly to the device
 * via a buffer I/O request.  This is the fast path.
 */
static void bio_completed(struct bio *bio)
{
    trace_aio_bio_completed();

    auto op = static_cast<struct aio_op *>(bio->bio_caller1);

    op->set_return(bio->bio_bcount);
    op->set_error(bio->bio_flags & BIO_ERROR ? bio->bio_error : 0);

    destroy_bio(bio);
    destroy_aio_op(op);

    WITH_LOCK(op_completed_lock) {}
    op_completed.wake_all();

    trace_aio_bio_completed_ret();
}

static int bio_queue_strategy(struct aio_op *op)
{
    struct aiocb *cb = op->cb;

    if (file_type(op->file) != DTYPE_VNODE)
        return -1;

    /* do a little pointer walking */
    auto d = file_dentry(op->file);
    auto vp = d->d_vnode;
    auto dev = static_cast<struct device *>(vp->v_data);

    if (vp->v_type != VBLK)
        return -1;

    auto bio = alloc_bio();
    if (!bio)
        return ENOMEM;

    /* fill in the paperwork */
    bio->bio_cmd = cb->aio_lio_opcode == LIO_READ ? BIO_READ : BIO_WRITE;
    bio->bio_dev = dev;
    bio->bio_data = const_cast<void *>(cb->aio_buf);
    bio->bio_offset = cb->aio_offset;
    bio->bio_bcount = cb->aio_nbytes;
    bio->bio_caller1 = op;
    bio->bio_done = bio_completed;

    dev->driver->devops->strategy(bio);

    return 0;
}

static int default_queue_strategy(struct aio_op *op)
{
    if (need_workers)
        aio_init();

    aio_worker_queue.push(op);

    return 0;
}

static int queue_aio_op(struct aio_op *op)
{
    int error = 0;

    /* try to queue directly */
    if ((error = bio_queue_strategy(op)) != 0) {
        /* otherwise, fall back to default queueing strategy */
        error = default_queue_strategy(op);
    }

    return error;
}

static int aio_queue_request(struct aiocb *cb)
{
    int error = 0;

    if (cb->aio_lio_opcode == LIO_NOP) {
        /* Guess we're done */
        return 0;
    }

    auto op = alloc_aio_op(cb);
    if (!op) {
        errno = EBADF;
        return -1;
    }

    if ((error = queue_aio_op(op)) != 0) {
        destroy_aio_op(op);
        errno = error;
        return -1;
    }

    return 0;
}

/*
 * Public AIO functions
 */

int aio_read(struct aiocb *cb)
{
    cb->aio_lio_opcode = LIO_READ;
    return aio_queue_request(cb);
}

int aio_write(struct aiocb *cb)
{
    cb->aio_lio_opcode = LIO_WRITE;
    return aio_queue_request(cb);
}

int aio_error(const struct aiocb *cb)
{
    return atomic_load(&cb->__err);
}

ssize_t aio_return(struct aiocb *cb)
{
    return atomic_load(&cb->__ret);
}

int aio_cancel(int fd, struct aiocb *cb)
{
    if (fd < 0 || fd > FDMAX) {
        errno = EBADF;
        return -1;
    }

    if (cb) {
        return aio_worker_queue.cancel(cb);
    }

    return aio_worker_queue.cancel(fd);
}

TRACEPOINT(trace_aio_suspend, "");
TRACEPOINT(trace_aio_suspend_ret, "");

int aio_suspend(const struct aiocb *const aiocb_list[],
                int nitems, const struct timespec *timeout)
{
    if (nitems < 0) {
        errno = EINVAL;
        return -1;
    }

    if (nitems == 0) {
        return 0;
    }

    trace_aio_suspend();

    for (;;) {
        WITH_LOCK(op_completed_lock) {
            for (int i = 0; i < nitems; ++i) {
                auto cb = aiocb_list[i];
                if (cb && aio_error(cb) == 0) {
                    trace_aio_suspend_ret();
                    return 0;
                }
            }

            if (timeout) {
                int ret = op_completed.wait(&op_completed_lock,
                                            (std::chrono::seconds(timeout->tv_sec) +
                                             std::chrono::seconds(timeout->tv_nsec)));

                if (ret == ETIMEDOUT) {
                    trace_aio_suspend_ret();
                    errno = EAGAIN;
                    return -1;
                }
            } else {
                op_completed.wait(&op_completed_lock);
            }
        }
    }
}

int aio_fsync(int op, struct aiocb *cb)
{
    /* XXX: not yet */
    return ENOSYS;
}
