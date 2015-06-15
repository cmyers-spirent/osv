#include <sys/mount.h>

#include <errno.h>

#include <osv/device.h>
#include <osv/debug.h>

#ifdef _SYS_IOCCOM_H_
error ("do not include me!")
#endif

/*
 * Handle common device ioctl's
 *
 * This is placed in a dedicated file so that we can be sure to pull in the
 * Linux compatible ioctl's.
 */
int device_ioctl_common(struct device *dev, u_long cmd, void *arg);

int
device_ioctl_common(struct device *dev, u_long cmd, void *arg)
{
    int error = 0;

    switch (cmd) {
    case BLKGETSIZE:
    {
        /* return size / 512 */
        unsigned long *size = (unsigned long *)arg;
        if ((uint64_t)(dev->size >> 9) > ~0UL) {
            error = -EFBIG;
        } else {
            *size = dev->size >> 9;
        }
        break;
    }
    case BLKGETSIZE64:
    {
        /* return size in bytes */
        uint64_t *size = (uint64_t *)arg;
        *size = dev->size;
        break;
    }
    default:
        error = (-EINVAL);
    }

    return error;
}
