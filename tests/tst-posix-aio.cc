#include <aio.h>
#include <fcntl.h>
#include <string.h>
#include <algorithm>
#include <osv/clock.hh>
#include <osv/debug.hh>

int tests = 0, fails = 0;

static void report(bool ok, const char *msg)
{
    ++tests;
    fails += !ok;
    debug("%s: %s\n", (ok ? "PASS" : "FAIL"), msg);
}

// We need a large bufsize for verifying that the timeout code actually works...
constexpr int bufsize_large = 4 * 1024 * 1024;
constexpr int bufsize_small = 16 * 1024;

int main(int ac, char **av)
{
    // Create a file for testing
    char filename[] = "/tmp/tst-posix-aio.XXXXXX";
    int fd = mkostemp(filename, O_SYNC);
    report(fd >= 0, "test file creation");
    int r = ftruncate(fd, bufsize_large);
    report(r == 0, "truncate");

    // write to the file
    std::vector<char> input, output;
    input.reserve(bufsize_small);
    output.reserve(bufsize_small);
    std::fill_n(input.begin(), bufsize_small, 'A');

    struct aiocb writecb;
    writecb.aio_fildes = fd;
    writecb.aio_offset = 0;
    writecb.aio_buf = &input[0];
    writecb.aio_nbytes = bufsize_small;
    writecb.aio_reqprio = 0;
    writecb.aio_sigevent.sigev_notify = SIGEV_NONE;

    r = aio_write(&writecb);
    report(r == 0, "aio write");

    // wait to complete
    struct aiocb *cblist[] = { &writecb };
    r = aio_suspend(cblist, 1, NULL);
    report(r == 0, "aio suspend");

    // verify no write error
    r = aio_error(&writecb);
    report(r == 0, "aio error");
    r = aio_return(&writecb);
    report(r == bufsize_small, "aio return");

    // read what we wrote
    struct aiocb readcb;
    readcb.aio_fildes = fd;
    readcb.aio_offset = 0;
    readcb.aio_buf = &output[0];
    readcb.aio_nbytes = bufsize_small;
    readcb.aio_reqprio = 0;
    readcb.aio_sigevent.sigev_notify = SIGEV_NONE;

    r = aio_read(&readcb);
    report(r == 0, "aio read");

    // wait to complete
    cblist[0] = &readcb;
    r = aio_suspend(cblist, 1, NULL);
    report(r == 0, "aio suspend");

    // verify no read error
    r = aio_error(&readcb);
    report(r == 0, "aio error");
    r = aio_return(&readcb);
    report(r == bufsize_small, "aio return");

    // verify read contents
    r = equal(input.begin(), input.end(), output.begin());
    report(r, "equal");

    // Now, perform operations with timeouts
    struct timespec ts_short = { 0, 1000 };
    struct timespec ts_long = { 1, 0 };

    input.reserve(bufsize_large);
    output.reserve(bufsize_large);
    std::fill_n(input.begin(), bufsize_large, 'B');
    writecb.aio_nbytes = bufsize_large;

    r = aio_write(&writecb);
    report(r == 0, "aio write");

    // wait to complete
    cblist[0] = &writecb;
    r = aio_suspend(cblist, 1, &ts_short);
    report(r == -1, "aio suspend short");
    report(errno == EAGAIN, "aio suspend short errno");

    r = aio_suspend(cblist, 1, &ts_long);
    report(r == 0, "aio suspend long");

    // verify no write error
    r = aio_error(&writecb);
    report(r == 0, "aio error");
    r = aio_return(&writecb);
    report(r == bufsize_large, "aio return");

    // reread what we rewrote
    readcb.aio_fildes = fd;
    readcb.aio_offset = 0;
    readcb.aio_buf = &output[0];
    readcb.aio_nbytes = bufsize_large;
    readcb.aio_reqprio = 0;
    readcb.aio_sigevent.sigev_notify = SIGEV_NONE;

    r = aio_read(&readcb);
    report(r == 0, "aio read");

    // wait to complete
    cblist[0] = &readcb;
    r = aio_suspend(cblist, 1, NULL);
    report(r == 0, "aio suspend");

    // verify no read error
    r = aio_error(&readcb);
    report(r == 0, "aio error");
    r = aio_return(&readcb);
    report(r == bufsize_large, "aio return");

    // verify read contents
    r = equal(input.begin(), input.end(), output.begin());
    report(r, "equal");

    close(fd);
    r = unlink(filename);
    report(r == 0, "unlink");

    debug("SUMMARY: %d tests, %d failures\n", tests, fails);
}
