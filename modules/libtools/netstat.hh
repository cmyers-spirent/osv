/*
 * Copyright (C) 2018 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#ifndef NETSTAT_HH_
#define NETSTAT_HH_
#include <string>
#include <functional>

#include <bsd/sys/netinet/tcp_stat.h>
#include <bsd/sys/netinet/udp_stat.h>

namespace osv {

struct pcb_stats {
    std::string proto;
    std::string foreign_addr;
    std::string local_addr;
    int         foreign_port;
    int         local_port;
    std::string state;
    u_long      txq_bytes;
    u_long      rxq_bytes;
};

/**
 * A lambda expression that is used to iterate of the protocol control blocks.
 * It gets the pcb_stats as a parameter, and return true to continue
 * iterating or false to stop.
 *
 */
typedef std::function<bool(const pcb_stats &)> pcb_stats_fun;

/**
 * Iterate over all TCP sessions, stops if pcb_stats_func return false
 * @param a function to go over the TCP session
 * @return 0 on success or errno on failure
 */
int foreach_tcp_session(pcb_stats_fun);

/**
 * Iterate over all UDP sessions, stops if pcb_stats_func return false
 * @param a function to go over the TCP session
 * @return 0 on success or errno on failure
 */
int foreach_udp_session(pcb_stats_fun);

/**
 * Get global TCP stats
 */
int get_tcp_stats(struct tcpstat &stats);

/**
 * Get global UDP stats
 */
int get_udp_stats(struct udpstat &stats);

}

#endif /* NETSTAT_HH_ */
