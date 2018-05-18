/*
 * Copyright (c) 1988, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *	  may be used to endorse or promote products derived from this software
 *	  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)rtsock.c	8.7 (Berkeley) 10/12/95
 * $FreeBSD$
 */

#include <osv/initialize.hh>
#include <bsd/porting/netport.h>

#include <bsd/sys/sys/param.h>
#include <bsd/sys/sys/domain.h>
#include <bsd/sys/sys/mbuf.h>
#include <bsd/sys/sys/priv.h>
#include <bsd/sys/sys/protosw.h>
#include <bsd/sys/sys/socket.h>
#include <bsd/sys/sys/socketvar.h>
#include <bsd/sys/sys/sysctl.h>

#include <bsd/sys/net/if.h>
#include <bsd/sys/net/if_dl.h>
#include <bsd/sys/net/if_llatbl.h>
#include <bsd/sys/net/if_types.h>
#include <bsd/sys/net/netisr.h>
#include <bsd/sys/net/raw_cb.h>
#include <bsd/sys/net/route.h>
#include <bsd/sys/net/vnet.h>

#include <bsd/sys/netinet/in.h>
#include <bsd/sys/netinet/if_ether.h>
#ifdef INET6
#include <bsd/sys/netinet/ip6.h>
#include <bsd/sys/netinet6/ip6_var.h>
#include <bsd/sys/netinet6/in6_var.h>
#include <bsd/sys/netinet6/scope6_var.h>
#endif

#include <bsd/sys/compat/linux/linux_netlink.h>
#include <bsd/sys/compat/linux/linux.h>
#include <bsd/sys/compat/linux/linux_socket.h>

#if !defined(offsetof)
#define offsetof(TYPE, MEMBER) __builtin_offsetof (TYPE, MEMBER)
#endif


mutex netlink_mtx;

#define NETLINK_LOCK()	 mutex_lock(&netlink_mtx)
#define NETLINK_UNLOCK() mutex_unlock(&netlink_mtx)
#define NETLINK_LOCK_ASSERT()	 assert(netlink_mtx.owned())


MALLOC_DEFINE(M_NETLINK, "netlink", "netlink socket");

static struct	bsd_sockaddr netlink_src = { 2, PF_NETLINK, };


static size_t mask_to_prefix_len(const uint8_t *bytes, size_t n_bytes)
{
	for (size_t i=0; i <n_bytes; ++i) {
		uint8_t val = bytes[n_bytes - i - 1];
		if (val == 0)
			continue;
		/* Find first bit in byte which is set */
		int bit_pos = __builtin_ffs((long)val) - 1;
		size_t pos = 8 * (n_bytes - i) - bit_pos;
		return pos;
	}
	return 0;
}

static int get_sockaddr_mask_prefix_len(struct bsd_sockaddr *sa)
{
	void *data;
	int	  data_len;

	if (!sa)
		return 0;

	switch (sa->sa_family) {
#ifdef INET
	case AF_INET:
		data = &((struct bsd_sockaddr_in *)sa)->sin_addr;
		data_len = sizeof(((struct bsd_sockaddr_in *)sa)->sin_addr);
		break;
#endif
#ifdef INET6
	case AF_INET6:
		data = ((struct bsd_sockaddr_in6 *)sa)->sin6_addr.s6_addr;
		data_len = sizeof(((struct bsd_sockaddr_in6 *)sa)->sin6_addr);
		break;
#endif
	default:
		return 0;
	}

	return mask_to_prefix_len((uint8_t *)data, data_len);
}


void *nl_m_put(struct mbuf *m0, int len)
{
	struct mbuf *m, *n;
	void *data = NULL;
	int space;

	/* Skip to last buffer in chain */
	for (m = m0; m->m_hdr.mh_next != NULL; m = m->m_hdr.mh_next)
		;

	space = M_TRAILINGSPACE(m);
	if (len <= space) {
		/* Add to existing buffer if there is space */
		data = m->m_hdr.mh_data + m->m_hdr.mh_len;
		m->m_hdr.mh_len += len;
	} else {
		/* Add additional buffer for new message */
		if (len > MLEN)
			return NULL;
		n = m_get(M_NOWAIT, m->m_hdr.mh_type);
		if (n == NULL)
			return NULL;
		data = n->m_hdr.mh_data;
		n->m_hdr.mh_len = len;
		m->m_hdr.mh_next = n;
		m = n;
	}
	if (m0->m_hdr.mh_flags & M_PKTHDR) {
		m0->M_dat.MH.MH_pkthdr.len += len;
	}
	return data;
}

struct nlmsghdr * nlmsg_put(struct mbuf *m, uint32_t pid, uint32_t seq, int type, int len, int flags)
{
	struct nlmsghdr *nlh;
	int size = nlmsg_msg_size(len);
	int align_size = NLMSG_ALIGN(size);
	nlh = (struct nlmsghdr *) nl_m_put(m, align_size);
	if (!nlh)
		return NULL;
	nlh->nlmsg_type = type;
	nlh->nlmsg_len = size;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_pid = pid;
	nlh->nlmsg_seq = seq;
	if (align_size != size) {
		memset(nlmsg_data(nlh) + len, 0, align_size - size);
	}
	return nlh;
}

struct nlmsghdr * nlmsg_begin(struct mbuf *m, uint32_t pid, uint32_t seq, int type, int len, int flags)
{
	return nlmsg_put(m, pid, seq, type, len, flags);
}

void nlmsg_end(struct mbuf *m, struct nlmsghdr *nlh)
{
	nlh->nlmsg_len = m->M_dat.MH.MH_pkthdr.len - ((uintptr_t)nlh - (uintptr_t)m->m_hdr.mh_data);
}

int nla_put(struct mbuf *m, int attrtype, int len, const void *src)
{
	struct nlattr *nla;
	int size = nla_attr_size(len);
	int align_size = NLA_ALIGN(size);
	nla = (struct nlattr *)nl_m_put(m, align_size);
	if (!nla)
		return ENOMEM;
	nla->nla_len = size;
	nla->nla_type = attrtype;
	void *dest = nla_data(nla);
	memcpy(dest, src, len);
	if (size != align_size)
		memset(dest + size, 0, (align_size - size));
	return 0;
}

template<class T>
int nla_put_type(struct mbuf *m, int attrtype, T val)
{
	return nla_put(m, attrtype, sizeof(val), &val);
}

int nla_put_string(struct mbuf *m, int attrtype, const char *str)
{
	return nla_put(m, attrtype, strlen(str) + 1, str);
}

int nla_put_sockaddr(struct mbuf *m, int attrtype, struct bsd_sockaddr *sa)
{
	void *data;
	int	  data_len;

	if (!sa)
		return 0;

	switch (sa->sa_family) {
#ifdef INET
	case AF_INET:
		data = &((struct bsd_sockaddr_in *)sa)->sin_addr;
		data_len = sizeof(((struct bsd_sockaddr_in *)sa)->sin_addr);
		break;
#endif
#ifdef INET6
	case AF_INET6:
		data = ((struct bsd_sockaddr_in6 *)sa)->sin6_addr.s6_addr;
		data_len = sizeof(((struct bsd_sockaddr_in6 *)sa)->sin6_addr);
		break;
#endif
	case AF_LINK:
		data = ((struct bsd_sockaddr_dl *)sa)->sdl_data + ((struct bsd_sockaddr_dl *)sa)->sdl_nlen;
		data_len = ((struct bsd_sockaddr_dl *)sa)->sdl_alen;
		break;
	default:
		data = sa->sa_data;
		data_len = sa->sa_len;
		break;
	}

	return nla_put(m, attrtype, data_len, data);
}

static int	netlink_output(struct mbuf *m, struct socket *so);

//#define NETLINK_ISR_DISPATCH
#ifdef NETLINK_ISR_DISPATCH

/* Currently messages are always redirected back to the socket which
 * sent the message, so an ISR dispatch handler is not needed.
 *
 */

static void	netlink_input(struct mbuf *m);

static struct netisr_handler netlink_nh = initialize_with([] (netisr_handler& x) {
	x.nh_name = "netlink";
	x.nh_handler = netlink_input;
	x.nh_proto = NETISR_NETLINK;
	x.nh_policy = NETISR_POLICY_SOURCE;
});

static int
raw_input_netlink_cb(struct mbuf *m, struct sockproto *proto, struct bsd_sockaddr *src, struct rawcb *rp)
{
	int fibnum;

	KASSERT(m != NULL, ("%s: m is NULL", __func__));
	KASSERT(proto != NULL, ("%s: proto is NULL", __func__));
	KASSERT(rp != NULL, ("%s: rp is NULL", __func__));

	/* No filtering requested. */
	if ((m->m_hdr.mh_flags & RTS_FILTER_FIB) == 0)
		return (0);

	/* Check if it is a rts and the fib matches the one of the socket. */
	fibnum = M_GETFIB(m);
	if (proto->sp_family != PF_ROUTE ||
		rp->rcb_socket == NULL ||
		rp->rcb_socket->so_fibnum == fibnum)
		return (0);

	/* Filtering requested and no match, the socket shall be skipped. */
	return (1);
}

static void
netlink_input(struct mbuf *m)
{
	struct sockproto netlink_proto;
	unsigned short *family;
	struct m_tag *tag;

	netlink_proto.sp_family = PF_NETLINK;

	raw_input_ext(m, &netlink_proto, &netlink_src, raw_input_netlink_cb);
}

#endif // NETLINK_ISR_DISPATCH

void
netlink_init(void)
{
	mutex_init(&netlink_mtx);
#ifdef NETLINK_ISR_DISPATCH
	netisr_register(&netlink_nh);
#endif // NETLINK_ISR_DISPATCH
}

SYSINIT(netlink, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, netlink_init, 0);

/*
 * It really doesn't make any sense at all for this code to share much
 * with raw_usrreq.c, since its functionality is so restricted.	 XXX
 */
static void
netlink_abort(struct socket *so)
{
	raw_usrreqs.pru_abort(so);
}

static void
netlink_close(struct socket *so)
{
	raw_usrreqs.pru_close(so);
}

/* pru_accept is EOPNOTSUPP */

static int
netlink_attach(struct socket *so, int proto, struct thread *td)
{
	struct rawcb *rp;
	int s, error;

	KASSERT(so->so_pcb == NULL, ("netlink_attach: so_pcb != NULL"));

	/* XXX */
	rp = (rawcb *)malloc(sizeof *rp);
	if (rp == NULL)
		return ENOBUFS;
	bzero(rp, sizeof *rp);

	/*
	 * The splnet() is necessary to block protocols from sending
	 * error notifications (like RTM_REDIRECT or RTM_LOSING) while
	 * this PCB is extant but incompletely initialized.
	 * Probably we should try to do more of this work beforehand and
	 * eliminate the spl.
	 */
	s = splnet();
	so->so_pcb = (caddr_t)rp;
	so->set_mutex(&netlink_mtx);
	so->so_fibnum = 0;
	error = raw_attach(so, proto);
	rp = sotorawcb(so);
	if (error) {
		splx(s);
		so->so_pcb = NULL;
		free(rp);
		return error;
	}
	NETLINK_LOCK();
	soisconnected(so);
	NETLINK_UNLOCK();
	so->so_options |= SO_USELOOPBACK;
	splx(s);
	return 0;
}

static int
netlink_bind(struct socket *so, struct bsd_sockaddr *nam, struct thread *td)
{
	return (raw_usrreqs.pru_bind(so, nam, td)); /* xxx just EINVAL */
}

static int
netlink_connect(struct socket *so, struct bsd_sockaddr *nam, struct thread *td)
{
	return (raw_usrreqs.pru_connect(so, nam, td)); /* XXX just EINVAL */
}

/* pru_connect2 is EOPNOTSUPP */
/* pru_control is EOPNOTSUPP */

static void
netlink_detach(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);

	KASSERT(rp != NULL, ("netlink_detach: rp == NULL"));

	raw_usrreqs.pru_detach(so);
}

static int
netlink_disconnect(struct socket *so)
{
	return (raw_usrreqs.pru_disconnect(so));
}

/* pru_listen is EOPNOTSUPP */

static int
netlink_peeraddr(struct socket *so, struct bsd_sockaddr **nam)
{
	return (raw_usrreqs.pru_peeraddr(so, nam));
}

/* pru_rcvd is EOPNOTSUPP */
/* pru_rcvoob is EOPNOTSUPP */

static int
netlink_send(struct socket *so, int flags, struct mbuf *m, struct bsd_sockaddr *nam,
	 struct mbuf *control, struct thread *td)
{
	return (raw_usrreqs.pru_send(so, flags, m, nam, control, td));
}

/* pru_sense is null */

static int
netlink_shutdown(struct socket *so)
{
	return (raw_usrreqs.pru_shutdown(so));
}

static int
netlink_sockaddr(struct socket *so, struct bsd_sockaddr **nam)
{
	return (raw_usrreqs.pru_sockaddr(so, nam));
}

static struct pr_usrreqs netlink_usrreqs = initialize_with([] (pr_usrreqs& x) {
	x.pru_abort =		netlink_abort;
	x.pru_attach =		netlink_attach;
	x.pru_bind =		netlink_bind;
	x.pru_connect =		netlink_connect;
	x.pru_detach =		netlink_detach;
	x.pru_disconnect =	netlink_disconnect;
	x.pru_peeraddr =	netlink_peeraddr;
	x.pru_send =		netlink_send;
	x.pru_shutdown =	netlink_shutdown;
	x.pru_sockaddr =	netlink_sockaddr;
	x.pru_close =		netlink_close;
});

static int
netlink_senderr(struct socket *so, struct nlmsghdr *nlm, int error)
{
	struct mbuf *m;
	struct nlmsghdr *hdr;
	struct nlmsgerr *err;

	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (!m) {
		return ENOBUFS;
	}

	if ((hdr = (struct nlmsghdr *)nlmsg_put(m,
											nlm ? nlm->nlmsg_pid : 0,
											nlm ? nlm->nlmsg_seq : 0,
											NLMSG_ERROR, sizeof(*err),
											nlm ? nlm->nlmsg_flags : 0)) == NULL) {
		m_free(m);
		return ENOBUFS;
	}
	err = (struct nlmsgerr *) nlmsg_data(hdr);
	err->error = error;
	if (nlm) {
		err->msg = *nlm;
	} else {
		memset(&err->msg, 0, sizeof(err->msg));
		nlm = &err->msg;
	}

	SOCK_LOCK(so);
	sbappendaddr_locked(so, &so->so_rcv, &netlink_src, m, NULL);
	sorwakeup_locked(so);
	return 0;
}

static int
netlink_process_getlink_msg(struct socket *so, struct nlmsghdr *nlm)
{
	struct ifnet *ifp = NULL;
	struct bsd_ifaddr *ifa;
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	struct mbuf *m = NULL;
	int error = 0;

	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (!m) {
		return ENOBUFS;
	}

	IFNET_RLOCK();
	TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		IF_ADDR_RLOCK(ifp);

		nlh = nlmsg_begin(m, nlm->nlmsg_pid, nlm->nlmsg_seq, LINUX_RTM_NEWLINK, sizeof(*ifm), nlm->nlmsg_flags);
		if (!nlh) {
			error = ENOBUFS;
			goto done;
		}

		ifm = (struct ifinfomsg *) nlmsg_data(nlh);
		ifm->ifi_family = AF_UNSPEC;
		ifm->__ifi_pad = 0;
		ifm->ifi_type = ifp->if_data.ifi_type;
		ifm->ifi_index = ifp->if_index;
		ifm->ifi_flags = ifp->if_flags | ifp->if_drv_flags;
		ifm->ifi_change = 0;
		if (nla_put_string(m, IFLA_IFNAME, ifp->if_xname) ||
			nla_put_type<uint32_t>(m, IFLA_LINK, ifp->if_index)) {
			error = ENOBUFS;
			goto done;
		}
		/* Add hw address info */
		for (ifa = ifp->if_addr; ifa != NULL; ifa = TAILQ_NEXT(ifa, ifa_link)) {
			if (ifa->ifa_addr->sa_family == AF_LINK)
				break;
		}
		if (ifa) {
			if (nla_put_sockaddr(m, IFLA_ADDRESS, ifa->ifa_addr) ||
				nla_put_sockaddr(m, IFLA_BROADCAST, ifa->ifa_broadaddr)){
				error = ENOBUFS;
				goto done;
			}
		}

		IF_ADDR_RUNLOCK(ifp);
		nlmsg_end(m, nlh);
	}
	nlh = nlmsg_put(m, nlm->nlmsg_pid, nlm->nlmsg_seq, NLMSG_DONE, 0, nlm->nlmsg_flags);

done:
	if (ifp != NULL)
		IF_ADDR_RUNLOCK(ifp);
	IFNET_RUNLOCK();
	if (m) {
		if (!error) {
			SOCK_LOCK(so);
			sbappendaddr_locked(so, &so->so_rcv, &netlink_src, m, NULL);
			sorwakeup_locked(so);
		} else {
			m_free(m);
		}
	}
	return (error);
}

static int
netlink_process_getaddr_msg(struct socket *so, struct nlmsghdr *nlm)
{
	struct ifnet *ifp = NULL;
	struct bsd_ifaddr *ifa;
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifm;
	struct mbuf *m = NULL;
	int error = 0;

	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (!m) {
		return ENOBUFS;
	}

	IFNET_RLOCK();
	TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		IF_ADDR_RLOCK(ifp);
		ifa = ifp->if_addr;
		for (ifa = ifp->if_addr; ifa != NULL; ifa = TAILQ_NEXT(ifa, ifa_link)) {
			int af = ifa->ifa_addr->sa_family;

			switch (af) {
#ifdef INET
			case AF_INET:
				af = LINUX_AF_INET;
				break;
#endif
#ifdef INET6
			case AF_INET6:
				af = LINUX_AF_INET6;
				break;
#endif
			default:
				af = -1;
			}
			if (af < 0)
				continue;

			if (!ifa->ifa_addr)
				continue;

			nlh = nlmsg_begin(m, nlm->nlmsg_pid, nlm->nlmsg_seq, LINUX_RTM_GETADDR, sizeof(*ifm), nlm->nlmsg_flags);
			if (!nlh) {
				error = ENOBUFS;
				goto done;
			}
			ifm = (struct ifaddrmsg *) nlmsg_data(nlh);
			ifm->ifa_index = ifp->if_index;
			ifm->ifa_family = af;
			ifm->ifa_prefixlen = get_sockaddr_mask_prefix_len(ifa->ifa_netmask);
			ifm->ifa_flags = ifp->if_flags | ifp->if_drv_flags;
			ifm->ifa_scope = 0; // FIXME:
			if (nla_put_string(m, IFA_LABEL, ifp->if_xname) ||
				nla_put_sockaddr(m, IFA_ADDRESS, ifa->ifa_addr) ||
				nla_put_sockaddr(m, IFA_BROADCAST, ifa->ifa_broadaddr)){
					error = ENOBUFS;
					goto done;
			}
			nlmsg_end(m, nlh);
		}

		IF_ADDR_RUNLOCK(ifp);
	}
	nlh = nlmsg_put(m, nlm->nlmsg_pid, nlm->nlmsg_seq, NLMSG_DONE, 0, nlm->nlmsg_flags);
done:
	if (ifp != NULL)
		IF_ADDR_RUNLOCK(ifp);
	IFNET_RUNLOCK();
	if (m) {
		if (!error) {
			SOCK_LOCK(so);
			sbappendaddr_locked(so, &so->so_rcv, &netlink_src, m, NULL);
			sorwakeup_locked(so);
		} else {
			m_free(m);
		}
	}
	return (error);
}

static int
netlink_process_msg(struct mbuf *m, struct socket *so)
{
	struct nlmsghdr *nlm = NULL;
	int len, error = 0;

#define senderr(e) { error = e; goto flush;}
	if (m == NULL)
		return (EINVAL);
	if (((m->m_hdr.mh_len < sizeof(long)) &&
		 (m = m_pullup(m, sizeof(long))) == NULL))
		senderr(ENOBUFS);
	if ((m->m_hdr.mh_flags & M_PKTHDR) == 0)
		panic("netlink_output");
	len = m->M_dat.MH.MH_pkthdr.len;
	if (len < sizeof(*nlm) ||
		len != mtod(m, struct nlmsghdr *)->nlmsg_len) {
		senderr(EINVAL);
	}
	nlm = mtod(m, struct nlmsghdr *);
	m_pullup(m, len);

	switch(nlm->nlmsg_type) {
		case LINUX_RTM_GETLINK:
			error = netlink_process_getlink_msg(so, nlm);
			break;
		case LINUX_RTM_GETADDR:
			error = netlink_process_getaddr_msg(so, nlm);
			break;
		default:
			senderr(EOPNOTSUPP);
	}

flush:
	if (error) {
		netlink_senderr(so, nlm, error);
	}
	if (m) {
		m_free(m);
	}

	return (error);
}

static int
netlink_output(struct mbuf *m, struct socket *so)
{
	return netlink_process_msg(m, so);
}

/*
 * Definitions of protocols supported in the NETLINK domain.
 */

extern struct domain netlinkdomain;		/* or at least forward */

static struct protosw netlinksw[] = {
	initialize_with([] (protosw& x) {
	x.pr_type =			SOCK_RAW;
	x.pr_domain =		&netlinkdomain;
	x.pr_flags =		PR_ATOMIC|PR_ADDR;
	x.pr_output =		netlink_output;
	x.pr_ctlinput =		raw_ctlinput;
	x.pr_init =			raw_init;
	x.pr_usrreqs =		&netlink_usrreqs;
	}),
};

struct domain netlinkdomain = initialize_with([] (domain& x) {
	x.dom_family =			PF_NETLINK;
	x.dom_name =			"netlink";
	x.dom_protosw =			netlinksw;
	x.dom_protoswNPROTOSW =	&netlinksw[sizeof(netlinksw)/sizeof(netlinksw[0])];
});

VNET_DOMAIN_SET(netlink);
