/*
 * tcpcp.h - TCP connection passing high-level API
 *
 * Written 2002 by Werner Almesberger
 * Distributed under the LGPL.
 *
 * Copyright (C) 2005-2006 NTT Corporation
 */


#ifndef TCPCP_H
#define TCPCP_H

#include <stdint.h>
#include <netinet/in.h>

#define TCPCP_RET_OK	0
#define TCPCP_RET_NG	-1

#define TCPCP_EXEC_ONE	0
#define TCPCP_EXEC_ALL	1

enum option {
	TCPCP_MAKE_SI		= 16,
	TCPCP_MAKE_SI_ALL,
	TCPCP_GET_SI,
	TCPCP_STOP,
	TCPCP_STOP_ALL,
	TCPCP_CLOSE,
	TCPCP_CLOSE_ALL,
	TCPCP_SET_SI,
	TCPCP_SET_SI_ALL,
	TCPCP_START,
	TCPCP_START_ALL,
	TCPCP_GET_RES_SIZE,
	TCPCP_GET_RES,
};

/* ----- FD Result (FDR) Information (only "ALL") -------------------------- */

struct fdr {
	int fd;
	int result;
};

struct result_list {
	unsigned int fd_all;	/* total of fd that succeeds in processing */
	unsigned int fd_ng;	/* Number of fd that fails in processing */
	struct fdr fdrs[0];	/* processing result pointer */
};

struct result {
	unsigned int fd_all;    /* total of fd that succeeds in processing */
	unsigned int fd_ng;     /* Number of fd that fails in processing */
	unsigned int buf_size;
	unsigned int fdrs_size;
};

/* ----- TCP Socket Informations (TCP-SIs) --------------------------------- */

/**
 * TCP Socket Information (TCP-SI) option: packet information
 **/
struct tcpcp_si_skb {
	uint8_t type;		/* TCP-SI option type */
				/*  1: TCPCP_SIE_BUF_SND */
				/*  2: TCPCP_SIE_BUF_RCV */
	uint8_t __pad1;
	uint16_t length;	/* segment data length */
	uint8_t flags;		/* TCP header flags */
	uint8_t sacked;		/* state flags for SACK/FACK */
	uint8_t __pad2[2];
	uint16_t tso_segs;
	uint16_t tso_size;
	uint32_t seq;		/* sequence number of first byte */
	uint8_t data[0];        /* data, padded to multiple of 4 bytes */
};

enum {
	TCPCP_SIE_BUF_SND = 1,	/* send buffer (only TCP segment, no IP) */
	TCPCP_SIE_BUF_RCV = 2,	/* receive buffer (only TCP segment, no IP) */
};

/**
 * TCP-SI element: globally unique TCP connection ID
 **/
struct tcpcp_sie_id4 {
	uint32_t ip_src;	/* source IPv4 address */
	uint32_t ip_dst;	/* destination IPv4 address */
};

struct tcpcp_sie_id6 {
	struct in6_addr ip_src;	/* source IPv6 address */
	struct in6_addr ip_dst;	/* destination IPv6 address */
	uint32_t scope_id;	/* scope id */
};

struct tcpcp_sie_id {
	uint8_t ip_version;	/* IP version */
				/*  4: IPv4 */
				/*  6: IPv6 */
	uint8_t __pad[3];
	union {
		struct tcpcp_sie_id4 v4;	/* IPv4 */
		struct tcpcp_sie_id6 v6;	/* IPv6 */
	} ip;
	uint16_t tcp_sport;	/* TCP source port */
	uint16_t tcp_dport; 	/* TCP destinatipon port */
};

/**
 * TCP-SI element: fixed general data
 **/
struct tcpcp_sie_fixgen {
	uint8_t tcp_flags;	/* TCP flags; from linux/tcp.h */
				/*  1: TCPI_OPT_TIMESTAMPS */
				/*  2: TCPI_OPT_SACK */
				/*  4: TCPI_OPT_WSCALE */
				/*  8: TCPI_OPT_ECN */
	uint8_t snd_wscale;	/* send window scale (0 if unused) */
	uint8_t rcv_wscale;	/* receive window scale (0 if unused) */
	uint8_t __pad;
	uint16_t snd_mss;	/* MSS sent */
	uint16_t rcv_mss;	/* MSS received */
};

/**
 * TCP-SI element: variable general data
 **/
struct tcpcp_sie_vargen {
	uint8_t state;		/* connection state; from linux/tcp.h */
				/*  1: TCP_ESTABLISHED */
				/*  2: TCP_SYN_SENT */
				/*  3: TCP_SYN_RECV */
				/*  4: TCP_FIN_WAIT1 */
				/*  5: TCP_FIN_WAIT2 */
				/*  6: TCP_TIME_WAIT */
				/*  7: TCP_CLOSE */
				/*  8: TCP_CLOSE_WAIT */
				/*  9: TCP_LAST_ACK */
				/* 10: TCP_LISTEN */
				/* 11: TCP_CLOSING */
				/* Note: TCP-SI may not ever use some of */
				/*       these values. */
	uint8_t __pad[3];
	uint32_t snd_nxt;	/* sequence number of next new byte to send */
	uint32_t rcv_nxt;	/* sequence number of next new byte expected */
				/* to receive */
	uint32_t snd_wnd;	/* window received from peer */
	uint32_t rcv_wnd;	/* window advertized to peer */
	uint32_t ts_recent;	/* cached timestamp from peer (0 if none) */
	uint32_t ts_gen;	/* current locally generated timestamp */
				/* (0 if not using timestamps) */
};

/**
 * TCP-SI element: socket options (socket)
 **/
struct tcpcp_sie_sk_sockopt {
	uint8_t flags;		/* flags */
				/*  1: TCPCP_SIE_SOCK_REUSEADDR */
				/*  2: TCPCP_SIE_SOCK_KEEPOPEN */
				/*  4: TCPCP_SIE_SOCK_LINGER */
	uint8_t userlocks;	/* %SO_SNDBUF and %SO_RCVBUF settings */
	uint8_t __pad[2];
	uint32_t priority;	/* %SO_PRIORITY setting */
	uint32_t sndbuf;	/* size of send buffer in bytes */
	uint32_t rcvbuf;	/* size of receive buffer in bytes */
	uint32_t l_linger;	/* How long to linger for */
};

enum {
	TCPCP_SIE_SOCK_REUSEADDR	= 1,
	TCPCP_SIE_SOCK_KEEPOPEN		= 2,
	TCPCP_SIE_SOCK_LINGER		= 4,
};

/**
 * TCP-SI element: socket options (IPv4)
 **/
struct tcpcp_sie_ipv4_sockopt {
	uint8_t flags;		/* flags */
				/*  1: TCPCP_SIE_IP_DEFAULT_TTL */
	uint8_t uc_ttl;		/* unicast TTL */
	uint8_t pmtudisc;	/* IP_MTU_DISCOVER state */
	uint8_t tos;		/* TOS */
	uint8_t opt_len;
	uint8_t __pad[3];
	uint8_t opt_data[40];
};

enum {
	TCPCP_SIE_IP_DEFAULT_TTL = 1,
};

/**
 * TCP-SI element: socket options (IPv6)
 **/
struct tcpcp_sie_ipv6_sockopt {
	uint8_t flags;		/* flags */
				/*  1: TCPCP_SIE_IPV6_DEFAULT_HOPLIMIT */
	uint8_t hop_limit;	/* unicast hop limit */
	uint8_t pmtudisc;	/* IPV6_MTU_DISCOVER state */
	uint8_t __pad;
};

enum {
	TCPCP_SIE_IPV6_DEFAULT_HOPLIMIT = 1,
};

/**
 * TCP-SI element: socket options (TCP)
 **/
struct tcpcp_sie_tcp_sockopt {
	uint8_t nonagle;	/* Disable Nagle aliorithm ? */
	uint8_t keepcnt;	/* num of allowed keep alive probes */
	uint8_t __pad[2];
	uint16_t keepidle;	/* time before keep alive takes place */
	uint16_t keepintvl;	/* time interval between keep alive */
				/* probes */
};

/**
 * TCP-SI element: socket options
 **/
struct tcpcp_sie_sockopt {
	struct tcpcp_sie_sk_sockopt sk;			/* socket */
	union {
		struct tcpcp_sie_ipv4_sockopt v4;	/* IPv4 */
		struct tcpcp_sie_ipv6_sockopt v6;	/* IPv6 */
	} ip;
	struct tcpcp_sie_tcp_sockopt tcp;		/* TCP */
};

/**
 * TCP Socket Information (TCP-SI) header
 **/
struct tcpcp_si_hdr {
	uint32_t si_length;		/* total length of TCP-SI / 4byte */
	uint32_t fd;
	struct tcpcp_sie_id id;		/* globally unique TCP connection ID */
	struct tcpcp_sie_fixgen fixgen;	/* fixed general data */
	struct tcpcp_sie_vargen vargen;	/* variable general data */
	struct tcpcp_sie_sockopt sockopt;	/* socket option */
	struct tcpcp_si_skb si_skb[0];
};

/**
 * TCP Socket Informations (TCP-SIs) total header
 **/
struct tcpcp_total_si_hdr {
	uint32_t total_si_length;	/* total length of TCP-SIs / 4byte */
	uint8_t major;			/* incompatible structure revision */
					/*  0: current version */
	uint8_t minor;			/* compatible structure extension */
					/*  0: current version */
	uint16_t si_cnt;
	struct tcpcp_si_hdr si_hdr[0];
};

/* ------------------------------------------------------------------------- */

int tcpcp_get_si(int fd, int flag, void **bufptr, unsigned int *size,
		 struct result_list **reslst);
int tcpcp_stop(int fd, int flag, struct result_list **reslst);
int tcpcp_close(int fd, struct result_list **reslst);
int tcpcp_set_si(int fd, int flag, void *bufptr, unsigned int size,
		 struct result_list **reslst);
int tcpcp_start(int fd, int flag, struct result_list **reslst);

#define plugin_dummy() __asm__ __volatile__("nop\n\t" \
	"nop\n\t" \
	"nop\n\t" \
	"nop\n\t" \
	"nop\n\t" \
	"nop\n\t" \
	"nop\n\t" \
	"nop\n\t" \
	"nop\n\t" \
	"nop\n\t" \
	"nop\n\t" \
	"nop\n\t" \
	"nop\n\t" \
	"nop\n\t") 


#endif /* TCPCP_H */
