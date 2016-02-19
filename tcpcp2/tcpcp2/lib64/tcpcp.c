/*
 * tcpcp.c - TCP connection passing high-level API
 *
 * Written 2002 by Werner Almesberger
 * Distributed under the LGPL.
 *
 * Copyright (C) 2005-2006 NTT Corporation
 */

#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>

#include "tcpcp.h"


/**
 * tcpcp_get_si - get TCP Socket Informations (TCP-SIs)
 *
 * [Args]
 *   (IN) fd        : FD
 *   (IN) flag      : "ONE" / "ALL"
 *   (OUT) **bufptr : socket informations buffer
 *   (OUT) *size    : size of socket informations buffer
 *   (OUT) **reslst : result information of processing
 *
 * [Return]
 *   TCPCP_RET_OK : OK.
 *   TCPCP_RET_NG : NG.
 **/
int tcpcp_get_si(int fd, int flag, void **bufptr,
		unsigned int *size, struct result_list **reslst)
{
	plugin_dummy();

	struct result res;
	unsigned int opt_len;
	int opt_kind;
	int ret;

	/* initialize. */
	memset(&res, 0, sizeof(struct result));
	opt_len = sizeof(struct result);
	*bufptr = NULL;
	*reslst = NULL;
	*size = 0;
			
	switch (flag) {
	case TCPCP_EXEC_ONE:
		opt_kind = TCPCP_MAKE_SI;
		break;

	case TCPCP_EXEC_ALL:
		opt_kind = TCPCP_MAKE_SI_ALL;
		break;

	default:
		errno = EINVAL;
		return TCPCP_RET_NG;
	}

	/* make SI. */
	ret = getsockopt(fd, SOL_TCP, opt_kind, (char*)&res, &opt_len);
	if (ret != 0)
		return TCPCP_RET_NG;

	/* allocate socket informations. */
	*bufptr = (char*)malloc(res.buf_size);
	if (*bufptr == NULL) {
		errno = ENOMEM;
		return TCPCP_RET_NG;
	}

	opt_len = res.buf_size;
	memset(*bufptr, 0, res.buf_size);

	/* get SIs. */
	ret = getsockopt(fd, SOL_TCP, TCPCP_GET_SI, *bufptr, &opt_len);
	if (ret != 0) {
		free(*bufptr);
		*bufptr = NULL;
		return TCPCP_RET_NG;
	}

	/* allocate result informations of processing. */
	*reslst = (struct result_list*)malloc(sizeof(struct result_list)
						+ res.fdrs_size);
	if (*reslst == NULL) {
		free(*bufptr);
		*bufptr = NULL;
		errno = ENOMEM;
		return TCPCP_RET_NG;
	}

	memset(*reslst, 0, sizeof(struct result_list) + res.fdrs_size);

	if (flag == TCPCP_EXEC_ONE) {
		(*reslst)->fd_all = res.fd_all;
		(*reslst)->fd_ng = res.fd_ng;
		(*reslst)->fdrs[0].fd = fd;
		(*reslst)->fdrs[0].result = 0;
		*size = res.buf_size;
	} else {
		opt_len = res.fdrs_size;

		/* get result informations of processing. */
		ret = getsockopt(fd, SOL_TCP, TCPCP_GET_RES, (*reslst)->fdrs,
					&opt_len);
		if (ret != 0) {
			free(*reslst);
			free(*bufptr);
			*reslst = NULL;
			*bufptr = NULL;
			return TCPCP_RET_NG;
		}

		(*reslst)->fd_all = res.fd_all;
		(*reslst)->fd_ng = res.fd_ng;
		*size = res.buf_size;
	}

	return TCPCP_RET_OK;
}

/**
 * tcpcp_stop - stop TCP sockets
 *
 * [Args]
 *   (IN) fd        : FD
 *   (IN) flag      : "ONE" / "ALL"
 *   (OUT) **reslst : result information of processing
 *
 * [Return]
 *   TCPCP_RET_OK : OK.
 *   TCPCP_RET_NG : NG.
 **/
int tcpcp_stop(int fd, int flag, struct result_list **reslst)
{
	plugin_dummy();

	struct result res;
	unsigned int opt_len;
	int opt_kind;
	int ret;

	/* initialize. */
	memset(&res, 0, sizeof(struct result));
	opt_len = sizeof(struct result);
	*reslst = NULL;
			
	switch (flag) {
	case TCPCP_EXEC_ONE:
		opt_kind = TCPCP_STOP;
		break;

	case TCPCP_EXEC_ALL:
		opt_kind = TCPCP_STOP_ALL;
		break;

	default:
		errno = EINVAL;
		return TCPCP_RET_NG;
	}

	/* stop sockets. */
	ret = getsockopt(fd, SOL_TCP, opt_kind, (char*)&res, &opt_len);
	if (ret != 0)
		return TCPCP_RET_NG;

	/* allocate result informations of processing. */
	*reslst = (struct result_list*)malloc(sizeof(struct result_list)
						+ res.fdrs_size);
	if (*reslst == NULL) {
		errno = ENOMEM;
		return TCPCP_RET_NG;
	}

	memset(*reslst, 0, sizeof(struct result_list) + res.fdrs_size);

	if (flag == TCPCP_EXEC_ONE) {
		(*reslst)->fd_all = res.fd_all;
		(*reslst)->fd_ng = res.fd_ng;
		(*reslst)->fdrs[0].fd = fd;
		(*reslst)->fdrs[0].result = 0;
	} else {
		opt_len = res.fdrs_size;

		/* get result informations of processing. */
		ret = getsockopt(fd, SOL_TCP, TCPCP_GET_RES, (*reslst)->fdrs,
					&opt_len);
		if (ret != 0) {
			free(*reslst);
			*reslst = NULL;
			return TCPCP_RET_NG;
		}

		(*reslst)->fd_all = res.fd_all;
		(*reslst)->fd_ng = res.fd_ng;
	}		

	return TCPCP_RET_OK;
}

/**
 * tcpcp_close - close TCP sockets
 *
 * [Args]
 *   (IN) fd        : FD
 *   (OUT) **reslst : result information of processing
 *
 * [Return]
 *   TCPCP_RET_OK : OK.
 *   TCPCP_RET_NG : NG.
 **/
int tcpcp_close(int fd, struct result_list **reslst)
{
	plugin_dummy();

	struct result res;
	unsigned int opt_len;
	int ret;

	/* initialize. */
	memset(&res, 0, sizeof(struct result));
	opt_len = sizeof(struct result);
	*reslst = NULL;

	/* close sockets. */
	ret = getsockopt(fd, SOL_TCP, TCPCP_CLOSE_ALL, (char*)&res, &opt_len);
	if (ret != 0)
		return TCPCP_RET_NG;

	/* allocate result informations of processing. */
	*reslst = (struct result_list*)malloc(sizeof(struct result_list)
						+ res.fdrs_size);
	if (*reslst == NULL) {
		errno = ENOMEM;
		return TCPCP_RET_NG;
	}

	memset(*reslst, 0, sizeof(struct result_list) + res.fdrs_size);
	opt_len = res.fdrs_size;

	/* get result informations of processing. */
	ret = getsockopt(fd, SOL_TCP, TCPCP_GET_RES, (*reslst)->fdrs, &opt_len);
	if (ret != 0) {
		free(*reslst);
		*reslst = NULL;
		return TCPCP_RET_NG;
	}

	(*reslst)->fd_all = res.fd_all;
	(*reslst)->fd_ng = res.fd_ng;

	return TCPCP_RET_OK;
}

/**
 * tcpcp_set_si - set TCP Socket Informations (TCP-SIs)
 *
 * [Args]
 *   (IN) fd        : FD
 *   (IN) flag      : "ONE" / "ALL"
 *   (IN) *bufptr   : socket informations buffer
 *   (IN) size      : size of socket informations buffer
 *   (OUT) **reslst : result information of processing
 *
 * [Return]
 *   TCPCP_RET_OK : OK.
 *   TCPCP_RET_NG : NG.
 **/
int tcpcp_set_si(int fd, int flag, void *bufptr,
		unsigned int size, struct result_list **reslst)
{
	plugin_dummy();

	struct result res;
	struct tcpcp_total_si_hdr *total_si_hdr;
	unsigned int opt_len;
	int opt_kind;
	int ret;

	/* initialize. */
	*reslst = NULL;

	switch (flag) {
	case TCPCP_EXEC_ONE:
		opt_kind = TCPCP_SET_SI;
		break;

	case TCPCP_EXEC_ALL:
		opt_kind = TCPCP_SET_SI_ALL;
		break;

	default:
		errno = EINVAL;
		return TCPCP_RET_NG;
	}

	/* set SIs. */
	ret = setsockopt(fd, SOL_TCP, opt_kind, (char*)bufptr, size);
	if (ret != 0)
		return TCPCP_RET_NG;

	if (flag == TCPCP_EXEC_ONE) {
		/* allocate result informations of processing. */
		*reslst = (struct result_list*)malloc(
			sizeof(struct result_list) + sizeof(struct fdr));
		if (*reslst == NULL) {
			errno = ENOMEM;
			return TCPCP_RET_NG;
		}

		total_si_hdr = (struct tcpcp_total_si_hdr*)bufptr;
		memset(*reslst, 0,
			sizeof(struct result_list) + sizeof(struct fdr));
		(*reslst)->fd_all = 1;
		(*reslst)->fdrs[0].fd = ntohl(total_si_hdr->si_hdr[0].fd);
		(*reslst)->fdrs[0].result = fd;
	} else {
		memset(&res, 0, sizeof(struct result));
		opt_len = sizeof(struct result);

		/* get size that result informations of processing. */
		ret = getsockopt(fd, SOL_TCP, TCPCP_GET_RES_SIZE, &res,
					&opt_len);
		if (ret != 0)
			return TCPCP_RET_NG;

		/* allocate result informations of processing. */
		*reslst = (struct result_list*)malloc(sizeof(struct result_list)
						+ res.fdrs_size);
		if (*reslst == NULL) {
			errno = ENOMEM;
			return TCPCP_RET_NG;
		}

		memset(*reslst, 0,
				sizeof(struct result_list) + res.fdrs_size);
		opt_len = res.fdrs_size;

		/* get result informations of processing. */
		ret = getsockopt(fd, SOL_TCP, TCPCP_GET_RES, (*reslst)->fdrs,
					&opt_len);
		if (ret != 0) {
			free(*reslst);
			*reslst = NULL;
			return TCPCP_RET_NG;
		}

		(*reslst)->fd_all = res.fd_all;
		(*reslst)->fd_ng = res.fd_ng;
	}

	return TCPCP_RET_OK;
}

/**
 * tcpcp_start - start TCP sockets
 *
 * [Args]
 *   (IN) fd        : FD
 *   (IN) flag      : "ONE" / "ALL"
 *   (OUT) **reslst : result information of processing
 *
 * [Return]
 *   TCPCP_RET_OK : OK.
 *   TCPCP_RET_NG : NG.
 **/
int tcpcp_start(int fd, int flag, struct result_list **reslst)
{
	plugin_dummy();

	struct result res;
	unsigned int opt_len;
	int opt_kind;
	int ret;

	/* initialize. */
	memset(&res, 0, sizeof(struct result));
	opt_len = sizeof(struct result);
	*reslst = NULL;
			
	switch (flag) {
	case TCPCP_EXEC_ONE:
		opt_kind = TCPCP_START;
		break;

	case TCPCP_EXEC_ALL:
		opt_kind = TCPCP_START_ALL;
		break;

	default:
		errno = EINVAL;
		return TCPCP_RET_NG;
	}

	/* start sockets. */
	ret = getsockopt(fd, SOL_TCP, opt_kind, (char*)&res, &opt_len);
	if (ret != 0)
		return TCPCP_RET_NG;

	/* allocate result informations of processing. */
	*reslst = (struct result_list*)malloc(sizeof(struct result_list)
						+ res.fdrs_size);
	if (*reslst == NULL) {
		errno = ENOMEM;
		return TCPCP_RET_NG;
	}

	memset(*reslst, 0, sizeof(struct result_list) + res.fdrs_size);

	if (flag == TCPCP_EXEC_ONE) {
		(*reslst)->fd_all = res.fd_all;
		(*reslst)->fd_ng = res.fd_ng;
		(*reslst)->fdrs[0].fd = fd;
		(*reslst)->fdrs[0].result = 0;
	} else {
		opt_len = res.fdrs_size;

		/* get result informations of processing. */
		ret = getsockopt(fd, SOL_TCP, TCPCP_GET_RES, (*reslst)->fdrs,
					&opt_len);
		if (ret != 0) {
			free(*reslst);
			*reslst = NULL;
			return TCPCP_RET_NG;
		}

		(*reslst)->fd_all = res.fd_all;
		(*reslst)->fd_ng = res.fd_ng;
	}

	return TCPCP_RET_OK;
}
