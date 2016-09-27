/*-
 * Copyright (c) 2015 Will Andrews.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS        
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED   
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR       
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS        
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR           
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF             
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS         
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN          
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)          
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE       
 * POSSIBILITY OF SUCH DAMAGE.                                                      
 */

/*
 * Plan9 filesystem (9P2000.u) subroutines.  This file is intended primarily
 * for Plan9-specific details.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <sys/limits.h>
#include <sys/vnode.h>

#include "p9fs_proto.h"
#include "p9fs_subr.h"

static MALLOC_DEFINE(M_P9REQ, "p9fsreq", "Request structures for p9fs");

/*
 * Plan 9 message handling.  This is primarily intended as a means of
 * performing marshalling/unmarshalling.
 *
 */

void
p9fs_init_session(struct mount *mp)
{
    struct p9_fid *fid;
    int rc = -ENOMEM;
    struct p9fs_session *p9s;

    p9mp = mp->mnt_data;
    p9s = &p9mp->p9_session;
    p9s->uid = INVALID_UID;
    p9s->dfltuid = V9FS_DEFUID;
    p9s->dfltgid = V9FS_DEFGID;
    // Create the clnt, ada func pointers.
    rc = p9_client_create(mp);

    if (rc) {
        p9_debug(P9_DEBUG_ERROR, "problem initializing 9p client\n");
        goto err_bdi;
    }
    p9s->flags = V9FS_ACCESS_USER;
    if (p9_is_proto_dotl(p9s->clnt)) {
        p9s->flags = V9FS_ACCESS_CLIENT;
        p9s->flags |= V9FS_PROTO_2000L;

    } else if (p9_is_proto_dotu(p9s->clnt)) {
        p9s->flags |= V9FS_PROTO_2000U;
    }

    if (rc < 0)
        goto err_clnt;

    p9s->maxdata = p9s->clnt->msize - P9_IOHDRSZ;

    if (!v9fs_proto_dotl(p9s) &&
            ((p9s->flags & V9FS_ACCESS_MASK) == V9FS_ACCESS_CLIENT)) {

        /*
         *          * We support ACCESS_CLIENT only for dotl.
         *                   * Fall back to ACCESS_USER
         *                            */
        p9s->flags &= ~V9FS_ACCESS_MASK;
        p9s->flags |= V9FS_ACCESS_USER;
    }

    /*FIXME !! */
    /* for legacy mode, fall back to V9FS_ACCESS_ANY */
    if (!(v9fs_proto_dotu(p9s) || v9fs_proto_dotl(p9s)) &&
            ((p9s->flags&V9FS_ACCESS_MASK) == V9FS_ACCESS_USER)) {

        p9s->flags &= ~V9FS_ACCESS_MASK;
        p9s->flags |= V9FS_ACCESS_ANY;
        p9s->uid = INVALID_UID;
    }

    fid = p9_client_attach(p9s->clnt, NULL, p9s->uname, INVALID_UID,
	p9s->aname);

    if (IS_ERR(fid)) {

        rc = PTR_ERR(fid);

        p9_debug(P9_DEBUG_ERROR, "cannot attach\n");

        goto err_clnt;

    }
    if ((p9s->flags & V9FS_ACCESS_MASK) == V9FS_ACCESS_SINGLE)
        fid->uid = p9s->uid;
    else
        fid->uid = INVALID_UID;

#ifdef CONFIG_9P_FSCACHE

    /* register the session for caching */
    v9fs_cache_session_get_cookie(p9s);
#endif
    mtx_lock_spin(&v9fs_sessionlist_lock);
    list_add(&p9s->slist, &v9fs_sessionlist);
    mtx_unlock_spin(&v9fs_sessionlist_lock);

    return fid;

err_clnt:

   p9_client_destroy(p9s->clnt);
err_names:
   
   free(p9s->uname);

   free(p9s->aname);

   return ERR_PTR(rc);
}

void
p9fs_close_session(struct p9fs_session *p9s)
{
	mtx_lock(&p9s->p9s_lock);
	if (p9s->p9s_sock != NULL) {
		struct p9fs_recv *p9r = &p9s->p9s_recv;
		struct sockbuf *rcv = &p9s->p9s_sock->so_rcv;

		p9s->p9s_state = P9S_CLOSING;
		mtx_unlock(&p9s->p9s_lock);

		SOCKBUF_LOCK(rcv);
		soupcall_clear(p9s->p9s_sock, SO_RCV);
		while (p9r->p9r_soupcalls > 0)
			(void) msleep(&p9r->p9r_soupcalls, SOCKBUF_MTX(rcv),
			    0, "p9rcvup", 0);
		SOCKBUF_UNLOCK(rcv);
		(void) soclose(p9s->p9s_sock);

		/*
		 * XXX Can there really be any such threads?  If vflush()
		 *     has completed, there shouldn't be.  See if we can
		 *     remove this and related code later.
		 */
		mtx_lock(&p9s->p9s_lock);
		while (p9s->p9s_threads > 0)
			msleep(p9s, &p9s->p9s_lock, 0, "p9sclose", 0);
		p9s->p9s_state = P9S_CLOSED;
	}
	mtx_unlock(&p9s->p9s_lock);

	/* Would like to explicitly clunk ROOTFID here, but soupcall gone. */
	delete_unrhdr(p9s->p9s_fids);
	delete_unrhdr(p9s->p9s_tags);
}

/* FID & tag management.  Makes use of subr_unit, since it's the best fit. */
uint32_t
p9fs_getfid(struct p9fs_session *p9s)
{
	return (alloc_unr(p9s->p9s_fids));
}
void
p9fs_relfid(struct p9fs_session *p9s, uint32_t fid)
{
	free_unr(p9s->p9s_fids, fid);
}
uint16_t
p9fs_gettag(struct p9fs_session *p9s)
{
	return (alloc_unr(p9s->p9s_tags));
}
void
p9fs_reltag(struct p9fs_session *p9s, uint16_t tag)
{
	free_unr(p9s->p9s_tags, tag);
}
