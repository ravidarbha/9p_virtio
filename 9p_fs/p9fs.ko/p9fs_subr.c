/*-
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

struct p9_fid *
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

    rc = p9_client_create(mp);

    if (rc) {
        p9_debug(P9_DEBUG_ERROR, "problem initializing 9p client\n");
        goto fail;
    }
    p9s->flags = V9FS_ACCESS_USER;
    if (p9_is_proto_dotl(p9s->clnt)) {
        p9s->flags = V9FS_ACCESS_CLIENT;
        p9s->flags |= V9FS_PROTO_2000L;

    } else if (p9_is_proto_dotu(p9s->clnt)) {
        p9s->flags |= V9FS_PROTO_2000U;
    }

    p9s->maxdata = p9s->clnt->msize - P9_IOHDRSZ;

    fid = p9_client_attach(p9s->clnt, NULL, p9s->uname, INVALID_UID,
	p9s->aname);

    if (fid == NULL) {

        rc = -ENOMEM;
        p9_debug(P9_DEBUG_ERROR, "cannot attach\n");

        goto fail;

    }
    if ((p9s->flags & V9FS_ACCESS_MASK) == V9FS_ACCESS_SINGLE)
        fid->uid = p9s->uid;
    else
        fid->uid = INVALID_UID;

    return fid;

fail:

   if (p9s->clnt) /* go aheaad and destroy it */
	p9_client_destroy(p9s->clnt);

   free(p9s->uname);

   free(p9s->aname);

   return NULL;
}

void
p9fs_close_session(struct mount *mp)
{
	struct p9fs_session *p9s;
	struct p9mount *p9mp;

  	p9mp = mp->mnt_data;
    	p9s = &p9mp->p9_session;

	/* Would like to explicitly clunk ROOTFID here, but soupcall gone. */

	/* do the reverse order of the init sessin  */
	/* Detach the root fid.*/
	p9_client_detach(p9s->p9s_rootnp.p9_fid);
	/* clean up the clnt structure. */
	p9_client_destroy(p9s->clnt);
	/* Clean up the sesssion pointer.*/
	free(p9s, sizeof(*p9s));
	/* CLeanup the mount structure. */
	free(p9mp, sizeof(*p9mp));
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
