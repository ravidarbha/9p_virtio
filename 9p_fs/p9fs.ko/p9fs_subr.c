/*-
 * Plan9 filesystem (9P2000.u) subroutines.  This file is intended primarily
 * for Plan9-specific details.
 * This file consists of all the Non VFS Subroutines.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/limits.h>
#include <sys/vnode.h>

#include "p9fs_proto.h"
#include "../../client.h"
#include "../../protocol.h"
#include "../../9p.h"

static MALLOC_DEFINE(M_P9REQ, "p9fsreq", "Request structures for p9fs");

/*
 * Plan 9 message handling.  This is primarily intended as a means of
 * performing marshalling/unmarshalling.
 */

int
p9fs_proto_dotl(struct p9fs_session *p9s)
{

    if (p9s->flags & V9FS_PROTO_2000L) {
	return 1;
    }
    else 
	return 0;
}

struct p9_fid *
p9fs_init_session(struct mount *mp)
{
    struct p9_fid *fid;
    struct p9fs_session *p9s;
    struct p9fs_mount *p9mp;
    int rc = -ENOMEM;

    p9mp = mp->mnt_data;
    p9s = &p9mp->p9_session;
    p9s->uid = 0;

    p9s->clnt = p9_client_create(mp);

    if (rc) {
        p9_debug(P9_DEBUG_ERROR, "problem initializing 9p client\n");
        goto fail;
    }
    p9s->flags = V9FS_ACCESS_USER;
    /* Find the client version and caceh the copy. We will use this copy 
     * throughout FS layer.*/
    if (p9_is_proto_dotl(p9s->clnt)) {
        p9s->flags = V9FS_ACCESS_CLIENT;
        p9s->flags |= V9FS_PROTO_2000L;

    } else if (p9_is_proto_dotu(p9s->clnt)) {
        p9s->flags |= V9FS_PROTO_2000U;
    }

    p9s->maxdata = p9s->clnt->msize;

    /* Attach with the backend host*/
    fid = p9_client_attach(p9s->clnt);

    if (fid == NULL) {

        rc = -ENOMEM;
        p9_debug(P9_DEBUG_ERROR, "cannot attach\n");

        goto fail;
    }

    fid->uid = p9s->uid;

    return fid;

fail:

   if (p9s->clnt) /* go aheaad and destroy it */
	p9_client_destroy(p9s->clnt);

   return NULL;
}

/* Call from unmount. Close the session. */
void
p9fs_close_session(struct mount *mp)
{
	struct p9fs_session *p9s;
	struct p9fs_mount *p9mp;

  	p9mp = VFSTOP9(mp);
    	p9s = &p9mp->p9_session;

	/* Do the reverse of the init session  */
	/* Detach the root fid.*/
	p9_client_detach(p9s->p9s_rootnp.p9n_fid);
	/* Clean up the clnt structure. */
	p9_client_destroy(p9s->clnt);
	/* CLeanup the mount structure. */
	free(p9mp, M_TEMP);
}

