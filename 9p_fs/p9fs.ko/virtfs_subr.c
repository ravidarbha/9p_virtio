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

#include "virtfs_proto.h"
#include "../../client.h"
#include "../../protocol.h"
#include "../../9p.h"
#include "virtfs.h"

static MALLOC_DEFINE(M_P9REQ, "virtfsreq", "Request structures for virtfs");

/*
 * Plan 9 message handling.  This is primarily intended as a means of
 * performing marshalling/unmarshalling.
 */

int
virtfs_proto_dotl(struct virtfs_session *vses)
{
    return (vses->flags & VIRTFS_PROTO_2000L);
}

struct p9_fid *
virtfs_init_session(struct mount *mp)
{
    struct p9_fid *fid;
    struct virtfs_session *vses;
    struct virtfs_mount *virtmp;
    int rc = -ENOMEM;

    virtmp = mp->mnt_data;
    vses = &virtmp->virtfs_session;
    vses->uid = 0;

    vses->clnt = p9_client_create(mp);

    if (rc) {
        p9_debug(SUBR, "problem initializing 9p client\n");
        goto fail;
    }
    /* Find the client version and cache the copy. We will use this copy 
     * throughout FS layer.*/
    if (p9_is_proto_dotl(vses->clnt)) {
        vses->flags |= VIRTFS_PROTO_2000L;

    } else if (p9_is_proto_dotu(vses->clnt)) {
        vses->flags |= VIRTFS_PROTO_2000U;
    }

    /* whatever we get from client */
    vses->maxdata = vses->clnt->msize;

    /* Attach with the backend host*/
    fid = p9_client_attach(vses->clnt);

    if (fid == NULL) {

        rc = -ENOMEM;
        p9_debug(SUBR, "cannot attach\n");

        goto fail;
    }

    fid->uid = vses->uid;

    return fid;

fail:

   if (vses->clnt) /* go aheaad and destroy it */
	p9_client_destroy(vses->clnt);

   return NULL;
}

/* Call from unmount. Close the session. */
void
virtfs_close_session(struct mount *mp)
{
	struct virtfs_session *vses;
	struct virtfs_mount *virtfsmp;

  	virtfsmp = VFSTOP9(mp);
    	vses = &virtfsmp->virtfs_session;

	/* Do the reverse of the init session  */
	/* Detach the root fid.*/
	p9_client_detach(vses->rnp.vfid);
	/* Clean up the clnt structure. */
	p9_client_destroy(vses->clnt);
	/* CLeanup the mount structure. */
	free(virtfsmp, M_TEMP);
	p9_debug(SUBR, " Clean close session .\n");
}
