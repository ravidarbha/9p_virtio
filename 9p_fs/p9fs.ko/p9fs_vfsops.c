/*-
*
 * Plan9 filesystem (9P2000.u) implementation.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/sockopt.h>
#include <sys/socketvar.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/fnv_hash.h>

#include "p9fs_proto.h"
#include "p9fs_subr.h"

static const char *p9_opts[] = {
	"addr",
	"debug",
	"hostname",
	"path",
	"proto",
};

struct p9fsmount {
	int p9_debuglevel;
	struct p9fs_session p9_session;
	struct mount *p9_mountp;
	char p9_hostname[256];
};
#define	VFSTOP9(mp) ((mp)->mnt_data)

static MALLOC_DEFINE(M_P9MNT, "p9fsmount", "Mount structures for p9fs");

static int
p9fs_mount_parse_opts(struct mount *mp)
{
	struct p9fsmount *p9mp = VFSTOP9(mp);
	struct p9fs_session *p9s = &p9mp->p9_session;
	char *opt;
	int error = EINVAL;
	int fromnamelen, ret;

	if (vfs_getopt(mp->mnt_optnew, "debug", (void **)&opt, NULL) == 0) {
		if (opt == NULL) {
			vfs_mount_error(mp, "must specify value for debug");
			goto out;
		}
		ret = sscanf(opt, "%d", &p9mp->p9_debuglevel);
		if (ret != 1 || p9mp->p9_debuglevel < 0) {
			vfs_mount_error(mp, "illegal debug value: %s", opt);
			goto out;
		}
	}

	/* Flags beyond here are not supported for updates. */
	if (mp->mnt_flag & MNT_UPDATE)
		return (0);

	error = 0;

out:
	return (error);
}

static int
p9fs_unmount(struct mount *mp, int mntflags)
{
	struct p9fsmount *p9mp = VFSTOP9(mp);
	int error, flags, i;

	error = 0;
	flags = 0;
	if (p9mp == NULL)
		return (0);

	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	for (i = 0; i < 10; i++) {
		error = vflush(mp, 0, flags, curthread);
		if (error == 0 || (mntflags & MNT_FORCE) == 0)
			break;
		/* Sleep until interrupted or 1 tick expires. */
		error = tsleep(&error, PSOCK, "p9unmnt", 1);
		if (error == EINTR)
			break;
		error = EBUSY;
	}
	if (error != 0)
		goto out;

	p9fs_close_session(mp);
	free(p9mp, M_P9MNT);
	mp->mnt_data = NULL;

out:
	return (error);
}

/* For the root vnode's vnops. */
extern struct vop_vector p9fs_vnops;

static const char *p9_opts[] = { "acls", "async", "noatime", "noclusterr",
    "noclusterw", "noexec", "export", "force", "from", "groupquota",
    "multilabel", "nfsv4acls", "fsckpid", "snapshot", "nosuid", "suiddir",
    "nosymfollow", "sync", "union", "userquota", NULL };

#if 0 
/* A Plan9 node. */
struct p9fs_node {
        uint32_t p9n_fid;
        uint32_t p9n_ofid;
        uint32_t p9n_opens;
        struct p9fs_qid p9n_qid;
        struct vnode *p9n_vnode;
        struct p9fs_session *p9n_session;
};

#define MAXUNAMELEN     32
struct p9fs_session {

     unsigned char flags;
     unsigned char nodev;
     unsigned short debug;
     unsigned int afid;
     unsigned int cache;
     // These look important .
     struct mount *p9s_mount;
     struct p9fs_node p9s_rootnp;
     char *uname;        /* user name to mount as */
     char *aname;        /* name of remote hierarchy being mounted */
     unsigned int maxdata;   /* max data for client interface */
     kuid_t dfltuid;     /* default uid/muid for legacy support */
     kgid_t dfltgid;     /* default gid for legacy support */
     kuid_t uid;     /* if ACCESS_SINGLE, the uid that has access */
     struct p9_client *clnt; /* 9p client */
     struct list_head slist; /* list of sessions registered with v9fs */
     mtx_lock p9s_lock;

#endif 

static int
p9fs_mount(struct mount *mp)
{
	struct p9fsmount *p9mp;
	struct p9fs_session *p9s;
	struct p9_fid *fid; // This typically has everything needed.
	struct p9_wstat st;
	int error;

	/* No support for UPDATe for now */
	if (mp->mnt_flag & MNT_UPDATE)
		return EOPNOTSUPP;

	if (vfs_filteropt(mp->mnt_optnew, p9_opts))
		goto out;

	fspec = vfs_getopts(mp->mnt_optnew, "from", &error);
        if (error)
                return (error);

	td = curthread;

	/* Allocate and initialize the private mount structure. */
	p9mp = malloc(sizeof (struct p9fsmount), M_P9MNT, M_WAITOK | M_ZERO);
	mp->mnt_data = p9mp;
	p9mp->p9_mountp = mp;
    	// This is creating the client instance along with the session pointer.
	fid = p9fs_init_session(mp);
	p9s = &p9mp->p9_session;
	p9s->p9s_mount = mp;

    	/*
     	** Not an update, or updating the name: look up the name
     	** and verify that it refers to a sensible disk device.
     	**/
    	NDINIT(&ndp, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, fspec, td);
    	if ((error = namei(&ndp)) != 0)
        	return (error);
    	NDFREE(&ndp, NDF_ONLY_PNBUF);
    	devvp = ndp.ni_vp;
    	if (!vn_isdisk(devvp, &error)) {
        	vput(devvp);
        	return (error);
    	}

	/* Determine if type of source file is supported (VREG or VCHR) */
    	/*
     	** If mount by non-root, then verify that user has necessary
     	** permissions on the device.
     	**/

	if (devvp->v_type == VREG) {
		DROP_GIANT();
		error = vn_open_vnode(devvp, flags, td->td_ucred, td, NULL);
		PICKUP_GIANT();
	} else if (vn_isdisk(devvp, &error) == 0) {
		error = VOP_ACCESS(devvp, VREAD, td->td_ucred, td);
		if (error != 0)
			error = priv_check(td, PRIV_VFS_MOUNT_PERM);
	}
	if (error != 0) {
		vput(devvp);
		return error;
	}

	
	// Done with the Pre mount phase. Do the actual mount.
	// fid is the fid for the root.
	// Init the structures of rootnp.
	p9s->p9s_rootnp.p9_vnode = devvp;
	p9s->p9s_rootnp.p9n_fid = fid;

	// Send a statfs on the fid to retreive the qid.
	p9_client_wstat(fid, &st);	
	p9s->p9s_rootnp.p9n_qid = st.qid;
	p9s->p9s_rootnp.p9n_session = p9s; /*session ptr structure .*/
	
	return 0;
out:
	if (error != 0)
		(void) p9fs_unmount(mp, MNT_FORCE);
	return (error);
}

static int
p9fs_root(struct mount *mp, int lkflags, struct vnode **vpp)
{
	struct p9fsmount *p9mp = VFSTOP9(mp);
	struct p9fs_node *np = &p9mp->p9_session.p9s_rootnp;

	*vpp = np->p9n_vnode;
	vref(*vpp);
	vn_lock(*vpp, lkflags);

	return (0);
}

static int
p9fs_statfs(struct mount *mp, struct statfs *sbp)
{

	/*
	 * XXX Uhhh..???
	 *     There does not be a 9P2000 call for filesystem level info!
	 *     Have to implement 9P2000.L statfs for that...
	 */
	sbp->f_version = STATFS_VERSION;
	sbp->f_bsize = DEV_BSIZE;
	sbp->f_iosize = MAXPHYS;
	sbp->f_blocks = 2; /* from devfs: 1K to keep df happy */
	return (0);
}

static int
p9fs_fhtovp(struct mount *mp, struct fid *fhp, int flags, struct vnode **vpp)
{
	return (EINVAL);
}

static int
p9fs_sync(struct mount *mp, int waitfor)
{
	return (0);
}

struct vfsops p9fs_vfsops = {
	.vfs_mount =	p9fs_mount,
	.vfs_unmount =	p9fs_unmount,
	.vfs_root =	p9fs_root,
	.vfs_statfs =	p9fs_statfs,
	.vfs_fhtovp =	p9fs_fhtovp,
	.vfs_sync =	p9fs_sync,
};
VFS_SET(p9fs_vfsops, p9fs, VFCF_JAIL);
