/*-
*
 * Plan9 filesystem (9P2000.u) implementation.
 * This file consists of all the VFS interactions.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/sockopt.h>
#include <sys/socketvar.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/fnv_hash.h>
#include <sys/fcntl.h>
#include <sys/priv.h>
#include <geom/geom.h>
#include <geom/geom_vfs.h>
#include <sys/namei.h>

#include "virtfs_proto.h"
#include "../../client.h"
#include "../../9p.h"
#include "virtfs.h"

static const char *p9_opts[] = {
	"debug",
	"from", /* This is the imp parameter for now . */
	"proto",
	"noatime",
	NULL
};

static MALLOC_DEFINE(M_P9MNT, "virtfs_mount", "Mount structures for virtfs");

static int
virtfs_unmount(struct mount *mp, int mntflags)
{
	struct virtfs_mount *vmp = VFSTOP9(mp);
	int error, flags, i;

	error = 0;
	flags = 0;
	if (vmp == NULL)
		return (0);

	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	for (i = 0; i < 10; i++) {
		/* Flush everything on this mount point.
		 * This anyways doesnt do anything now.*/
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

	virtfs_close_session(mp);
	free(vmp, M_P9MNT);
	mp->mnt_data = NULL;

out:
	return (error);
}

/* For the root vnode's vnops. */
extern struct vop_vector virtfs_vnops;

#if 0 
struct virtfs_mount {
	int p9_debuglevel;
	struct virtfs_session virtfs_session;
	struct mount *virtfs_mount;
	char p9_hostname[256];
}
/* A Plan9 node. */
struct virtfs_node {
        uint32_t p9n_fid;
        uint32_t p9n_ofid;
        uint32_t p9n_opens;
        struct virtfs_qid vqid;
        struct vnode *v_node;
        struct virtfs_session *p9n_session;
};

#define MAXUNAMELEN     32
struct virtfs_session {

     unsigned char flags;
     unsigned char nodev;
     unsigned short debug;
     unsigned int afid;
     unsigned int cache;
     // These look important .
     struct mount *p9s_mount;
     struct virtfs_node p9s_rootnp;
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

/* This is a vfs ops routiune so defining it here instead of vnops. This 
   needs some fixing(a wrapper moslty when we need create to work. Ideally
   it should call this, initialize the virtfs_node and create the fids and qids
   for interactions*/
int virtfs_vget(mp, ino, flags, vpp)
        struct mount *mp;
        int ino;
        int flags;
        struct vnode **vpp;
{
	struct virtfs_mount *vmp;
	struct virtfs_node *p9_node;
	struct virtfs_session *p9s;
	struct vnode *vp;
	//struct cdev *dev;
	struct thread *td;
	struct p9_stat_dotl *st = NULL;
	struct p9_fid *fid = NULL;
	int error;

	td = curthread;
	error = vfs_hash_get(mp, ino, flags, td, vpp, NULL, NULL);
	if (error || *vpp != NULL)
		return (error);

	/*
	 * We must promote to an exclusive lock for vnode creation.  This
	 * can happen if lookup is passed LOCKSHARED.
 	 */
	if ((flags & LK_TYPE_MASK) == LK_SHARED) {
		flags &= ~LK_TYPE_MASK;
		flags |= LK_EXCLUSIVE;
	}

	vmp = VFSTOP9(mp);

	/* Allocate a new vnode. */
	if ((error = getnewvnode("virtfs", mp, &virtfs_vnops, &vp)) != 0) {
		*vpp = NULLVP;
		return (error);
	}

	p9s = &vmp->virtfs_session;
	p9_node = malloc(sizeof(struct virtfs_node), M_TEMP,
	    M_WAITOK | M_ZERO);
	vp->v_data = p9_node;
	/* This should be initalized in the caller of this routine */
	//p9_node->p9n_fid = fid;  /* Nodes fid*/
	p9_node->v_node = vp; /* map the vnode to ondisk*/
	p9_node->virtfs_ses = p9s; /* Map the current session */

	lockmgr(vp->v_vnlock, LK_EXCLUSIVE, NULL);
	error = insmntque(vp, mp);
	if (error != 0) {
		free(p9_node, M_TEMP);
		*vpp = NULLVP;
		return (error);
	}
	error = vfs_hash_insert(vp, ino, flags, td, vpp, NULL, NULL);
	if (error || *vpp != NULL)
		return (error);

	/* The common code for vfs mount is done. Now we do the 9pfs 
	 * specifc mount code. */

	if (virtfs_proto_dotl(p9s)) {
		st = p9_client_getattr_dotl(fid, P9_STATS_BASIC);
        	if (st == NULL) {
			error = -ENOMEM;
			goto out;
		}
		//vp->v_type = st->va_type;

		/* copy back the qid into the p9node also,.*/
		memcpy(&p9_node->vqid, &st->qid, sizeof(st->qid));

		/* Init the vnode with the disk info*/
                virtfs_stat_vnode_dotl(st, vp);
		/* There needs to be quite a few changes to M_TEMPS to have
		pools for each structure */
                free(st, M_TEMP);

        } else {
                struct p9_wstat *st = NULL;
                st = p9_client_stat(fid);
                if (st == NULL) {
                        error = -ENOMEM;
                        goto out;
                }

		//vp->v_type = st->va_type;
		memcpy(&p9_node->vqid, &st->qid, sizeof(st->qid));

		/* Init the vnode with the disk info*/
                virtfs_stat_vnode_dotl(st, vp);
                free(st, M_TEMP);
	}

	*vpp = vp;
	return (0);
out:
	return error;
}

/* Main mount function for 9pfs*/
static int
p9_mount(struct vnode *devvp, struct mount *mp)
{
	struct p9_fid *fid;
	struct virtfs_mount *vmp = NULL;
	struct virtfs_session *p9s;
	struct cdev *dev;
	struct virtfs_node *root;
	int error = EINVAL;
	struct g_consumer *cp;

	dev = devvp->v_rdev;
	dev_ref(dev);
	g_topology_lock();
	error = g_vfs_open(devvp, &cp, "virtfs", 0);
	g_topology_unlock();
	VOP_UNLOCK(devvp, 0);

	if (error)
		goto out;
	if (devvp->v_rdev->si_iosize_max != 0)
		mp->mnt_iosize_max = devvp->v_rdev->si_iosize_max;
	if (mp->mnt_iosize_max > MAXPHYS)
		mp->mnt_iosize_max = MAXPHYS;

	/* Allocate and initialize the private mount structure. */
	vmp = malloc(sizeof (struct virtfs_mount), M_TEMP, M_WAITOK | M_ZERO);
	mp->mnt_data = vmp;
	vmp->virtfs_mountp = mp;
	p9s = &vmp->virtfs_session;
	p9s->virtfs_mount = mp;
	root = &p9s->rnp;

	fid = virtfs_init_session(mp);
	root->v_node = devvp;
	root->vfid = fid;
	root->virtfs_ses = p9s; /*session ptr structure .*/

	struct p9_stat_dotl *st = NULL;

	/* Create the stat structure to init the vnode */
	if (virtfs_proto_dotl(p9s)) {
		st = p9_client_getattr_dotl(fid, P9_STATS_BASIC);
        	if (st == NULL) {
			error = -ENOMEM;
			goto out;
		}
		memcpy(&root->vqid, &st->qid, sizeof(st->qid));
		/* Init the vnode with the disk info*/
                virtfs_stat_vnode_dotl(st, root->v_node);
                free(st, M_TEMP);
        } else {
                struct p9_wstat *st = NULL;
                st = p9_client_stat(fid);
                if (st == NULL) {
                        error = -ENOMEM;
                        goto out;
                }

		memcpy(&root->vqid, &st->qid, sizeof(st->qid));
		/* Init the vnode with the disk info*/
                virtfs_stat_vnode_dotl(st, root->v_node);
                free(st, M_TEMP);
	}

	mp->mnt_stat.f_fsid.val[0] = dev2udev(dev);
	mp->mnt_stat.f_fsid.val[1] = mp->mnt_vfc->vfc_typenum;
	mp->mnt_maxsymlinklen = 0;
	MNT_ILOCK(mp);
	mp->mnt_flag |= MNT_LOCAL;
	mp->mnt_kern_flag |= MNTK_LOOKUP_SHARED | MNTK_EXTENDED_SHARED;
	MNT_IUNLOCK(mp);
	/* Mount structures created. */

	return 0;
out:
	if (cp != NULL) {
		g_topology_lock();
		g_vfs_close(cp);
		g_topology_unlock();
	}
	if (vmp) {
		free(vmp, M_TEMP);
		mp->mnt_data = NULL;
	}
	dev_rel(dev);
	return error;
}

#if 0
struct virtfs_mount {
	int p9_debuglevel;
	struct virtfs_session virtfs_session;
	struct mount *virtfs_mount;
	char p9_hostname[256];
};
#if 0 
/* A Plan9 node. */
struct virtfs_node {
        uint32_t p9n_fid;
        uint32_t p9n_ofid;
        uint32_t p9n_opens;
        struct virtfs_qid vqid;
        struct vnode *v_node;
        struct virtfs_session *p9n_session;
};

#define MAXUNAMELEN     32
struct virtfs_session {

     unsigned char flags;
     unsigned char nodev;
     unsigned short debug;
     unsigned int afid;
     unsigned int cache;
     struct mount *p9s_mount;
     struct virtfs_node p9s_rootnp;
     unsigned int maxdata;   /* max data for client interface */
     uid_t uid;     /* if ACCESS_SINGLE, the uid that has access */
     struct p9_client *clnt; /* 9p client */
     mtx_lock p9s_lock;

#endif

#endif

/* Mount entry point */
static int
virtfs_mount(struct mount *mp)
{
	int error = 0;
	struct vnode *devvp;
	struct thread *td;
	char *fspec;
	int flags;
	struct nameidata ndp;

	/* No support for UPDATe for now */
	if (mp->mnt_flag & MNT_UPDATE)
		return EOPNOTSUPP;

	if (vfs_filteropt(mp->mnt_optnew, p9_opts))
		goto out;

	fspec = vfs_getopts(mp->mnt_optnew, "from", &error);
        if (error)
                return (error);

	td = curthread;

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
	flags = FREAD;

	/* Determine if type of source file is supported (VREG or VCHR)
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

	if ((error = p9_mount(devvp, mp)))
	{
		vrele(devvp);
		return error;
	}

	return 0;
out:
	if (error != 0)
		(void) virtfs_unmount(mp, MNT_FORCE);
	return (error);
}

static int
virtfs_root(struct mount *mp, int lkflags, struct vnode **vpp)
{
	struct virtfs_mount *vmp = VFSTOP9(mp);
	struct virtfs_node *np = &vmp->virtfs_session.rnp;

	*vpp = np->v_node;
	vref(*vpp);
	vn_lock(*vpp, lkflags);

	return (0);
}

static int
virtfs_statfs(struct mount *mp, struct statfs *sbp)
{
	return 0;
}

static int
virtfs_fhtovp(struct mount *mp, struct fid *fhp, int flags, struct vnode **vpp)
{
	return (EINVAL);
}

static int
virtfs_sync(struct mount *mp, int waitfor)
{
	return (0);
}

struct vfsops virtfs_vfsops = {
	.vfs_mount =	virtfs_mount,
	.vfs_unmount =	virtfs_unmount,
	.vfs_root =	virtfs_root,
	.vfs_statfs =	virtfs_statfs,
	.vfs_fhtovp =	virtfs_fhtovp,
	.vfs_sync =	virtfs_sync,
	.vfs_vget =     virtfs_vget,      /* Most imp vnode_get function.*/
};
VFS_SET(virtfs_vfsops, virtfs, VFCF_JAIL);
