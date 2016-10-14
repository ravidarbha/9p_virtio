
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/dirent.h>
#include <sys/namei.h>

#include "p9fs_proto.h"

struct vop_vector p9fs_vnops;
static MALLOC_DEFINE(M_P9NODE, "p9fs_node", "p9fs node structures");

static int
p9fs_lookup(struct vop_cachedlookup_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct p9fs_node *dnp = dvp->v_data;
	struct p9fs_session *p9s = dnp->p9n_session;
	struct p9fs_node *np = NULL;
	struct p9fs_qid qid;
	uint32_t newfid;
	int error;

	*vpp = NULL;
	printf("%s(fid %u name '%.*s')\n", __func__, dnp->p9n_fid,
	    (int)cnp->cn_namelen, cnp->cn_nameptr);

	/* Special case: lookup a directory from itself. */
	if (cnp->cn_namelen == 1 && *cnp->cn_nameptr == '.') {
		*vpp = dvp;
		vref(*vpp);
		return (0);
	}

	/* The clone has to be set to get a new fid */
	error = p9_client_walk(dnp->p9n_fid,
	    cnp->cn_namelen, cnp->cn_nameptr, 1);
	if (error == 0) {
		int ltype = 0;

		if (cnp->cn_flags & ISDOTDOT) {
			ltype = VOP_ISLOCKED(dvp);
			VOP_UNLOCK(dvp, 0);
		}
		/* Vget gets the vp for the newly created vnode. Stick it to the p9fs_node too*/
		error = p9fs_vget(ap->mp, newfid, cnp->cn_lkflags, &vp);
		if (cnp->cn_flags & ISDOTDOT)
			vn_lock(dvp, ltype | LK_RETRY);
	}
	if (error == 0) {
		*vpp = vp;
		vref(*vpp);
	} else
		p9fs_relfid(p9s, newfid);

	return (error);
}

#define	VNOP_UNIMPLEMENTED				\
	printf("%s: not implemented yet\n", __func__);	\
	return (EINVAL)

/* We ll implement this once mount works fine .*/
static int
p9fs_create(struct vop_create_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_mknod(struct vop_mknod_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

#endif 

static int
p9fs_open(struct vop_open_args *ap)
{
	int error;
	struct p9fs_node *np = ap->a_vp->v_data;
	uint32_t fid = np->p9n_fid;
	struct wstat *stat;

	printf("%s(fid %u)\n", __func__, np->p9n_fid);

	if (np->p9n_opens > 0) {
		np->p9n_opens++;
		return (0);
	}

	stat  = p9_client_stat(np->p9n_fid);
	if (error != 0)
		return (error);

	/*
	 * XXX VFS calls VOP_OPEN() on a directory it's about to perform
	 *     VOP_READDIR() calls on.  However, 9P2000 Twalk requires that
	 *     the given fid not have been opened.
	 * 	For now, this call performs an internal Twalk to obtain a cloned
	 * 	fid that can be opened separately.  It will be clunk'd at the
	 * 	same time as the unopened fid.
	 */
	if (ap->a_vp->v_type == VDIR) {
		if (np->p9n_ofid == 0) {

			/*ofid is the open fid for this file.*/
			np->p9n_ofid = p9_client_walk(np->p9n_fid,
			     0, NULL, 1); /* Clone the fid here.*/
			if (error != 0) {
				np->p9n_ofid = 0;
				return (error);
			}
		}
		fid = np->p9n_ofid;
	}

	/* Use the newly created fid for the open.*/
	error = p9_client_open(fid, ap->a_mode);
	if (error == 0) {
		np->p9n_opens = 1;
		vnode_create_vobject(ap->a_vp, vattr.va_bytes, ap->a_td);
	}

	return (error);
}

static int
p9fs_close(struct vop_close_args *ap)
{
	struct p9fs_node *np = ap->a_vp->v_data;

	printf("%s(fid %d ofid %d opens %d)\n", __func__,
	    np->p9n_fid, np->p9n_ofid, np->p9n_opens);
	np->p9n_opens--;
	if (np->p9n_opens == 0) {
		p9fs_relfid(np->p9n_session, np->p9n_ofid);
		np->p9n_ofid = 0;
	}

	/*
	 * In p9fs, the only close-time operation to do is Tclunk, but it's
	 * only appropriate to do that in VOP_RECLAIM, since we may reuse
	 * the vnode for a file for some time before its fid is guaranteed
	 * not to be used again.
	 */
	return (0);
}

static int
p9fs_getattr(struct vop_getattr_args *ap)
{
	struct p9fs_node *np = ap->a_vp->v_data;
	ap->a_vap = p9_client_stat(np->p9n_fid, ap->a_vap);

	printf("%s(fid %d) ret %d\n", __func__, np->p9n_fid, error);
	return 0;
}


int
p9fs_stat_vnode_dotl(void *st, struct vnode *vp)
{

	struct p9fs_node = vp->v_data;
	struct p9fs_inode *inode = 9fs_node->inode;

	if (p9fs_proto_dotl(p9s)) {
		struct p9_stat_dotl *stat = (struct p9_stat_dotl *)st;

		/* Just get the needed fields for now. We can add more later. */
                inode->i_mtime = stat->st_mtime_sec;
                inode->i_mtime_nsec = stat->st_mtime_nsec;
                inode->i_ctime = stat->st_ctime_sec;
                inode->i_ctime_nsec = stat->st_ctime_nsec;
                inode->i_uid = stat->st_uid;
                inode->i_gid = stat->st_gid;
                inode->i_blocks = stat->st_blocks;
		inode->i_mode = stat->st_mode;
	}
	else
		struct p9_wstat *stat = (struct p9_wstat *)st;
		warn(" We still dont support this version ");
	
	}
}

static int
p9fs_setattr(struct vop_setattr_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_read(struct vop_read_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_write(struct vop_write_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_fsync(struct vop_fsync_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_remove(struct vop_remove_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_link(struct vop_link_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_rename(struct vop_rename_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_mkdir(struct vop_mkdir_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_rmdir(struct vop_rmdir_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_symlink(struct vop_symlink_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

/*
 * Minimum length for a directory entry: size of fixed size section of
 * struct dirent plus a 1 byte C string for the name.
 */
#define	DIRENT_MIN_LEN	(offsetof(struct dirent, d_name) + 2)

static int
p9fs_readdir(struct vop_readdir_args *ap)
{
	struct uio *uio = ap->a_uio;
        struct vnode *vp = ap->a_vp;
	struct p9_dirent *curdirent;
        struct dirent dirent;
        uint64_t file_size, diroffset, transoffset, blkoff;
        uint8_t *pos, name_len;
	struct p9fs_node *np = ap->a_vp->v_data;
        int error = 0;

	if (ap->a_uio->uio_iov->iov_len <= 0)
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	/* This should have the updated value always.*/
	file_size = node->p9_inode.i_size;

	/* We are called just as long as we keep on pushing data in */
	error = 0;
	if ((uio->uio_offset < file_size) &&
	    (uio->uio_resid >= sizeof(struct dirent))) {
		diroffset = uio->uio_offset;
		transoffset = diroffset;

		/* Our version of the readdir through the virtio. The data buf has the 
		 * data block information. Now parse through the buf and make the dirent.
		 * /
		error = p9_client_readdir(np->p9n_ofid, (char *)data,
		clnt->msize, 0); /* The max size our client can handle */

		if (error) {
			return (EIO);
		}
	}
#if 0
	struct p9_dirent {
        struct p9_qid qid;
        uint64_t d_off;
        unsigned char d_type;
        char d_name[256];
};
#endif // Directory entry 

		offset = 0;
		while (diroffset < file_size) {

			/* Read and make sense out of the buffer in one dirent
			 * This is part of 9p protocol read.
			 */
			err = p9dirent_read(fid->clnt, data + offset,
                                            sizeof(curdirent),
                                            &curdirent);
                        if (err < 0) {
                                p9_debug(P9_DEBUG_VFS, "returned %d\n", err);
                                return -EIO;                                             
                        }

			name_len = curdirent->name_len;
			memset(&dirent, 0, sizeof(struct dirent));
			memcpy(&dirent.d_fileno, &curdirent->qid, sizeof(curdirent->qid));
			if (dirent.d_fileno) {
				dirent.d_type = curdirent->file_type;
				dirent.d_namlen = name_len;
				strncpy(dirent.d_name, curdirent->name, name_len);
				dirent.d_reclen = GENERIC_DIRSIZ(&dirent);
			}

			/*
			 * If there isn't enough space in the uio to return a
			 * whole dirent, break off read
			 */
			if (uio->uio_resid < GENERIC_DIRSIZ(&dirent))
				break;

			/* Transfer */
			if (dirent.d_fileno)
				uiomove(&dirent, GENERIC_DIRSIZ(&dirent), uio);

			/* Advance */
			diroffset += curdirent->rec_len;
			offset += curdirent->rec_len;

			transoffset = diroffset;
		}

		/* Pass on last transferred offset */
		uio->uio_offset = transoffset;
	}

	if (ap->a_eofflag)
		*ap->a_eofflag = (uio->uio_offset >= file_size);

	return (error);
}

static int
p9fs_readlink(struct vop_readlink_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_inactive(struct vop_inactive_args *ap)
{
	return (0);
}

struct vop_vector p9fs_vnops = {
	.vop_default =		&default_vnodeops,
	.vop_lookup =		vfs_cache_lookup,
	.vop_cachedlookup =	p9fs_lookup,
	.vop_create =		p9fs_create,
	.vop_mknod =		p9fs_mknod,
	.vop_open =		p9fs_open,
	.vop_close =		p9fs_close,
	.vop_access =		p9fs_access,
	.vop_getattr =		p9fs_getattr,
	.vop_setattr =		p9fs_setattr,
	.vop_read =		p9fs_read,
	.vop_write =		p9fs_write,
	.vop_fsync =		p9fs_fsync,
	.vop_remove =		p9fs_remove,
	.vop_link =		p9fs_link,
	.vop_rename =		p9fs_rename,
	.vop_mkdir =		p9fs_mkdir,
	.vop_rmdir =		p9fs_rmdir,
	.vop_symlink =		p9fs_symlink,
	.vop_readdir =		p9fs_readdir,
	.vop_readlink =		p9fs_readlink,
	.vop_inactive =		p9fs_inactive,
};
