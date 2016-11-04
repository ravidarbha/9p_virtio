/* This file has prototypes specifc and used all over the FS .*/
#ifndef __VIRTFS__
#define __VIRTFS__

enum v9s_state {
	V9S_INIT,
	V9S_RUNNING,
	V9S_CLOSING,
	V9S_CLOSED,
};

struct virtfs_session;

/* The in memory representation of the on disk inode. Save the current 
 * fields to write it back later. */

struct virtfs_inode {

	/* Make it simple first, Add more fields later */
        uint64_t        i_blocks;
        uint64_t        i_size;
        uint64_t        i_ctime;
        uint64_t        i_mtime;
        uint32_t        i_uid;
        uint32_t        i_gid;
        uint16_t        i_mode;
        uint32_t        i_flags;
};

/* A Plan9 node. */
struct virtfs_node {
	struct p9_fid *vfid; /*node fid*/
	struct p9_fid *vofid; /* open fid for this file */
	uint32_t v_opens; /* Number of open handlers. */
	struct virtfs_qid vqid; /* the server qid, will be from the host*/
	struct vnode *v_node; /* vnode for this fs_node. */
	struct virtfs_inode inode; /* This represents the ondisk in mem inode */
	struct virtfs_session *virtfs_ses; /*  Session_ptr for this node */
};

#define	MAXUNAMELEN	32

/* Session structure for the FS */
struct virtfs_session {

     unsigned char flags; /* these flags for the session */
     struct mount *virtfs_mount; /* mount point */
     struct virtfs_node rnp; /* root virtfss_node for this session */
     unsigned int maxdata;   /* max data for client interface */
     uid_t uid;     /* the uid that has access */
     struct p9_client *clnt; /* 9p client */
     struct mtx virtfs_lock;
};

struct virtfs_mount {
	int virt_debug;
	struct virtfs_session virtfs_session;
	struct mount *virtfs_mountp;
};

#define	VFSTOP9(mp) ((mp)->mnt_data)

/* All session flags based on 9p versions  */
enum virt_session_flags {
	VIRTFS_PROTO_2000U	= 0x01,
	VIRTFS_PROTO_2000L	= 0x02,
};

/* These are all the VIRTFS specific vops */
//int virtfs_open(struct p9_client *clnt, int mode);
//int virtfs_close(struct p9_client *clnt);
int virtfs_stat_vnode_dotl(void *st, struct vnode *vp);
int virtfs_proto_dotl(struct virtfs_session *virtfss);
struct p9_fid *virtfs_init_session(struct mount *mp);
void virtfs_close_session(struct mount *mp);
int virtfs_vget(struct mount *mp, ino_t ino, int flags, struct vnode **vpp);

#endif /* __VIRTFS__ */
