/*
 * Plan9 filesystem (9P2000.u) protocol definitions.
 */

/**************************************************************************
 * Plan9 protocol documentation section
 **************************************************************************/

/*
 * 2 Introduction / 2.1 Messages
 *
 * - A client transmits requests (T-messages) to a server, which subsequently
 *   returns replies (R-messages) to the client.  The combined acts of
 *   transmitting (receiving) a request of a particular type, and receiving
 *   (transmitting) its reply is called a transaction of that type.
 *
 * - Each message consists of a sequence of bytes. Two-, four-, and
 *   eight-byte fields hold unsigned integers represented in little-endian
 *   order (least significant byte first).  Data items of larger or variable
 *   lengths are represented by a two-byte field specifying a count, n,
 *   followed by n bytes of data. Text strings are represented this way, with
 *   the text itself stored as a UTF-8 encoded sequence of Unicode characters.
 *   Text strings in 9P messages are not NUL-terminated: n counts the bytes
 *   of UTF-8 data, which include no final zero byte.  The NUL character is
 *   illegal in all text strings in 9P, and is therefore excluded from file
 *   names, user names, and so on.
 *
 * - Each 9P message begins with a four-byte size field specifying the length
 *   in bytes of the complete message including the four bytes of the size
 *   field itself.  The next byte is the message type, one of the constants
 *   in the enumeration in the include file fcall.h.  The next two bytes are
 *   an identifying tag, described below. The remaining bytes are parameters
 *   of different sizes. In the message descriptions, the number of bytes in a
 *   field is given in brackets after the field name.  The notation
 *   parameter[n] where n is not a constant represents a variable-length
 *   parameter: n[2] followed by n bytes of data forming the parameter.
 *   The notation string[s] (using a literal s character) is shorthand for
 *   s[2] followed by s bytes of UTF-8 text.  (Systems may choose to reduce
 *   the set of legal characters to reduce syntactic problems, for example
 *   to remove slashes from name components, but the protocol has no such
 *   restriction.  Plan 9 names may contain any printable character (that
 *   is, any character outside hexadecimal 00-1F and 80-9F) except slash.)
 *   Messages are transported in byte form to allow for machine independence;
 *   fcall(2) describes routines that convert to and from this form into a
 *   machine-dependent C structure.
 *
 * - Each T-message has a tag field, chosen and used by the client to
 *   identify the message.  The reply to the message will have the same tag.
 *   Clients must arrange that no two outstanding messages on the same
 *   connection have the same tag.  An exception is the tag NOTAG, defined
 *   as (ushort)~0 in fcall.h: the client can use it, when establishing a
 *   connection, to override tag matching in version messages.
 *
 * - The type of an R-message will either be one greater than the type of
 *   the corresponding T-message or Rerror, indicating that the request failed.
 *   In the latter case, the ename field contains a string describing the
 *   reason for failure.
 *
 * - The version message identifies the version of the protocol and indicates
 *   the maximum message size the system is prepared to handle.  It also
 *   initializes the connection and aborts all outstanding I/O on the
 *   connection.  The set of messages between version requests is called
 *   a session.
 *
 * - Most T-messages contain a fid, a 32-bit unsigned integer that the
 *   client uses to identify a ``current file'' on the server.  Fids are
 *   somewhat like file descriptors in a user process, but they are not
 *   restricted to files open for I/O: directories being examined, files
 *   being accessed by stat(2) calls, and so on -- all files being
 *   manipulated by the operating system -- are identified by fids.  Fids are
 *   chosen by the client.  All requests on a connection share the same fid
 *   space; when several clients share a connection, the agent managing the
 *   sharing must arrange that no two clients choose the same fid.
 *
 * - The fid supplied in an attach message will be taken by the server to
 *   refer to the root of the served file tree.  The attach identifies the
 *   user to the server and may specify a particular file tree served by the
 *   server (for those that supply more than one).
 *
 * - Permission to attach to the service is proven by providing a special
 *   fid, called afid, in the attach message.  This afid is established by
 *   exchanging auth messages and subsequently manipulated using read and
 *   write messages to exchange authentication information not defined
 *   explicitly by 9P [P9SEC].  Once the authentication protocol is
 *   complete, the afid is presented in the attach to permit the user to
 *   access the service.
 *
 * - A walk message causes the server to change the current file associated
 *   with a fid to be a file in the directory that is the old current file,
 *   or one of its subdirectories.  Walk returns a new fid that refers to
 *   the resulting file.  Usually, a client maintains a fid for the root,
 *   and navigates by walks from the root fid.
 *
 * - A client can send multiple T-messages without waiting for the
 *   corresponding R-messages, but all outstanding T-messages must specify
 *   different tags.  The server may delay the response to a request and
 *   respond to later ones; this is sometimes necessary, for example when
 *   the client reads from a file that the server synthesizes from external
 *   events such as keyboard characters.
 *
 * - Replies (R-messages) to auth, attach, walk, open, and create requests
 *   convey a qid field back to the client.  The qid represents the server's
 *   unique identification for the file being accessed: two files on the
 *   same server hierarchy are the same if and only if their qids are the
 *   same. (The client may have multiple fids pointing to a single file on
 *   a server and hence having a single qid.)  The thirteen-byte qid fields
 *   hold a one-byte type, specifying whether the file is a directory,
 *   append-only file, etc., and two unsigned integers: first the four-byte
 *   qid version, then the eight-byte qid path.  The path is an integer unique
 *   among all files in the hierarchy.  If a file is deleted and recreated
 *   with the same name in the same directory, the old and new path
 *   components of the qids should be different.  The version is a version
 *   number for a file; typically, it is incremented every time the file
 *   is modified.
 *
 * - An existing file can be opened, or a new file may be created in the
 *   current (directory) file.  I/O of a given number of bytes at a given
 *   offset on an open file is done by read and write.
 *
 * - A client should clunk any fid that is no longer needed. The remove
 *   transaction deletes files.
 *
 * - The stat transaction retrieves information about the file.  The stat
 *   field in the reply includes the file's name, access permissions (read,
 *   write and execute for owner, group and public), access and modification
 *   times, and owner and group identifications (see stat(2)).  The owner
 *   and group identifications are textual names.  The wstat transaction
 *   allows some of a file's properties to be changed.  A request can be
 *   aborted with a flush request.  When a server receives a Tflush, it
 *   should not reply to the message with tag oldtag (unless it has already
 *   replied), and it should immediately send an Rflush.  The client must
 *   wait until it gets the Rflush (even if the reply to the original message
 *   arrives in the interim), at which point oldtag may be reused.
 *
 * - Because the message size is negotiable and some elements of the
 *   protocol are variable length, it is possible (although unlikely) to
 *   have a situation where a valid message is too large to fit within the
 *   negotiated size.  For example, a very long file name may cause a Rstat
 *   of the file or Rread of its directory entry to be too large to send.
 *   In most such cases, the server should generate an error rather than
 *   modify the data to fit, such as by truncating the file name.  The
 *   exception is that a long error string in an Rerror message should be
 *   truncated if necessary, since the string is only advisory and in
 *   some sense arbitrary.
 *
 * - 
 */

/*
 * 2.2 Directories
 *
 * - Directories are created by create with DMDIR set in the permissions
 *   argument.  The members of a directory can be found with
 *   read(5).  All directories must support walks to the directory ..
 *   (dot-dot) meaning parent directory, although by convention directories
 *   contain no explicit entry for .. or . (dot).  The parent of the root
 *   directory of a server's tree is itself.
 *
 * - Each file server maintains a set of user and group names.  Each user
 *   can be a member of any number of groups.  Each group has a group leader
 *   who has special privileges.  Every file request has an implicit user id
 *   (copied from the original attach) and an implicit set of groups (every
 *   group of which the user is a member).
 */

/*
 * 2.3 Access Permissions
 *
 * - Each file has an associated owner and group id and three sets of
 *   permissions: those of the owner, those of the group, and those of
 *   ``other'' users.  When the owner attempts to do something to a file,
 *   the owner, group, and other permissions are consulted, and if any of
 *   them grant the requested permission, the operation is allowed.  For
 *   someone who is not the owner, but is a member of the file's group, the
 *   group and other permissions are consulted.  For everyone else, the
 *   other permissions are used.  Each set of permissions says whether
 *   reading is allowed, whether writing is allowed, and whether executing
 *   is allowed.  A walk in a directory is regarded as executing the
 *   directory, not reading it.  Permissions are kept in the low-order bits
 *   of the file mode: owner read/write/execute permission represented as
 *   1 in bits 8, 7, and 6 respectively (using 0 to number the low order).
 *   The group permissions are in bits 5, 4, and 3, and the other
 *   permissions are in bits 2, 1, and 0.
 *
 * - The file mode contains some additional attributes besides the
 *   permissions.  If bit 31 (DMDIR) is set, the file is a directory; if
 *   bit 30 (DMAPPEND) is set, the file is append-only (offset is ignored
 *   in writes); if bit 29 (DMEXCL) is set, the file is exclusive- use
 *   (only one client may have it open at a time); if bit 27 (DMAUTH) is set,
 *   the file is an authentication file established by auth messages; if
 *   bit 26 (DMTMP) is set, the contents of the file (or directory) are not
 *   included in nightly archives.  (Bit 28 is skipped for historical
 *   reasons.)  These bits are reproduced, from the top bit down, in the
 *   type byte of the Qid: QTDIR, QTAPPEND, QTEXCL, (skipping one bit)
 *   QTAUTH, and QTTMP.  The name QTFILE, defined to be zero, identifies
 *   the value of the type for a plain file.
 */

/**************************************************************************
 * Plan9 protocol definitions section
 **************************************************************************/

#ifndef	__P9FS_PROTO_H__
#define	__P9FS_PROTO_H__

#include "../../9p.h"
/*
 * The message type used as the fifth byte for all 9P2000 messages.
 */
enum p9fs_msg_type {
	Tversion =	100,
	Rversion,
	Tauth,
	Rauth,
	Tattach,
	Rattach,
	/* Terror is illegal */
	Rerror =	107,
	Tflush,
	Rflush,
	Twalk,
	Rwalk,
	Topen,
	Ropen,
	Tcreate,
	Rcreate,
	Tread,
	Rread,
	Twrite,
	Rwrite,
	Tclunk,
	Rclunk,
	Tremove,
	Rremove,
	Tstat,
	Rstat,
	Twstat,
	Rwstat,
};

/*
 * Common structures for 9P2000 message payload items.
 */

/* QID: Unique identification for the file being accessed */
struct p9fs_qid {
	uint8_t qid_mode;
	uint32_t qid_version;
	uint64_t qid_path;
} __attribute__((packed));

enum p9fs_qid_type {
	QTDIR =		0x80,
	QTAPPEND =	0x40,
	QTEXCL =	0x20,
	QTMOUNT =	0x10,
	QTAUTH =	0x08,
	QTTMP =		0x04,
	QTLINK =	0x02,
	QTFILE =	0x00,
};

/* From 9P2000.u pages 9-10 */
enum p9fs_mode {
	DMDIR =		0x80000000,
	DMAPPEND =	0x40000000,
	DMEXCL =	0x20000000,
	DMMOUNT =	0x10000000,
	DMAUTH =	0x08000000,
	DMTMP =		0x04000000,
	DMSYMLINK =	0x02000000,
	/* 9P2000.u extensions */
	DMDEVICE =	0x00800000,
	DMNAMEDPIPE =	0x00200000,
	DMSOCKET =	0x00100000,
	DMSETUID =	0x00080000,
	DMSETGID =	0x00040000,

	/* Use this to select only the above upper bits. */
	P9MODEUPPER =	0xffff0000,
};

/* Plan9-specific stat structure */
struct p9fs_stat {
	uint16_t stat_size;
	uint16_t stat_type;
	uint32_t stat_dev;
	struct p9fs_qid stat_qid;
	uint32_t stat_mode;
	uint32_t stat_atime;
	uint32_t stat_mtime;
	uint64_t stat_length;
	/* stat_name[s] */
	/* stat_uid[s] */
	/* stat_gid[s] */
	/* stat_muid[s] */
} __attribute__((packed));

/* This is the stat addendum for 9P2000.u vs 9P2000 */
struct p9fs_stat_u {
	struct p9fs_stat u_stat;
	/* extension[s] */
	/* p9fs_stat_u_footer */
} __attribute__((packed));

struct p9fs_stat_u_footer {
	uint32_t n_uid;
	uint32_t n_gid;
	uint32_t n_muid;
} __attribute__((packed));

#define	NOFID		(uint32_t)~0
/* This FID is not specified by the standard, but implemented here as such. */
#define	ROOTFID		(uint32_t)0

#define	P9_VERS		"9P2000"
#define	UN_VERS		P9_VERS ".u"

#define	OREAD	0
#define	OWRITE	1
#define	ORDWR	2
#define	OEXEC	3
#define	OTRUNC	0x10

/**************************************************************************
 * Plan9 session details section
 **************************************************************************/
enum p9s_state {
	P9S_INIT,
	P9S_RUNNING,
	P9S_CLOSING,
	P9S_CLOSED,
};

struct p9fs_session;

struct p9fs_node_user {
	uint32_t p9nu_read_fid;
	uint16_t p9nu_read_refs;
	uint32_t p9nu_write_fid;
	uint16_t p9nu_write_refs;
	uint32_t p9nu_append_fid;
	uint16_t p9nu_append_refs;
};


/* The in memory representation of the on disk inode. Save the current 
 * fields to write it back later. */

struct p9fs_inode {

        uint64_t        i_blocks;       /* 0: size in device blocks             */
        uint64_t        i_size;         /* 8: size in bytes                     */
        uint64_t        i_ctime;        /* 16: creation time in seconds         */
        uint64_t        i_mtime;        /* 24: modification time in seconds part*/
	/* WE can add atime and b time later . They already exist in the stat */
        uint32_t        i_ctime_nsec;   /* 32: creation time nanoseconds part   */
        uint32_t        i_mtime_nsec;   /* 36: modification time in nanoseconds */
        uint32_t        i_uid;          /* 40: user id                          */
        uint32_t        i_gid;          /* 44: group id                         */
        uint16_t        i_mode;         /* 48: file mode                        */
        uint16_t        i_links_count;  /* 50: number of references to the inode*/
        uint32_t        i_flags;        /* 52: NANDFS_*_FL flags                */
        uint64_t        i_special;      /* 56: special                          */
	/* Do we need block numbers here ? */
	/* We are read ing and writing to the host, by sending requests .*/ 
        //uint64_t        i_db[NDADDR];   /* 64: Direct disk blocks.              */
        //uint64_t        i_ib[NIADDR];   /* 160: Indirect disk blocks.           */
        uint64_t        i_xattr;        /* 184: reserved for extended attributes*/
        uint32_t        i_generation;   /* 192: file generation for NFS         */
        uint32_t        i_pad[15];      /* 196: make it 64 bits aligned         */
};

/* A Plan9 node. */
struct p9fs_node {
	uint32_t p9n_fid; /*node fid*/
	uint32_t p9n_ofid; /* open fid for this file */
	uint32_t p9n_opens; /* Number of open handlers. */
	struct p9fs_qid p9n_qid; /* the server qid, will be from the host*/
	struct vnode *p9n_vnode; /* vnode for this fs_node. */
	struct p9fs_inode inode; /* This represents the ondisk in mem inode */
	struct p9fs_session *p9n_session; /*  Session_ptr for this node */
};

#define	MAXUNAMELEN	32
/* these session fields look good for now.
 * WEll add more later.*/ 
struct p9fs_session {

     unsigned char flags;
     unsigned char nodev;
     unsigned short debug;
     unsigned int afid;
     struct mount *p9s_mount;
     struct p9fs_node p9s_rootnp;
     unsigned int maxdata;   /* max data for client interface */
     uid_t uid;     /* if ACCESS_SINGLE, the uid that has access */
     struct p9_client *clnt; /* 9p client */
     struct mtx p9s_lock;
};


#define	V9FS_ACCESS_ANY (V9FS_ACCESS_SINGLE | \
			 V9FS_ACCESS_USER |   \
			 V9FS_ACCESS_CLIENT)
#define V9FS_ACCESS_MASK V9FS_ACCESS_ANY
#define V9FS_ACL_MASK V9FS_POSIX_ACL
#define	VFSTOP9(mp) ((mp)->mnt_data)

enum p9_session_flags {
	V9FS_PROTO_2000U	= 0x01,
	V9FS_PROTO_2000L	= 0x02,
	V9FS_ACCESS_SINGLE	= 0x04,
	V9FS_ACCESS_USER	= 0x08,
	V9FS_ACCESS_CLIENT	= 0x10,
	V9FS_POSIX_ACL		= 0x20
};


/* Primary 9P2000.u client API calls. */
int p9_client_version(struct p9_client *clnt);
struct p9_fid *p9_client_attach(struct p9_client *clnt, struct p9_fid *afid,
        char *uname, uid_t n_uname, char *aname);
struct p9_client *p9_client_create(struct mount *mp);
void p9_client_destroy(struct p9_client *clnt);
int p9_client_detach(struct p9_fid *fid);
struct p9_fid *p9_client_walk(struct p9_fid *oldfid, uint16_t nwname,
                char **wnames, int clone);
int p9fs_client_open(struct p9_client *clnt, int mode);
int p9fs_proto_dotl(struct p9fs_session *p9s);
struct p9_fid *p9fs_init_session(struct mount *mp);
struct p9_wstat *p9_client_stat(struct p9_fid *fid);
struct p9_stat_dotl *p9_client_getattr_dotl(struct p9_fid *fid, uint64_t mask);
int p9_client_setattr(struct p9_fid *fid, struct p9_iattr_dotl *p9attr);
int p9_client_wstat(struct p9_fid *fid, struct p9_wstat *wst);
int p9_client_statfs(struct p9_fid *fid, struct p9_rstatfs *sb);
int p9_client_readdir(struct p9_fid *fid, char *data, uint32_t count, uint64_t offset);

#endif /* __P9FS_PROTO_H__ */
