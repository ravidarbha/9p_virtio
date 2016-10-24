/*
 * P9 protocol definitions.
 */

#ifndef NET_P9_H
#define NET_P9_H

#include <sys/types.h>

enum p9_msg_t {
	P9_TLERROR = 6,
	P9_RLERROR,
	P9_TSTATFS = 8,
	P9_RSTATFS,
	P9_TLOPEN = 12,
	P9_RLOPEN,
	P9_TLCREATE = 14,
	P9_RLCREATE,
	P9_TSYMLINK = 16,
	P9_RSYMLINK,
	P9_TMKNOD = 18,
	P9_RMKNOD,
	P9_TRENAME = 20,
	P9_RRENAME,
	P9_TREADLINK = 22,
	P9_RREADLINK,
	P9_TGETATTR = 24,
	P9_RGETATTR,
	P9_TSETATTR = 26,
	P9_RSETATTR,
	P9_TXATTRWALK = 30,
	P9_RXATTRWALK,
	P9_TXATTRCREATE = 32,
	P9_RXATTRCREATE,
	P9_TREADDIR = 40,
	P9_RREADDIR,
	P9_TFSYNC = 50,
	P9_RFSYNC,
	P9_TLOCK = 52,
	P9_RLOCK,
	P9_TGETLOCK = 54,
	P9_RGETLOCK,
	P9_TLINK = 70,
	P9_RLINK,
	P9_TMKDIR = 72,
	P9_RMKDIR,
	P9_TRENAMEAT = 74,
	P9_RRENAMEAT,
	P9_TUNLINKAT = 76,
	P9_RUNLINKAT,
	P9_TVERSION = 100,
	P9_RVERSION,
	P9_TAUTH = 102,
	P9_RAUTH,
	P9_TATTACH = 104,
	P9_RATTACH,
	P9_TERROR = 106,
	P9_RERROR,
	P9_TFLUSH = 108,
	P9_RFLUSH,
	P9_TWALK = 110,
	P9_RWALK,
	P9_TOPEN = 112,
	P9_ROPEN,
	P9_TCREATE = 114,
	P9_RCREATE,
	P9_TREAD = 116,
	P9_RREAD,
	P9_TWRITE = 118,
	P9_RWRITE,
	P9_TCLUNK = 120,
	P9_RCLUNK,
	P9_TREMOVE = 122,
	P9_RREMOVE,
	P9_TSTAT = 124,
	P9_RSTAT,
	P9_TWSTAT = 126,
	P9_RWSTAT,
};

enum p9_open_mode_t {
	P9_OREAD = 0x00,
	P9_OWRITE = 0x01,
	P9_ORDWR = 0x02,
	P9_OEXEC = 0x03,
	P9_OTRUNC = 0x10,
	P9_OREXEC = 0x20,
	P9_ORCLOSE = 0x40,
	P9_OAPPEND = 0x80,
	P9_OEXCL = 0x1000,
};

enum p9_perm_t {
	P9_DMDIR = 0x80000000,
	P9_DMAPPEND = 0x40000000,
	P9_DMEXCL = 0x20000000,
	P9_DMMOUNT = 0x10000000,
	P9_DMAUTH = 0x08000000,
	P9_DMTMP = 0x04000000,
/* P92000.u extensions */
	P9_DMSYMLINK = 0x02000000,
	P9_DMLINK = 0x01000000,
	P9_DMDEVICE = 0x00800000,
	P9_DMNAMEDPIPE = 0x00200000,
	P9_DMSOCKET = 0x00100000,
	P9_DMSETUID = 0x00080000,
	P9_DMSETGID = 0x00040000,
	P9_DMSETVTX = 0x00010000,
};

/* 9p2000.L open flags */
#define P9_DOTL_RDONLY        00000000
#define P9_DOTL_WRONLY        00000001
#define P9_DOTL_RDWR          00000002
#define P9_DOTL_NOACCESS      00000003
#define P9_DOTL_CREATE        00000100
#define P9_DOTL_EXCL          00000200
#define P9_DOTL_NOCTTY        00000400
#define P9_DOTL_TRUNC         00001000
#define P9_DOTL_APPEND        00002000
#define P9_DOTL_NONBLOCK      00004000
#define P9_DOTL_DSYNC         00010000
#define P9_DOTL_FASYNC        00020000
#define P9_DOTL_DIRECT        00040000
#define P9_DOTL_LARGEFILE     00100000
#define P9_DOTL_DIRECTORY     00200000
#define P9_DOTL_NOFOLLOW      00400000
#define P9_DOTL_NOATIME       01000000
#define P9_DOTL_CLOEXEC       02000000
#define P9_DOTL_SYNC          04000000

/* 9p2000.L at flags */
#define P9_DOTL_AT_REMOVEDIR		0x200

/* 9p2000.L lock type */
#define P9_LOCK_TYPE_RDLCK 0
#define P9_LOCK_TYPE_WRLCK 1
#define P9_LOCK_TYPE_UNLCK 2

enum p9_qid_t {
	P9_QTDIR = 0x80,
	P9_QTAPPEND = 0x40,
	P9_QTEXCL = 0x20,
	P9_QTMOUNT = 0x10,
	P9_QTAUTH = 0x08,
	P9_QTTMP = 0x04,
	P9_QTSYMLINK = 0x02,
	P9_QTLINK = 0x01,
	P9_QTFILE = 0x00,
};

/* P9 Magic Numbers */
#define P9_NOTAG	(uint16_t)(~0)
#define P9_NOFID	(uint32_t)(~0)
#define P9_MAXWELEM	16

struct p9_qid {
	uint8_t type;
	uint32_t version;
	uint64_t path;
};

struct p9_wstat {
	uint16_t size;
	uint16_t type;
	uint32_t dev;
	struct p9_qid qid;
	uint32_t mode;
	uint32_t atime;
	uint32_t mtime;
	uint64_t length;
	char *name;
	char *uid;
	char *gid;
	char *muid;
	char *extension;	/* 9p2000.u extensions */
	uid_t n_uid;		/* 9p2000.u extensions */
	gid_t n_gid;		/* 9p2000.u extensions */
	uid_t n_muid;		/* 9p2000.u extensions */
};

struct p9_stat_dotl {
	uint64_t st_result_mask;
	struct p9_qid qid;
	uint32_t st_mode;
	uid_t st_uid;
	gid_t st_gid;
	uint64_t st_nlink;
	uint64_t st_rdev;
	uint64_t st_size;
	uint64_t st_blksize;
	uint64_t st_blocks;
	uint64_t st_atime_sec;
	uint64_t st_atime_nsec;
	uint64_t st_mtime_sec;
	uint64_t st_mtime_nsec;
	uint64_t st_ctime_sec;
	uint64_t st_ctime_nsec;
	uint64_t st_btime_sec;
	uint64_t st_btime_nsec;
	uint64_t st_gen;
	uint64_t st_data_version;
};

#define P9_STATS_MODE		0x00000001ULL
#define P9_STATS_NLINK		0x00000002ULL
#define P9_STATS_UID		0x00000004ULL
#define P9_STATS_GID		0x00000008ULL
#define P9_STATS_RDEV		0x00000010ULL
#define P9_STATS_ATIME		0x00000020ULL
#define P9_STATS_MTIME		0x00000040ULL
#define P9_STATS_CTIME		0x00000080ULL
#define P9_STATS_INO		0x00000100ULL
#define P9_STATS_SIZE		0x00000200ULL
#define P9_STATS_BLOCKS		0x00000400ULL

#define P9_STATS_BTIME		0x00000800ULL
#define P9_STATS_GEN		0x00001000ULL
#define P9_STATS_DATA_VERSION	0x00002000ULL

#define P9_STATS_BASIC		0x000007ffULL /* Mask for fields up to BLOCKS */
#define P9_STATS_ALL		0x00003fffULL /* Mask for All fields above */

struct p9_iattr_dotl {
	uint32_t valid;
	uint32_t mode;
	uid_t uid;
	gid_t gid;
	uint64_t size;
	uint64_t atime_sec;
	uint64_t atime_nsec;
	uint64_t mtime_sec;
	uint64_t mtime_nsec;
};


struct p9_rstatfs {
	uint32_t type;
	uint32_t bsize;
	uint64_t blocks;
	uint64_t bfree;
	uint64_t bavail;
	uint64_t files;
	uint64_t ffree;
	uint64_t fsid;
	uint32_t namelen;
};

struct p9_fcall {
	uint32_t size;
	uint8_t id;
	uint16_t tag;

	size_t offset;
	size_t capacity;

	uint8_t *sdata;
};


int p9_errstr2errno(char *errstr, int len);

int p9_error_init(void);
int p9_trans_fd_init(void);
void p9_trans_fd_exit(void);
#endif /* NET_P9_H */
