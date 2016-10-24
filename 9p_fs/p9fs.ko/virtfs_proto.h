/*
 * Plan9 filesystem (9P2000.u) protocol definitions.
 */

/**************************************************************************
 * Plan9 protocol definitions section
 **************************************************************************/

#ifndef	__VIRTFS_PROTO_H__
#define	__VIRTFS_PROTO_H__

#include "../../9p.h"
/*
 * The message type used as the fifth byte for all 9P2000 messages.
 */
enum virtfs_msg_type {
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
struct virtfs_qid {
	uint8_t qid_mode;
	uint32_t qid_version;
	uint64_t qid_path;
} __attribute__((packed));

enum virtfs_qid_type {
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
enum virtfs_mode {
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
struct virtfs_stat {
	uint16_t stat_size;
	uint16_t stat_type;
	uint32_t stat_dev;
	struct virtfs_qid stat_qid;
	uint32_t stat_mode;
	uint32_t stat_atime;
	uint32_t stat_mtime;
	uint64_t stat_length;
	/* stat_name[s] */
	/* stat_uid[s] */
	/* stat_gid[s] */
	/* stat_muid[s] */
} __attribute__((packed));

#define	OREAD	0
#define	OWRITE	1
#define	ORDWR	2
#define	OEXEC	3
#define	OTRUNC	0x10

#endif /* __VIRTFS_PROTO_H__ */
