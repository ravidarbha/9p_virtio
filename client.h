
#ifndef NET_9P_CLIENT_H
#define NET_9P_CLIENT_H

#define MAX_ERRNO 30

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <machine/stdarg.h>

#include "9p.h"

enum p9_proto_versions{
	p9_proto_legacy,
	p9_proto_2000u,
	p9_proto_2000L,
};

enum p9_trans_status {
	Connected,
	BeginDisconnect,
	Disconnected,
	Hung,
};

enum p9_req_status_t {
	REQ_STATUS_IDLE,
	REQ_STATUS_ALLOC,
	REQ_STATUS_UNSENT,
	REQ_STATUS_SENT,
	REQ_STATUS_RCVD,
	REQ_STATUS_FLSHD,
	REQ_STATUS_ERROR,
};

struct p9_req_t {
	int status;
	int t_err;
	struct p9_fcall *tc;
	struct p9_fcall *rc;
	void *aux;
};


struct p9_client {
	struct mtx lock; /* protect client structure */
	struct cv req_cv;
	unsigned int msize;
	unsigned char proto_version;
	struct p9_trans_module *trans_mod;
	enum p9_trans_status status;
	void *trans;

	struct unrhdr *fidpool;
	//TAILQ_HEAD(,p9_fid)  fidlist;

	// malloc these requests and keep to use during fast path.
	//TAILQ_HEAD (_,p9_req_t ) reqlist;

	char name[32];
};

/* The main fid structure which keeps track of the file.*/
struct p9_fid {
	struct p9_client *clnt;
	uint32_t fid;
	int mode;
	struct p9_qid qid;
	uint32_t iounit;
	uid_t uid;
	void *rdir;
};


/* struct p9_dirent - directory entry structure
 * the directoy entry used for directory structures.
 * Make sure this is aligned with the dirent structure.	
 */

struct p9_dirent {
	struct p9_qid qid;
	uint64_t d_off;
	unsigned char d_type;
	char d_name[256];
};

struct iov_iter;

int p9_client_statfs(struct p9_fid *fid, struct p9_rstatfs *sb);
int p9_client_rename(struct p9_fid *fid, struct p9_fid *newdirfid,
		     const char *name);
int p9_client_renameat(struct p9_fid *olddirfid, const char *old_name,
		       struct p9_fid *newdirfid, const char *new_name);
struct p9_client *p9_client_create(struct mount *mp);
void
p9fs_close_session(struct mount *mp);
void p9_client_destroy(struct p9_client *clnt);
void p9_client_disconnect(struct p9_client *clnt);
void p9_client_begin_disconnect(struct p9_client *clnt);
struct p9_fid *p9_client_attach(struct p9_client *clnt);
struct p9_fid *p9_client_walk(struct p9_fid *oldfid, uint16_t nwname,
		char **wnames, int clone);
int p9_client_open(struct p9_fid *fid, int mode);
int p9_client_fcreate(struct p9_fid *fid, char *name, uint32_t perm, int mode,
							char *extension);
int p9_client_link(struct p9_fid *fid, struct p9_fid *oldfid, char *newname);
int p9_client_symlink(struct p9_fid *fid, char *name, char *symname, gid_t gid,
							struct p9_qid *qid);
int p9_client_create_dotl(struct p9_fid *ofid, char *name, uint32_t flags, uint32_t mode,
		gid_t gid, struct p9_qid *qid);
int p9_client_clunk(struct p9_fid *fid);
int p9_client_fsync(struct p9_fid *fid, int datasync);
int p9_client_remove(struct p9_fid *fid);
int p9_client_unlinkat(struct p9_fid *dfid, const char *name, int flags);
int p9_client_read(struct p9_fid *fid, uint64_t offset, struct iov_iter *to, int *err);
int p9_client_write(struct p9_fid *fid, uint64_t offset, struct iov_iter *from, int *err);
int p9_client_readdir(struct p9_fid *fid, char *data, uint32_t count, uint64_t offset);
int p9dirent_read(struct p9_client *clnt, char *buf, int len,
		  struct p9_dirent *dirent);
struct p9_wstat *p9_client_stat(struct p9_fid *fid);
int p9_client_wstat(struct p9_fid *fid, struct p9_wstat *wst);
int p9_client_setattr(struct p9_fid *fid, struct p9_iattr_dotl *attr);

struct p9_stat_dotl *p9_client_getattr_dotl(struct p9_fid *fid,
							uint64_t request_mask);

int p9_client_mknod_dotl(struct p9_fid *oldfid, char *name, int mode,
			dev_t rdev, gid_t gid, struct p9_qid *);
int p9_client_mkdir_dotl(struct p9_fid *fid, char *name, int mode,
				gid_t gid, struct p9_qid *);
int p9_client_lock_dotl(struct p9_fid *fid, struct p9_flock *flock, uint8_t *status);
int p9_client_getlock_dotl(struct p9_fid *fid, struct p9_getlock *fl);
struct p9_req_t *p9_tag_lookup(struct p9_client *, uint16_t);
void p9_client_cb(struct p9_client *c, struct p9_req_t *req);

int p9_parse_header(struct p9_fcall *, int32_t *, int8_t *, int16_t *, int);
int p9stat_read(struct p9_client *, char *, int, struct p9_wstat *);
void p9stat_free(struct p9_wstat *);

int p9_is_proto_dotu(struct p9_client *clnt);
int p9_is_proto_dotl(struct p9_client *clnt);
struct p9_fid *p9_client_xattrwalk(struct p9_fid *, const char *, uint64_t *);
int p9_client_xattrcreate(struct p9_fid *, const char *, uint64_t, int);
int p9_client_readlink(struct p9_fid *fid, char **target);
int p9_client_detach(struct p9_fid *fid);
int p9_client_version(struct p9_client *c);

#endif /* NET_9P_CLIENT_H */
