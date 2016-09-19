/*
 * net/9p/clnt.c
 *
 * 9P Client API -  We are going to built this a module.
 */


#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/poll.h>
#include <sys/mutex.h>
#include <sys/sched.h>
#include <sys/uio.h>

// ALl local headers move to include and then compile with the include.
#include "../9p.h"
#include "../client.h"
#include "../transport.h"
#include "../protocol.h"



#if  0 
/*
  * Client Option Parsing (code inspired by NFS code)
  *  - a little lazy - parse all client options
  */

enum {
	Opt_msize,
	Opt_trans,
	Opt_legacy,
	Opt_version,
	Opt_err,
};

static const match_table_t tokens = {
	{Opt_msize, "msize=%u"},
	{Opt_legacy, "noextend"},
	{Opt_trans, "trans=%s"},
	{Opt_version, "version=%s"},
	{Opt_err, NULL},
};

#endif // We ll leave it here for now

inline int p9_is_proto_dotl(struct p9_client *clnt)
{
	return clnt->proto_version == p9_proto_2000L;
}

inline int p9_is_proto_dotu(struct p9_client *clnt)
{
	return clnt->proto_version == p9_proto_2000u;
}

/*
 * Some error codes are taken directly from the server replies,
 * make sure they are valid.
 */
static int safe_errno(int err)
{
	if ((err > 0) || (err < -MAX_ERRNO)) {
		p9_debug(P9_DEBUG_ERROR, "Invalid error code %d\n", err);
		return -EPROTO;
	}
	return err;
}


/* Interpret mount option for protocol version */
static int get_protocol_version(char *s)
{
	int version = -EINVAL;

	if (!strcmp(s, "9p2000")) {
		version = p9_proto_legacy;
		p9_debug(P9_DEBUG_9P, "Protocol version: Legacy\n");
	} else if (!strcmp(s, "9p2000.u")) {
		version = p9_proto_2000u;
		p9_debug(P9_DEBUG_9P, "Protocol version: 9P2000.u\n");
	} else if (!strcmp(s, "9p2000.L")) {
		version = p9_proto_2000L;
		p9_debug(P9_DEBUG_9P, "Protocol version: 9P2000.L\n");
	} else
		pr_info("Unknown protocol version %s\n", s);

	return version;
}

/**
 * parse_options - parse mount options into client structure
 * @opts: options string passed from mount
 * @clnt: existing v9fs client information
 *
 * Return 0 upon success, -ERRNO upon failure
 */

static int parse_opts(struct mount  *mp, struct p9_client *clnt)
{
	char *trans;
	int error = 0;

	clnt->proto_version = p9_proto_2000L;
	// WHy is this 8k?
	clnt->msize = 8192;

	// Find only the trans option for now to load that particular func pointers.
	// vfs_getopts is a freebsd kernel function.
    	trans = vfs_getopts(mp->mnt_optnew, "trans", &error);
    	if (error)
        	return (error);

    	clnt->trans_mod = v9fs_get_trans_by_name(trans);
    	if (clnt->trans_mod == NULL) {
            	printf("Could not find request transport: %s\n",s);
            	error = -EINVAL;
           	free(trans, sizeof(*trans));
        }
	return error;
}

static struct p9_fcall *p9_fcall_alloc(int alloc_msize)
{
	struct p9_fcall *fc;
	fc = malloc(sizeof(struct p9_fcall) + alloc_msize);
	if (!fc)
		return NULL;
	fc->capacity = alloc_msize;
	fc->sdata = (char *) fc + sizeof(struct p9_fcall);
	return fc;
}


// call this from close_functions to free up all requests in the pool.
static void p9_free_req(struct p9_client *c, struct p9_req_t *r)
{
	free(r ,sizeof(*r));
}


void complete_upper(req)
{
	// For compiling.
	printf("completion to the upper layers. ");

}
/**
 * p9_client_cb - call back from transport to client
 * c: client state
 * req: request received
 *
 */
void p9_client_cb(struct p9_client *c, struct p9_req_t *req)
{
	
	// Finish the request to upper layers.
	// Copy the information into buffers if needed (FS specific) 
	// Add the request back into the list.
	complete_upper(req);
	bzero(req, sizeof(*req));
	// add it back to the pool.
	SLIST_ADD_TAIL(&c->reqlist, req);

	// one new request added, Check if any threads are sleeping for requests.
	condvar_wakeup(&c->req_cv);
}

/**
 * p9_parse_header - parse header arguments out of a packet
 * @pdu: packet to parse
 * @size: size of packet
 * @type: type of request
 * @tag: tag of packet
 * @rewind: set if we need to rewind offset afterwards
 */

#if 0 // Parse header and these functions are not being used .//
int
p9_parse_header(struct p9_fcall *pdu, int32_t *size, int8_t *type, int16_t *tag,
								int rewind)
{
	int8_t r_type;
	int16_t r_tag;
	int32_t r_size;
	int offset = pdu->offset;
	int err;

	pdu->offset = 0;
	if (pdu->size == 0)
		pdu->size = 7;

	err = p9pdu_readf(pdu, 0, "dbw", &r_size, &r_type, &r_tag);
	if (err)
		goto rewind_and_exit;

	pdu->size = r_size;
	pdu->id = r_type;
	pdu->tag = r_tag;

	p9_debug(P9_DEBUG_9P, "<<< size=%d type: %d tag: %d\n",
		 pdu->size, pdu->id, pdu->tag);

	if (type)
		*type = r_type;
	if (tag)
		*tag = r_tag;
	if (size)
		*size = r_size;

rewind_and_exit:
	if (rewind)
		pdu->offset = offset;
	return err;
}

/**
 * p9_check_errors - check 9p packet for error return and process it
 * @c: current client instance
 * @req: request to parse and check for error conditions
 *
 * returns error code if one is discovered, otherwise returns 0
 *
 * this will have to be more complicated if we have multiple
 * error packet types
 */

static int p9_check_errors(struct p9_client *c, struct p9_req_t *req)
{
	int8_t type;
	int err;
	int ecode;

	err = p9_parse_header(req->rc, NULL, &type, NULL, 0);
	/*
	 * dump the response from server
	 * This should be after check errors which poplulate pdu_fcall.
	 */
	trace_9p_protocol_dump(c, req->rc);
	if (err) {
		p9_debug(P9_DEBUG_ERROR, "couldn't parse header %d\n", err);
		return err;
	}
	if (type != P9_RERROR && type != P9_RLERROR)
		return 0;

	if (!p9_is_proto_dotl(c)) {
		char *ename;
		err = p9pdu_readf(req->rc, c->proto_version, "s?d",
				  &ename, &ecode);
		if (err)
			goto out_err;

		if (p9_is_proto_dotu(c) && ecode < 512)
			err = -ecode;

		if (!err) {
			err = p9_errstr2errno(ename, strlen(ename));

			p9_debug(P9_DEBUG_9P, "<<< RERROR (%d) %s\n",
				 -ecode, ename);
		}
		kfree(ename);
	} else {
		err = p9pdu_readf(req->rc, c->proto_version, "d", &ecode);
		err = -ecode;

		p9_debug(P9_DEBUG_9P, "<<< RLERROR (%d)\n", -ecode);
	}

	return err;

out_err:
	p9_debug(P9_DEBUG_ERROR, "couldn't parse error%d\n", err);

	return err;
}

/**
 * p9_check_zc_errors - check 9p packet for error return and process it
 * @c: current client instance
 * @req: request to parse and check for error conditions
 * @in_hdrlen: Size of response protocol buffer.
 *
 * returns error code if one is discovered, otherwise returns 0
 *
 * this will have to be more complicated if we have multiple
 * error packet types
 */

static int p9_check_zc_errors(struct p9_client *c, struct p9_req_t *req,
			      struct iov_iter *uidata, int in_hdrlen)
{
	int err;
	int ecode;
	int8_t type;
	char *ename = NULL;

	err = p9_parse_header(req->rc, NULL, &type, NULL, 0);
	/*
	 * dump the response from server
	 * This should be after parse_header which poplulate pdu_fcall.
	 */
	trace_9p_protocol_dump(c, req->rc);
	if (err) {
		p9_debug(P9_DEBUG_ERROR, "couldn't parse header %d\n", err);
		return err;
	}

	if (type != P9_RERROR && type != P9_RLERROR)
		return 0;

	if (!p9_is_proto_dotl(c)) {
		/* Error is reported in string format */
		int len;
		/* 7 = header size for RERROR; */
		int inline_len = in_hdrlen - 7;

		len =  req->rc->size - req->rc->offset;
		if (len > (P9_ZC_HDR_SZ - 7)) {
			err = -EFAULT;
			goto out_err;
		}

		ename = &req->rc->sdata[req->rc->offset];
		if (len > inline_len) {
			/* We have error in external buffer */
			err = copy_from_iter(ename + inline_len,
					     len - inline_len, uidata);
			if (err != len - inline_len) {
				err = -EFAULT;
				goto out_err;
			}
		}
		ename = NULL;
		err = p9pdu_readf(req->rc, c->proto_version, "s?d",
				  &ename, &ecode);
		if (err)
			goto out_err;

		if (p9_is_proto_dotu(c) && ecode < 512)
			err = -ecode;

		if (!err) {
			err = p9_errstr2errno(ename, strlen(ename));

			p9_debug(P9_DEBUG_9P, "<<< RERROR (%d) %s\n",
				 -ecode, ename);
		}
		kfree(ename);
	} else {
		err = p9pdu_readf(req->rc, c->proto_version, "d", &ecode);
		err = -ecode;

		p9_debug(P9_DEBUG_9P, "<<< RLERROR (%d)\n", -ecode);
	}
	return err;

out_err:
	p9_debug(P9_DEBUG_ERROR, "couldn't parse error%d\n", err);
	return err;
}
#endif // Parse header fucntions will end here.

static struct p9_req_t *
p9_client_rpc(struct p9_client *c, int8_t type, const char *fmt, ...);

/**
 * p9_client_flush - flush (cancel) a request
 * @c: client state
 * @oldreq: request to cancel
 *
 * This sents a flush for a particular request and links
 * the flush request to the original request.  The current
 * code only supports a single flush request although the protocol
 * allows for multiple flush requests to be sent for a single request.
 *
 */

static int p9_client_flush(struct p9_client *c, struct p9_req_t *oldreq)
{
	struct p9_req_t *req;
	int16_t oldtag;
	int err;

	/*err = p9_parse_header(oldreq->tc, NULL, NULL, &oldtag, 1);
	if (err)
		return err;
	*/ // parse header may not be required.

	p9_debug(P9_DEBUG_9P, ">>> TFLUSH tag %d\n", oldtag);

	req = p9_client_rpc(c, P9_TFLUSH, "w", oldtag);
	if (IS_ERR(req))
		return PTR_ERR(req);

	/*
	 * if we haven't received a response for oldreq,
	 * remove it from the list
	 */
	if (oldreq->status == REQ_STATUS_SENT)
		if (c->trans_mod->cancelled)
			c->trans_mod->cancelled(c, oldreq);

	p9_free_req(c, req);
	return 0;
}

// This will be called from session_init
int
allocator_pool_init(struct p9_client *c)
{
 	// Mallocing a request ??  No pool allocations.
	// Porabbly maintain a list of requests.

	req = malloc(sizeof(*req), M_P9_REQ, M_ZERO|M_WAITOK);
	if (req == NULL) return -ENOMEM;
	if (!req->tc)
		req->tc = p9_fcall_alloc(alloc_msize);
	if (!req->rc)
		req->rc = p9_fcall_alloc(alloc_msize);
	
	if (req->tc == NULL || req->rc == NULL) 
		return -ENOMEM;

	// Add to the head
	SLIST_INSERT_HEAD(&c->reqlist,  req, list);
}

struct p9_client *request_allocator(struct p9_client *c)
{
	struct p9_req_t *req = NULL;

	while ((req = SLIST_FIRST(&c->reqlist)) == NULL) 
	{
		// no more so sleep till someone wakes you up.
		cv_wait(&c->req_cv, &cv->req_lock);
	}
	// unlink it from the list.
	SLIST_REMOVE_HEAD(&c->reqlist, link);	
	// Req shouldnt be NULL as we just woke up otherwise.
	kassert(req != NULL);
       	return req;
}

static struct p9_req_t *p9_client_prepare_req(struct p9_client *c,
					      int8_t type, int req_size,
					      const char *fmt, va_list ap)
{
	int err;
	struct p9_req_t *req;

	p9_debug(P9_DEBUG_MUX, "client %p op %d\n", c, type);

	/* we allow for any status other than disconnected */
	if (c->status == Disconnected)
		return ERR_PTR(-EIO);

	/* if status is begin_disconnected we allow only clunk request */
	if ((c->status == BeginDisconnect) && (type != P9_TCLUNK))
		return ERR_PTR(-EIO);

	// allocate the request.
	req = request_allocator(c, req_size);
	if (req == NULL)
	{
		return NULL;
	}

	/* marshall the data */
	p9pdu_prepare(req->tc, type);
	err = p9pdu_vwritef(req->tc, c->proto_version, fmt, ap);
	if (err)
		goto reterr;
	p9pdu_finalize(c, req->tc);
	return req;
reterr:
	p9_free_req(c, req);
	return ERR_PTR(err);
}

/**
 * p9_client_rpc - issue a request and wait for a response
 * @c: client session
 * @type: type of request
 * @fmt: protocol format string (see protocol.c)
 *
 * Returns request structure (which client must free using p9_free_req)
 */

static struct p9_req_t *
p9_client_rpc(struct p9_client *c, int8_t type, const char *fmt, ...)
{
	va_list ap;
	int sigpending, err;
	unsigned long flags;
	struct p9_req_t *req;

	va_start(ap, fmt);
	// This will get the req . Malloc the request, fill in the fd allocs 
	// and then send the request for the type.
	req = p9_client_prepare_req(c, type, c->msize, fmt, ap);
	va_end(ap);
	if (IS_ERR(req))
		return req;

	err = c->trans_mod->request(c, req);
	if (err < 0) {
		if (err != -ERESTARTSYS && err != -EFAULT)
			c->status = Disconnected;
		goto reterr;
	}
again:
	/* Wait for the response */
	err = wait_event_interruptible(*req->wq,
				       req->status >= REQ_STATUS_RCVD);

	/*
	 * Make sure our req is coherent with regard to updates in other
	 * threads - echoes to wmb() in the callback
	 */
	smp_rmb();

	if ((err == -ERESTARTSYS) && (c->status == Connected)
				  && (type == P9_TFLUSH)) {
		sigpending = 1;
		clear_thread_flag(TIF_SIGPENDING);
		goto again;
	}

	if (req->status == REQ_STATUS_ERROR) {
		p9_debug(P9_DEBUG_ERROR, "req_status error %d\n", req->t_err);
		err = req->t_err;
	}
	if ((err == -ERESTARTSYS) && (c->status == Connected)) {
		p9_debug(P9_DEBUG_MUX, "flushing\n");
		sigpending = 1;
		clear_thread_flag(TIF_SIGPENDING);

		if (c->trans_mod->cancel(c, req))
			p9_client_flush(c, req);

		/* if we received the response anyway, don't signal error */
		if (req->status == REQ_STATUS_RCVD)
			err = 0;
	}
	if (sigpending) {
		mtx_lock_spin_irqsave(&current->sighand->siglock, flags);
		recalc_sigpending();
		mtx_unlock_spin_irqrestore(&current->sighand->siglock, flags);
	}
	if (err < 0)
		goto reterr;

	err = p9_check_errors(c, req);
	trace_9p_client_res(c, type, req->rc->tag, err);
	if (!err)
		return req;
reterr:
	p9_free_req(c, req);
	return ERR_PTR(safe_errno(err));
}

/**
 * p9_client_zc_rpc - issue a request and wait for a response
 * @c: client session
 * @type: type of request
 * @uidata: destination for zero copy read
 * @uodata: source for zero copy write
 * @inlen: read buffer size
 * @olen: write buffer size
 * @hdrlen: reader header size, This is the size of response protocol data
 * @fmt: protocol format string (see protocol.c)
 *
 * Returns request structure (which client must free using p9_free_req)
 */
static struct p9_req_t *p9_client_zc_rpc(struct p9_client *c, int8_t type,
					 struct iov_iter *uidata,
					 struct iov_iter *uodata,
					 int inlen, int olen, int in_hdrlen,
					 const char *fmt, ...)
{
	va_list ap;
	int sigpending, err;
	unsigned long flags;
	struct p9_req_t *req;

	va_start(ap, fmt);
	/*
	 * We allocate a inline protocol data of only 4k bytes.
	 * The actual content is passed in zero-copy fashion.
	 */
	req = p9_client_prepare_req(c, type, P9_ZC_HDR_SZ, fmt, ap);
	va_end(ap);
	if (IS_ERR(req))
		return req;

	if (signal_pending(current)) {
		sigpending = 1;
		clear_thread_flag(TIF_SIGPENDING);
	} else
		sigpending = 0;

	err = c->trans_mod->zc_request(c, req, uidata, uodata,
				       inlen, olen, in_hdrlen);
	if (err < 0) {
		if (err == -EIO)
			c->status = Disconnected;
		if (err != -ERESTARTSYS)
			goto reterr;
	}
	if (req->status == REQ_STATUS_ERROR) {
		p9_debug(P9_DEBUG_ERROR, "req_status error %d\n", req->t_err);
		err = req->t_err;
	}
	if ((err == -ERESTARTSYS) && (c->status == Connected)) {
		p9_debug(P9_DEBUG_MUX, "flushing\n");
		sigpending = 1;
		clear_thread_flag(TIF_SIGPENDING);

		if (c->trans_mod->cancel(c, req))
			p9_client_flush(c, req);

		/* if we received the response anyway, don't signal error */
		if (req->status == REQ_STATUS_RCVD)
			err = 0;
	}
	if (sigpending) {
		mtx_lock_spin_irqsave(&current->sighand->siglock, flags);
		recalc_sigpending();
		mtx_unlock_spin_irqrestore(&current->sighand->siglock, flags);
	}
	if (err < 0)
		goto reterr;

	err = p9_check_zc_errors(c, req, uidata, in_hdrlen);
	trace_9p_client_res(c, type, req->rc->tag, err);
	if (!err)
		return req;
reterr:
	p9_free_req(c, req);
	return ERR_PTR(safe_errno(err));
}

static struct p9_fid *p9_fid_create(struct p9_client *clnt)
{
	int ret;
	struct p9_fid *fid;
	unsigned long flags;

	p9_debug(P9_DEBUG_FID, "clnt %p\n", clnt);
	fid = kmalloc(sizeof(struct p9_fid), GFP_KERNEL);
	if (!fid)
		return ERR_PTR(-ENOMEM);

	ret = p9_idpool_get(clnt->fidpool);
	if (ret < 0) {
		ret = -ENOSPC;
		goto error;
	}
	fid->fid = ret;

	memset(&fid->qid, 0, sizeof(struct p9_qid));
	fid->mode = -1;
	fid->uid = current_fsuid();
	fid->clnt = clnt;
	fid->rdir = NULL;
	mtx_lock_spin_irqsave(&clnt->lock, flags);
	list_add(&fid->flist, &clnt->fidlist);
	mtx_unlock_spin_irqrestore(&clnt->lock, flags);

	return fid;

error:
	kfree(fid);
	return ERR_PTR(ret);
}

static void p9_fid_destroy(struct p9_fid *fid)
{
	struct p9_client *clnt;
	unsigned long flags;

	p9_debug(P9_DEBUG_FID, "fid %d\n", fid->fid);
	clnt = fid->clnt;
	p9_idpool_put(fid->fid, clnt->fidpool);
	mtx_lock_spin_irqsave(&clnt->lock, flags);
	list_del(&fid->flist);
	mtx_unlock_spin_irqrestore(&clnt->lock, flags);
	kfree(fid->rdir);
	kfree(fid);
}

static int p9_client_version(struct p9_client *c)
{
	int err = 0;
	struct p9_req_t *req;
	char *version;
	int msize;

	p9_debug(P9_DEBUG_9P, ">>> TVERSION msize %d protocol %d\n",
		 c->msize, c->proto_version);

	switch (c->proto_version) {
	case p9_proto_2000L:
		req = p9_client_rpc(c, P9_TVERSION, "ds",
					c->msize, "9P2000.L");
		break;
	case p9_proto_2000u:
		req = p9_client_rpc(c, P9_TVERSION, "ds",
					c->msize, "9P2000.u");
		break;
	case p9_proto_legacy:
		req = p9_client_rpc(c, P9_TVERSION, "ds",
					c->msize, "9P2000");
		break;
	default:
		return -EINVAL;
	}

	if (IS_ERR(req))
		return PTR_ERR(req);

	err = p9pdu_readf(req->rc, c->proto_version, "ds", &msize, &version);
	if (err) {
		p9_debug(P9_DEBUG_9P, "version error %d\n", err);
		trace_9p_protocol_dump(c, req->rc);
		goto error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RVERSION msize %d %s\n", msize, version);
	if (!strncmp(version, "9P2000.L", 8))
		c->proto_version = p9_proto_2000L;
	else if (!strncmp(version, "9P2000.u", 8))
		c->proto_version = p9_proto_2000u;
	else if (!strncmp(version, "9P2000", 6))
		c->proto_version = p9_proto_legacy;
	else {
		err = -EREMOTEIO;
		goto error;
	}

	if (msize < c->msize)
		c->msize = msize;

error:
	kfree(version);
	p9_free_req(c, req);

	return err;
}

int 
p9_client_create(const char *dev_name, struct mount *mp)
{
	int err = 0;
	struct p9_client *clnt;
	char *client_id;
	struct p9fs_session *p9s;
	p9mp = mp->mnt_data;
	p9s = &p9mp->p9_session;
   
	clnt = malloc(sizeof(struct p9_client));
	if (!clnt)
		goto bail_out;

	p9s->clnt = clnt;
	clnt->trans_mod = NULL;
	clnt->trans = NULL;

	mtx_spin_init(&clnt->lock);
	TAILQ_INIT(&clnt->fidlist);

	err = parse_opts(mp, clnt);
	if (err < 0)
		goto bail_out;

	if (!clnt->trans_mod)
		clnt->trans_mod = v9fs_get_default_trans();

	if (clnt->trans_mod == NULL) {
		err = -EPROTONOSUPPORT;
		p9_debug(P9_DEBUG_ERROR,
			 "No transport defined or default transport\n");
		goto bail_out;
	}
	
	// Init the request_pool .
	allocator_pool_init(clnt);

	clnt->fidpool = p9_idpool_create();
	if (!(clnt->fidpool)) {
		err = -ENOMEM;
		goto bail_out;
	}

	p9_debug(P9_DEBUG_MUX, "clnt %p trans %p msize %d protocol %d\n",
		 clnt, clnt->trans_mod, clnt->msize, clnt->proto_version);

	err = clnt->trans_mod->create(clnt, dev_name, options);
	if (err) {
		err = -NOCLIENT_ERROR // add sometghing here.
		goto bail_out;
	}
	if (clnt->msize > clnt->trans_mod->maxsize)
		clnt->msize = clnt->trans_mod->maxsize;

	err = p9_client_version(clnt);
	if (err)
		goto bail_out;

	return err;

bailout:
	if (err == _NOCLIENT_ERROR) 
	clnt->trans_mod->close(clnt);
	if (clnt)
	free(clnt, sizeof(*clnt));
	
	return err;
}

void p9_client_destroy(struct p9_client *clnt)
{
	struct p9_fid *fid, *fidptr;

	p9_debug(P9_DEBUG_MUX, "clnt %p\n", clnt);

	if (clnt->trans_mod)
		clnt->trans_mod->close(clnt);

	v9fs_put_trans(clnt->trans_mod);

	list_for_each_entry_safe(fid, fidptr, &clnt->fidlist, flist) {
		pr_info("Found fid %d not clunked\n", fid->fid);
		p9_fid_destroy(fid);
	}

	if (clnt->fidpool)
		p9_idpool_destroy(clnt->fidpool);

	p9_tag_cleanup(clnt);

	kfree(clnt);
}

void p9_client_disconnect(struct p9_client *clnt)
{
	p9_debug(P9_DEBUG_9P, "clnt %p\n", clnt);
	clnt->status = Disconnected;
}

void p9_client_begin_disconnect(struct p9_client *clnt)
{
	p9_debug(P9_DEBUG_9P, "clnt %p\n", clnt);
	clnt->status = BeginDisconnect;
}

struct p9_fid *p9_client_attach(struct p9_client *clnt, struct p9_fid *afid,
	char *uname, kuid_t n_uname, char *aname)
{
	int err = 0;
	struct p9_req_t *req;
	struct p9_fid *fid;
	struct p9_qid qid;


	p9_debug(P9_DEBUG_9P, ">>> TATTACH afid %d uname %s aname %s\n",
		 afid ? afid->fid : -1, uname, aname);
	fid = p9_fid_create(clnt);
	if (IS_ERR(fid)) {
		err = PTR_ERR(fid);
		fid = NULL;
		goto error;
	}
	fid->uid = n_uname;

	req = p9_client_rpc(clnt, P9_TATTACH, "ddss?u", fid->fid,
			afid ? afid->fid : P9_NOFID, uname, aname, n_uname);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "Q", &qid);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		p9_free_req(clnt, req);
		goto error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RATTACH qid %x.%llx.%x\n",
		 qid.type, (unsigned long long)qid.path, qid.version);

	memmove(&fid->qid, &qid, sizeof(struct p9_qid));

	p9_free_req(clnt, req);
	return fid;

error:
	if (fid)
		p9_fid_destroy(fid);
	return ERR_PTR(err);
}

struct p9_fid *p9_client_walk(struct p9_fid *oldfid, uint16_t nwname,
		char **wnames, int clone)
{
	int err;
	struct p9_client *clnt;
	struct p9_fid *fid;
	struct p9_qid *wqids;
	struct p9_req_t *req;
	uint16_t nwqids, count;

	err = 0;
	wqids = NULL;
	clnt = oldfid->clnt;
	if (clone) {
		fid = p9_fid_create(clnt);
		if (IS_ERR(fid)) {
			err = PTR_ERR(fid);
			fid = NULL;
			goto error;
		}

		fid->uid = oldfid->uid;
	} else
		fid = oldfid;


	p9_debug(P9_DEBUG_9P, ">>> TWALK fids %d,%d nwname %ud wname[0] %s\n",
		 oldfid->fid, fid->fid, nwname, wnames ? wnames[0] : NULL);

	req = p9_client_rpc(clnt, P9_TWALK, "ddT", oldfid->fid, fid->fid,
								nwname, wnames);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "R", &nwqids, &wqids);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		p9_free_req(clnt, req);
		goto clunk_fid;
	}
	p9_free_req(clnt, req);

	p9_debug(P9_DEBUG_9P, "<<< RWALK nwqid %d:\n", nwqids);

	if (nwqids != nwname) {
		err = -ENOENT;
		goto clunk_fid;
	}

	for (count = 0; count < nwqids; count++)
		p9_debug(P9_DEBUG_9P, "<<<     [%d] %x.%llx.%x\n",
			count, wqids[count].type,
			(unsigned long long)wqids[count].path,
			wqids[count].version);

	if (nwname)
		memmove(&fid->qid, &wqids[nwqids - 1], sizeof(struct p9_qid));
	else
		fid->qid = oldfid->qid;

	kfree(wqids);
	return fid;

clunk_fid:
	kfree(wqids);
	p9_client_clunk(fid);
	fid = NULL;

error:
	if (fid && (fid != oldfid))
		p9_fid_destroy(fid);

	return ERR_PTR(err);
}

int p9_client_open(struct p9_fid *fid, int mode)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;
	struct p9_qid qid;
	int iounit;

	clnt = fid->clnt;
	p9_debug(P9_DEBUG_9P, ">>> %s fid %d mode %d\n",
		p9_is_proto_dotl(clnt) ? "TLOPEN" : "TOPEN", fid->fid, mode);
	err = 0;

	if (fid->mode != -1)
		return -EINVAL;

	if (p9_is_proto_dotl(clnt))
		req = p9_client_rpc(clnt, P9_TLOPEN, "dd", fid->fid, mode);
	else
		req = p9_client_rpc(clnt, P9_TOPEN, "db", fid->fid, mode);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "Qd", &qid, &iounit);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		goto free_and_error;
	}

	p9_debug(P9_DEBUG_9P, "<<< %s qid %x.%llx.%x iounit %x\n",
		p9_is_proto_dotl(clnt) ? "RLOPEN" : "ROPEN",  qid.type,
		(unsigned long long)qid.path, qid.version, iounit);

	fid->mode = mode;
	fid->iounit = iounit;

free_and_error:
	p9_free_req(clnt, req);
error:
	return err;
}

int p9_client_create_dotl(struct p9_fid *ofid, char *name, u32 flags, u32 mode,
		kgid_t gid, struct p9_qid *qid)
{
	int err = 0;
	struct p9_client *clnt;
	struct p9_req_t *req;
	int iounit;

	p9_debug(P9_DEBUG_9P,
			">>> TLCREATE fid %d name %s flags %d mode %d gid %d\n",
			ofid->fid, name, flags, mode,
		 	from_kgid(&init_user_ns, gid));
	clnt = ofid->clnt;

	if (ofid->mode != -1)
		return -EINVAL;

	req = p9_client_rpc(clnt, P9_TLCREATE, "dsddg", ofid->fid, name, flags,
			mode, gid);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "Qd", qid, &iounit);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		goto free_and_error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RLCREATE qid %x.%llx.%x iounit %x\n",
			qid->type,
			(unsigned long long)qid->path,
			qid->version, iounit);

	ofid->mode = mode;
	ofid->iounit = iounit;

free_and_error:
	p9_free_req(clnt, req);
error:
	return err;
}

int p9_client_fcreate(struct p9_fid *fid, char *name, u32 perm, int mode,
		     char *extension)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;
	struct p9_qid qid;
	int iounit;

	p9_debug(P9_DEBUG_9P, ">>> TCREATE fid %d name %s perm %d mode %d\n",
						fid->fid, name, perm, mode);
	err = 0;
	clnt = fid->clnt;

	if (fid->mode != -1)
		return -EINVAL;

	req = p9_client_rpc(clnt, P9_TCREATE, "dsdb?s", fid->fid, name, perm,
				mode, extension);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "Qd", &qid, &iounit);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		goto free_and_error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RCREATE qid %x.%llx.%x iounit %x\n",
				qid.type,
				(unsigned long long)qid.path,
				qid.version, iounit);

	fid->mode = mode;
	fid->iounit = iounit;

free_and_error:
	p9_free_req(clnt, req);
error:
	return err;
}

int p9_client_symlink(struct p9_fid *dfid, char *name, char *symtgt, kgid_t gid,
		struct p9_qid *qid)
{
	int err = 0;
	struct p9_client *clnt;
	struct p9_req_t *req;

	p9_debug(P9_DEBUG_9P, ">>> TSYMLINK dfid %d name %s  symtgt %s\n",
			dfid->fid, name, symtgt);
	clnt = dfid->clnt;

	req = p9_client_rpc(clnt, P9_TSYMLINK, "dssg", dfid->fid, name, symtgt,
			gid);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "Q", qid);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		goto free_and_error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RSYMLINK qid %x.%llx.%x\n",
			qid->type, (unsigned long long)qid->path, qid->version);

free_and_error:
	p9_free_req(clnt, req);
error:
	return err;
}

int p9_client_link(struct p9_fid *dfid, struct p9_fid *oldfid, char *newname)
{
	struct p9_client *clnt;
	struct p9_req_t *req;

	p9_debug(P9_DEBUG_9P, ">>> TLINK dfid %d oldfid %d newname %s\n",
			dfid->fid, oldfid->fid, newname);
	clnt = dfid->clnt;
	req = p9_client_rpc(clnt, P9_TLINK, "dds", dfid->fid, oldfid->fid,
			newname);
	if (IS_ERR(req))
		return PTR_ERR(req);

	p9_debug(P9_DEBUG_9P, "<<< RLINK\n");
	p9_free_req(clnt, req);
	return 0;
}

int p9_client_fsync(struct p9_fid *fid, int datasync)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;

	p9_debug(P9_DEBUG_9P, ">>> TFSYNC fid %d datasync:%d\n",
			fid->fid, datasync);
	err = 0;
	clnt = fid->clnt;

	req = p9_client_rpc(clnt, P9_TFSYNC, "dd", fid->fid, datasync);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RFSYNC fid %d\n", fid->fid);

	p9_free_req(clnt, req);

error:
	return err;
}

int p9_client_clunk(struct p9_fid *fid)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;
	int retries = 0;

	if (!fid) {
		pr_warn("%s (%d): Trying to clunk with NULL fid\n",
			__func__, task_pid_nr(current));
		dump_stack();
		return 0;
	}

again:
	p9_debug(P9_DEBUG_9P, ">>> TCLUNK fid %d (try %d)\n", fid->fid,
								retries);
	err = 0;
	clnt = fid->clnt;

	req = p9_client_rpc(clnt, P9_TCLUNK, "d", fid->fid);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RCLUNK fid %d\n", fid->fid);

	p9_free_req(clnt, req);
error:
	/*
	 * Fid is not valid even after a failed clunk
	 * If interrupted, retry once then give up and
	 * leak fid until umount.
	 */
	if (err == -ERESTARTSYS) {
		if (retries++ == 0)
			goto again;
	} else
		p9_fid_destroy(fid);
	return err;
}

int p9_client_remove(struct p9_fid *fid)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;

	p9_debug(P9_DEBUG_9P, ">>> TREMOVE fid %d\n", fid->fid);
	err = 0;
	clnt = fid->clnt;

	req = p9_client_rpc(clnt, P9_TREMOVE, "d", fid->fid);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RREMOVE fid %d\n", fid->fid);

	p9_free_req(clnt, req);
error:
	if (err == -ERESTARTSYS)
		p9_client_clunk(fid);
	else
		p9_fid_destroy(fid);
	return err;
}

int p9_client_unlinkat(struct p9_fid *dfid, const char *name, int flags)
{
	int err = 0;
	struct p9_req_t *req;
	struct p9_client *clnt;

	p9_debug(P9_DEBUG_9P, ">>> TUNLINKAT fid %d %s %d\n",
		   dfid->fid, name, flags);

	clnt = dfid->clnt;
	req = p9_client_rpc(clnt, P9_TUNLINKAT, "dsd", dfid->fid, name, flags);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}
	p9_debug(P9_DEBUG_9P, "<<< RUNLINKAT fid %d %s\n", dfid->fid, name);

	p9_free_req(clnt, req);
error:
	return err;
}

int
p9_client_read(struct p9_fid *fid, u64 offset, struct iov_iter *to, int *err)
{
	struct p9_client *clnt = fid->clnt;
	struct p9_req_t *req;
	int total = 0;
	*err = 0;

	p9_debug(P9_DEBUG_9P, ">>> TREAD fid %d offset %llu %d\n",
		   fid->fid, (unsigned long long) offset, (int)iov_iter_count(to));

	while (iov_iter_count(to)) {
		int count = iov_iter_count(to);
		int rsize, non_zc = 0;
		char *dataptr;
			
		rsize = fid->iounit;
		if (!rsize || rsize > clnt->msize-P9_IOHDRSZ)
			rsize = clnt->msize - P9_IOHDRSZ;

		if (count < rsize)
			rsize = count;

		/* Don't bother zerocopy for small IO (< 1024) */
		if (clnt->trans_mod->zc_request && rsize > 1024) {
			/*
			 * response header len is 11
			 * PDU Header(7) + IO Size (4)
			 */
			req = p9_client_zc_rpc(clnt, P9_TREAD, to, NULL, rsize,
					       0, 11, "dqd", fid->fid,
					       offset, rsize);
		} else {
			non_zc = 1;
			req = p9_client_rpc(clnt, P9_TREAD, "dqd", fid->fid, offset,
					    rsize);
		}
		if (IS_ERR(req)) {
			*err = PTR_ERR(req);
			break;
		}

		*err = p9pdu_readf(req->rc, clnt->proto_version,
				   "D", &count, &dataptr);
		if (*err) {
			trace_9p_protocol_dump(clnt, req->rc);
			p9_free_req(clnt, req);
			break;
		}
		if (rsize < count) {
			pr_err("bogus RREAD count (%d > %d)\n", count, rsize);
			count = rsize;
		}

		p9_debug(P9_DEBUG_9P, "<<< RREAD count %d\n", count);
		if (!count) {
			p9_free_req(clnt, req);
			break;
		}

		if (non_zc) {
			int n = copy_to_iter(dataptr, count, to);
			total += n;
			offset += n;
			if (n != count) {
				*err = -EFAULT;
				p9_free_req(clnt, req);
				break;
			}
		} else {
			iov_iter_advance(to, count);
			total += count;
			offset += count;
		}
		p9_free_req(clnt, req);
	}
	return total;
}

int
p9_client_write(struct p9_fid *fid, u64 offset, struct iov_iter *from, int *err)
{
	struct p9_client *clnt = fid->clnt;
	struct p9_req_t *req;
	int total = 0;
	*err = 0;

	p9_debug(P9_DEBUG_9P, ">>> TWRITE fid %d offset %llu count %zd\n",
				fid->fid, (unsigned long long) offset,
				iov_iter_count(from));

	while (iov_iter_count(from)) {
		int count = iov_iter_count(from);
		int rsize = fid->iounit;
		if (!rsize || rsize > clnt->msize-P9_IOHDRSZ)
			rsize = clnt->msize - P9_IOHDRSZ;

		if (count < rsize)
			rsize = count;

		/* Don't bother zerocopy for small IO (< 1024) */
		if (clnt->trans_mod->zc_request && rsize > 1024) {
			req = p9_client_zc_rpc(clnt, P9_TWRITE, NULL, from, 0,
					       rsize, P9_ZC_HDR_SZ, "dqd",
					       fid->fid, offset, rsize);
		} else {
			req = p9_client_rpc(clnt, P9_TWRITE, "dqV", fid->fid,
						    offset, rsize, from);
		}
		if (IS_ERR(req)) {
			*err = PTR_ERR(req);
			break;
		}

		*err = p9pdu_readf(req->rc, clnt->proto_version, "d", &count);
		if (*err) {
			trace_9p_protocol_dump(clnt, req->rc);
			p9_free_req(clnt, req);
			break;
		}
		if (rsize < count) {
			pr_err("bogus RWRITE count (%d > %d)\n", count, rsize);
			count = rsize;
		}

		p9_debug(P9_DEBUG_9P, "<<< RWRITE count %d\n", count);

		p9_free_req(clnt, req);
		iov_iter_advance(from, count);
		total += count;
		offset += count;
	}
	return total;
}

struct p9_wstat *p9_client_stat(struct p9_fid *fid)
{
	int err;
	struct p9_client *clnt;
	struct p9_wstat *ret = kmalloc(sizeof(struct p9_wstat), GFP_KERNEL);
	struct p9_req_t *req;
	u16 ignored;

	p9_debug(P9_DEBUG_9P, ">>> TSTAT fid %d\n", fid->fid);

	if (!ret)
		return ERR_PTR(-ENOMEM);

	err = 0;
	clnt = fid->clnt;

	req = p9_client_rpc(clnt, P9_TSTAT, "d", fid->fid);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "wS", &ignored, ret);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		p9_free_req(clnt, req);
		goto error;
	}

	p9_debug(P9_DEBUG_9P,
		"<<< RSTAT sz=%x type=%x dev=%x qid=%x.%llx.%x\n"
		"<<<    mode=%8.8x atime=%8.8x mtime=%8.8x length=%llx\n"
		"<<<    name=%s uid=%s gid=%s muid=%s extension=(%s)\n"
		"<<<    uid=%d gid=%d n_muid=%d\n",
		ret->size, ret->type, ret->dev, ret->qid.type,
		(unsigned long long)ret->qid.path, ret->qid.version, ret->mode,
		ret->atime, ret->mtime, (unsigned long long)ret->length,
		ret->name, ret->uid, ret->gid, ret->muid, ret->extension,
		from_kuid(&init_user_ns, ret->n_uid),
		from_kgid(&init_user_ns, ret->n_gid),
		from_kuid(&init_user_ns, ret->n_muid));

	p9_free_req(clnt, req);
	return ret;

error:
	kfree(ret);
	return ERR_PTR(err);
}

struct p9_stat_dotl *p9_client_getattr_dotl(struct p9_fid *fid,
							u64 request_mask)
{
	int err;
	struct p9_client *clnt;
	struct p9_stat_dotl *ret = kmalloc(sizeof(struct p9_stat_dotl),
								GFP_KERNEL);
	struct p9_req_t *req;

	p9_debug(P9_DEBUG_9P, ">>> TGETATTR fid %d, request_mask %lld\n",
							fid->fid, request_mask);

	if (!ret)
		return ERR_PTR(-ENOMEM);

	err = 0;
	clnt = fid->clnt;

	req = p9_client_rpc(clnt, P9_TGETATTR, "dq", fid->fid, request_mask);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "A", ret);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		p9_free_req(clnt, req);
		goto error;
	}

	p9_debug(P9_DEBUG_9P,
		"<<< RGETATTR st_result_mask=%lld\n"
		"<<< qid=%x.%llx.%x\n"
		"<<< st_mode=%8.8x st_nlink=%llu\n"
		"<<< st_uid=%d st_gid=%d\n"
		"<<< st_rdev=%llx st_size=%llx st_blksize=%llu st_blocks=%llu\n"
		"<<< st_atime_sec=%lld st_atime_nsec=%lld\n"
		"<<< st_mtime_sec=%lld st_mtime_nsec=%lld\n"
		"<<< st_ctime_sec=%lld st_ctime_nsec=%lld\n"
		"<<< st_btime_sec=%lld st_btime_nsec=%lld\n"
		"<<< st_gen=%lld st_data_version=%lld",
		ret->st_result_mask, ret->qid.type, ret->qid.path,
		ret->qid.version, ret->st_mode, ret->st_nlink,
		from_kuid(&init_user_ns, ret->st_uid),
		from_kgid(&init_user_ns, ret->st_gid),
		ret->st_rdev, ret->st_size, ret->st_blksize,
		ret->st_blocks, ret->st_atime_sec, ret->st_atime_nsec,
		ret->st_mtime_sec, ret->st_mtime_nsec, ret->st_ctime_sec,
		ret->st_ctime_nsec, ret->st_btime_sec, ret->st_btime_nsec,
		ret->st_gen, ret->st_data_version);

	p9_free_req(clnt, req);
	return ret;

error:
	kfree(ret);
	return ERR_PTR(err);
}

static int p9_client_statsize(struct p9_wstat *wst, int proto_version)
{
	int ret;

	/* NOTE: size shouldn't include its own length */
	/* size[2] type[2] dev[4] qid[13] */
	/* mode[4] atime[4] mtime[4] length[8]*/
	/* name[s] uid[s] gid[s] muid[s] */
	ret = 2+4+13+4+4+4+8+2+2+2+2;

	if (wst->name)
		ret += strlen(wst->name);
	if (wst->uid)
		ret += strlen(wst->uid);
	if (wst->gid)
		ret += strlen(wst->gid);
	if (wst->muid)
		ret += strlen(wst->muid);

	if ((proto_version == p9_proto_2000u) ||
		(proto_version == p9_proto_2000L)) {
		ret += 2+4+4+4;	/* extension[s] n_uid[4] n_gid[4] n_muid[4] */
		if (wst->extension)
			ret += strlen(wst->extension);
	}

	return ret;
}

int p9_client_wstat(struct p9_fid *fid, struct p9_wstat *wst)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	err = 0;
	clnt = fid->clnt;
	wst->size = p9_client_statsize(wst, clnt->proto_version);
	p9_debug(P9_DEBUG_9P, ">>> TWSTAT fid %d\n", fid->fid);
	p9_debug(P9_DEBUG_9P,
		"     sz=%x type=%x dev=%x qid=%x.%llx.%x\n"
		"     mode=%8.8x atime=%8.8x mtime=%8.8x length=%llx\n"
		"     name=%s uid=%s gid=%s muid=%s extension=(%s)\n"
		"     uid=%d gid=%d n_muid=%d\n",
		wst->size, wst->type, wst->dev, wst->qid.type,
		(unsigned long long)wst->qid.path, wst->qid.version, wst->mode,
		wst->atime, wst->mtime, (unsigned long long)wst->length,
		wst->name, wst->uid, wst->gid, wst->muid, wst->extension,
		from_kuid(&init_user_ns, wst->n_uid),
		from_kgid(&init_user_ns, wst->n_gid),
		from_kuid(&init_user_ns, wst->n_muid));

	req = p9_client_rpc(clnt, P9_TWSTAT, "dwS", fid->fid, wst->size+2, wst);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RWSTAT fid %d\n", fid->fid);

	p9_free_req(clnt, req);
error:
	return err;
}

int p9_client_setattr(struct p9_fid *fid, struct p9_iattr_dotl *p9attr)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	err = 0;
	clnt = fid->clnt;
	p9_debug(P9_DEBUG_9P, ">>> TSETATTR fid %d\n", fid->fid);
	p9_debug(P9_DEBUG_9P,
		"    valid=%x mode=%x uid=%d gid=%d size=%lld\n"
		"    atime_sec=%lld atime_nsec=%lld\n"
		"    mtime_sec=%lld mtime_nsec=%lld\n",
		p9attr->valid, p9attr->mode,
		from_kuid(&init_user_ns, p9attr->uid),
		from_kgid(&init_user_ns, p9attr->gid),
		p9attr->size, p9attr->atime_sec, p9attr->atime_nsec,
		p9attr->mtime_sec, p9attr->mtime_nsec);

	req = p9_client_rpc(clnt, P9_TSETATTR, "dI", fid->fid, p9attr);

	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}
	p9_debug(P9_DEBUG_9P, "<<< RSETATTR fid %d\n", fid->fid);
	p9_free_req(clnt, req);
error:
	return err;
}

int p9_client_statfs(struct p9_fid *fid, struct p9_rstatfs *sb)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	err = 0;
	clnt = fid->clnt;

	p9_debug(P9_DEBUG_9P, ">>> TSTATFS fid %d\n", fid->fid);

	req = p9_client_rpc(clnt, P9_TSTATFS, "d", fid->fid);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "ddqqqqqqd", &sb->type,
		&sb->bsize, &sb->blocks, &sb->bfree, &sb->bavail,
		&sb->files, &sb->ffree, &sb->fsid, &sb->namelen);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		p9_free_req(clnt, req);
		goto error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RSTATFS fid %d type 0x%lx bsize %ld "
		"blocks %llu bfree %llu bavail %llu files %llu ffree %llu "
		"fsid %llu namelen %ld\n",
		fid->fid, (long unsigned int)sb->type, (long int)sb->bsize,
		sb->blocks, sb->bfree, sb->bavail, sb->files,  sb->ffree,
		sb->fsid, (long int)sb->namelen);

	p9_free_req(clnt, req);
error:
	return err;
}

int p9_client_rename(struct p9_fid *fid,
		     struct p9_fid *newdirfid, const char *name)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	err = 0;
	clnt = fid->clnt;

	p9_debug(P9_DEBUG_9P, ">>> TRENAME fid %d newdirfid %d name %s\n",
			fid->fid, newdirfid->fid, name);

	req = p9_client_rpc(clnt, P9_TRENAME, "dds", fid->fid,
			newdirfid->fid, name);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RRENAME fid %d\n", fid->fid);

	p9_free_req(clnt, req);
error:
	return err;
}

int p9_client_renameat(struct p9_fid *olddirfid, const char *old_name,
		       struct p9_fid *newdirfid, const char *new_name)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	err = 0;
	clnt = olddirfid->clnt;

	p9_debug(P9_DEBUG_9P, ">>> TRENAMEAT olddirfid %d old name %s"
		   " newdirfid %d new name %s\n", olddirfid->fid, old_name,
		   newdirfid->fid, new_name);

	req = p9_client_rpc(clnt, P9_TRENAMEAT, "dsds", olddirfid->fid,
			    old_name, newdirfid->fid, new_name);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RRENAMEAT newdirfid %d new name %s\n",
		   newdirfid->fid, new_name);

	p9_free_req(clnt, req);
error:
	return err;
}

/*
 * An xattrwalk without @attr_name gives the fid for the lisxattr namespace
 */
struct p9_fid *p9_client_xattrwalk(struct p9_fid *file_fid,
				const char *attr_name, u64 *attr_size)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;
	struct p9_fid *attr_fid;

	err = 0;
	clnt = file_fid->clnt;
	attr_fid = p9_fid_create(clnt);
	if (IS_ERR(attr_fid)) {
		err = PTR_ERR(attr_fid);
		attr_fid = NULL;
		goto error;
	}
	p9_debug(P9_DEBUG_9P,
		">>> TXATTRWALK file_fid %d, attr_fid %d name %s\n",
		file_fid->fid, attr_fid->fid, attr_name);

	req = p9_client_rpc(clnt, P9_TXATTRWALK, "dds",
			file_fid->fid, attr_fid->fid, attr_name);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}
	err = p9pdu_readf(req->rc, clnt->proto_version, "q", attr_size);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		p9_free_req(clnt, req);
		goto clunk_fid;
	}
	p9_free_req(clnt, req);
	p9_debug(P9_DEBUG_9P, "<<<  RXATTRWALK fid %d size %llu\n",
		attr_fid->fid, *attr_size);
	return attr_fid;
clunk_fid:
	p9_client_clunk(attr_fid);
	attr_fid = NULL;
error:
	if (attr_fid && (attr_fid != file_fid))
		p9_fid_destroy(attr_fid);

	return ERR_PTR(err);
}

int p9_client_xattrcreate(struct p9_fid *fid, const char *name,
			u64 attr_size, int flags)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	p9_debug(P9_DEBUG_9P,
		">>> TXATTRCREATE fid %d name  %s size %lld flag %d\n",
		fid->fid, name, (long long)attr_size, flags);
	err = 0;
	clnt = fid->clnt;
	req = p9_client_rpc(clnt, P9_TXATTRCREATE, "dsqd",
			fid->fid, name, attr_size, flags);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}
	p9_debug(P9_DEBUG_9P, "<<< RXATTRCREATE fid %d\n", fid->fid);
	p9_free_req(clnt, req);
error:
	return err;
}

int p9_client_readdir(struct p9_fid *fid, char *data, u32 count, u64 offset)
{
	int err, rsize, non_zc = 0;
	struct p9_client *clnt;
	struct p9_req_t *req;
	char *dataptr;
	struct kvec kv = {.iov_base = data, .iov_len = count};
	struct iov_iter to;

	iov_iter_kvec(&to, READ | ITER_KVEC, &kv, 1, count);

	p9_debug(P9_DEBUG_9P, ">>> TREADDIR fid %d offset %llu count %d\n",
				fid->fid, (unsigned long long) offset, count);

	err = 0;
	clnt = fid->clnt;

	rsize = fid->iounit;
	if (!rsize || rsize > clnt->msize-P9_READDIRHDRSZ)
		rsize = clnt->msize - P9_READDIRHDRSZ;

	if (count < rsize)
		rsize = count;

	/* Don't bother zerocopy for small IO (< 1024) */
	if (clnt->trans_mod->zc_request && rsize > 1024) {
		/*
		 * response header len is 11
		 * PDU Header(7) + IO Size (4)
		 */
		req = p9_client_zc_rpc(clnt, P9_TREADDIR, &to, NULL, rsize, 0,
				       11, "dqd", fid->fid, offset, rsize);
	} else {
		non_zc = 1;
		req = p9_client_rpc(clnt, P9_TREADDIR, "dqd", fid->fid,
				    offset, rsize);
	}
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto error;
	}

	err = p9pdu_readf(req->rc, clnt->proto_version, "D", &count, &dataptr);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		goto free_and_error;
	}

	p9_debug(P9_DEBUG_9P, "<<< RREADDIR count %d\n", count);

	if (non_zc)
		memmove(data, dataptr, count);

	p9_free_req(clnt, req);
	return count;

free_and_error:
	p9_free_req(clnt, req);
error:
	return err;
}

int p9_client_mknod_dotl(struct p9_fid *fid, char *name, int mode,
			dev_t rdev, kgid_t gid, struct p9_qid *qid)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;

	err = 0;
	clnt = fid->clnt;
	p9_debug(P9_DEBUG_9P, ">>> TMKNOD fid %d name %s mode %d major %d "
		"minor %d\n", fid->fid, name, mode, MAJOR(rdev), MINOR(rdev));
	req = p9_client_rpc(clnt, P9_TMKNOD, "dsdddg", fid->fid, name, mode,
		MAJOR(rdev), MINOR(rdev), gid);
	if (IS_ERR(req))
		return PTR_ERR(req);

	err = p9pdu_readf(req->rc, clnt->proto_version, "Q", qid);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		goto error;
	}
	p9_debug(P9_DEBUG_9P, "<<< RMKNOD qid %x.%llx.%x\n", qid->type,
				(unsigned long long)qid->path, qid->version);

error:
	p9_free_req(clnt, req);
	return err;

}

int p9_client_mkdir_dotl(struct p9_fid *fid, char *name, int mode,
				kgid_t gid, struct p9_qid *qid)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;

	err = 0;
	clnt = fid->clnt;
	p9_debug(P9_DEBUG_9P, ">>> TMKDIR fid %d name %s mode %d gid %d\n",
		 fid->fid, name, mode, from_kgid(&init_user_ns, gid));
	req = p9_client_rpc(clnt, P9_TMKDIR, "dsdg", fid->fid, name, mode,
		gid);
	if (IS_ERR(req))
		return PTR_ERR(req);

	err = p9pdu_readf(req->rc, clnt->proto_version, "Q", qid);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		goto error;
	}
	p9_debug(P9_DEBUG_9P, "<<< RMKDIR qid %x.%llx.%x\n", qid->type,
				(unsigned long long)qid->path, qid->version);

error:
	p9_free_req(clnt, req);
	return err;

}

int p9_client_lock_dotl(struct p9_fid *fid, struct p9_flock *flock, u8 *status)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;

	err = 0;
	clnt = fid->clnt;
	p9_debug(P9_DEBUG_9P, ">>> TLOCK fid %d type %i flags %d "
			"start %lld length %lld proc_id %d client_id %s\n",
			fid->fid, flock->type, flock->flags, flock->start,
			flock->length, flock->proc_id, flock->client_id);

	req = p9_client_rpc(clnt, P9_TLOCK, "dbdqqds", fid->fid, flock->type,
				flock->flags, flock->start, flock->length,
					flock->proc_id, flock->client_id);

	if (IS_ERR(req))
		return PTR_ERR(req);

	err = p9pdu_readf(req->rc, clnt->proto_version, "b", status);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		goto error;
	}
	p9_debug(P9_DEBUG_9P, "<<< RLOCK status %i\n", *status);
error:
	p9_free_req(clnt, req);
	return err;

}

int p9_client_getlock_dotl(struct p9_fid *fid, struct p9_getlock *glock)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;

	err = 0;
	clnt = fid->clnt;
	p9_debug(P9_DEBUG_9P, ">>> TGETLOCK fid %d, type %i start %lld "
		"length %lld proc_id %d client_id %s\n", fid->fid, glock->type,
		glock->start, glock->length, glock->proc_id, glock->client_id);

	req = p9_client_rpc(clnt, P9_TGETLOCK, "dbqqds", fid->fid,  glock->type,
		glock->start, glock->length, glock->proc_id, glock->client_id);

	if (IS_ERR(req))
		return PTR_ERR(req);

	err = p9pdu_readf(req->rc, clnt->proto_version, "bqqds", &glock->type,
			&glock->start, &glock->length, &glock->proc_id,
			&glock->client_id);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		goto error;
	}
	p9_debug(P9_DEBUG_9P, "<<< RGETLOCK type %i start %lld length %lld "
		"proc_id %d client_id %s\n", glock->type, glock->start,
		glock->length, glock->proc_id, glock->client_id);
error:
	p9_free_req(clnt, req);
	return err;
}

//Readlink 
int p9_client_readlink(struct p9_fid *fid, char **target)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;

	err = 0;
	clnt = fid->clnt;
	p9_debug(P9_DEBUG_9P, ">>> TREADLINK fid %d\n", fid->fid);

	req = p9_client_rpc(clnt, P9_TREADLINK, "d", fid->fid);
	if (IS_ERR(req))
		return PTR_ERR(req);

	err = p9pdu_readf(req->rc, clnt->proto_version, "s", target);
	if (err) {
		trace_9p_protocol_dump(clnt, req->rc);
		goto error;
	}
	p9_debug(P9_DEBUG_9P, "<<< RREADLINK target %s\n", *target);
error:
	p9_free_req(clnt, req);
	return err;
}