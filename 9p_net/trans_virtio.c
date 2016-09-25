/*
 * The Virtio 9p transport driver
 *
 * This is a block based transport driver based on the lguest block driver
 * code.
 *
 *  Based on virtio console driver
 *
 */

#include <sys/errno.h>
#include "../9p.h"
#include "../client.h"
#include "../transport.h"
#include "../protocol.h"

#include <sys/module.h>
#include <sys/sglist.h>
#include <sys/queue.h>
#include <machine/bus.h>
#include <sys/bus.h>
#include "../../virtfs_bhyve/sys/dev/virtio/virtio.h"
#include "../../virtfs_bhyve/sys/dev/virtio/virtqueue.h"


#include <sys/condvar.h>

#define VIRTQUEUE_NUM	128

/* a single mutex to manage channel initialization and attachment */
struct mtx virtio_9p_lock;

/**
 * struct vchan_softc - per-instance transport information
 * @initialized: whether the channel is initialized
 * @inuse: whether the channel is in use
 * @lock: protects multiple elements within this structure
 * @client: client instance
 * @vdev: virtio dev associated with this channel
 * @vq: virtio queue associated with this channel
 * @sg: scatter gather list which is used to pack a request (protected?)
 *
 * We keep all per-channel information in a structure.
 * This structure is allocated within the devices dev->mem space.
 * A pointer to the structure will get put in the transport private.
 *
 */

struct vchan_softc {
	int inuse;
	struct mtx lock; // Init as a spin lock for intr cxt.Spin lock.
	struct cv  submit_cv; 
	struct mtx submit_cv_lock;
	struct p9_client *client;
	device_t vdev;
	struct virtqueue *vq;
	int ring_bufs_avail;
	int max_nsegs;
	// I dunno if we need this  ?
	////TAILQ_HEAD vc_wq;

	/* This is global limit. Since we don't have a global structure,
	 * will be placing it in each channel.
	 */
	// Do we need this ? NUmber of pages ?
	unsigned long p9_max_pages;
	// Sglist for this channel 
	struct sglist *sg;

	int chan_name_len;
	/*
	 * tag name to identify a mount Non-null terminated
	 */
	char *chan_name;

	// tail queue head for channel list.
	//SLIST_ENTRY (vchan_softc) chan_list;
};

//static SLIST_HEAD (,vchan_softc) vchan_softc_list;


/**
 * p9_virtio_close - reclaim resources of a channel
 * @client: client instance
 *
 * This reclaims a channel by p9_freeing its resources and
 * reseting its inuse flag.
 *
 */

static void p9_virtio_close(struct p9_client *client)
{
	struct vchan_softc *chan = client->trans;

	mtx_lock(&virtio_9p_lock);
	if (chan)
		chan->inuse = false;

	mtx_unlock(&virtio_9p_lock);
}

/* We don't currently allow canceling of virtio requests */
static int p9_virtio_cancel(struct p9_client *client, struct p9_req_t *req)
{
	return 1;
}

/**
 * p9_virtio_request - issue a request
 * @client: client instance issuing the request
 * @req: request to be issued
 *
 */

static int
p9_virtio_request(struct p9_client *client, struct p9_req_t *req)
{
	int err, out, in;
	struct vchan_softc *chan = client->trans;

	p9_debug(P9_DEBUG_TRANS, "9p debug: virtio request\n");

	req->status = REQ_STATUS_SENT;
req_retry:
	mtx_lock_spin(&chan->lock);

	/* Handle out VirtIO ring buffers */
	out = sglist_append(chan->sg, req->tc->sdata, req->tc->size);

	in = sglist_append(chan->sg, req->rc->sdata, req->rc->capacity);

	err = virtqueue_enqueue(chan->vq, req, chan->sg, in, out);

	// Retry mechanism for the requeue. We could either
	// do it this way - Where we sleep in this context and
	// wakeup again when we have resources or create a new
	// queue to enqueue and return back.
	if (err < 0) {
		if (err == -ENOSPC) {
			chan->ring_bufs_avail = 0;
			mtx_unlock_spin(&chan->lock);
			// Condvar for the submit queue.
			cv_wait(&chan->submit_cv, &chan->submit_cv_lock);
			p9_debug(P9_DEBUG_TRANS, "Retry virtio request\n");
			goto req_retry;
		} else {
			mtx_unlock_spin(&chan->lock);
			p9_debug(P9_DEBUG_TRANS,
				 "virtio rpc add_sgs returned failure\n");
			return -EIO;
		}
	}

	p9_debug(P9_DEBUG_TRANS, "virtio request kicked\n");
	// We return back to the client and wait there for the submission.
	return 0;
}

/// REmove support for zc_request for now ONly work with request.
#if 0
static int p9_get_mapped_pages(struct vchan_softc *chan,
			       struct page ***pages,
			       struct iov_iter *data,
			       int count,
			       size_t *offs,
			       int *need_drop)
{
	int nr_pages;
	int err;

	if (!iov_iter_count(data))
		return 0;

	if (!(data->type & ITER_KVEC)) {
		int n;
		/*
		 * We allow only p9_max_pages pinned. We wait for the
		 * Other zc request to finish here
		 */
		if (atomic_read(&vp_pinned) >= chan->p9_max_pages) {
			err = wait_event_interruptible(vp_wq,
			      (atomic_read(&vp_pinned) < chan->p9_max_pages));
			if (err == -ERESTARTSYS)
				return err;
		}
		n = iov_iter_get_pages_alloc(data, pages, count, offs);
		if (n < 0)
			return n;
		*need_drop = 1;
		nr_pages = DIV_ROUND_UP(n + *offs, PAGE_SIZE);
		atomic_add(nr_pages, &vp_pinned);
		return n;
	} else {
		/* kernel buffer, no need to pin pages */
		int index;
		size_t len;
		void *p;

		/* we'd already checked that it's non-empty */
		while (1) {
			len = iov_iter_single_seg_count(data);
			if (likely(len)) {
				p = data->kvec->iov_base + data->iov_offset;
				break;
			}
			iov_iter_advance(data, 0);
		}
		if (len > count)
			len = count;

		nr_pages = DIV_ROUND_UP((unsigned long)p + len, PAGE_SIZE) -
			   (unsigned long)p / PAGE_SIZE;

		*pages = kp9_malloc(sizeof(struct page *) * nr_pages, GFP_NOFS);
		if (!*pages)
			return -ENOMEM;

		*need_drop = 0;
		p -= (*offs = offset_in_page(p));
		for (index = 0; index < nr_pages; index++) {
			if (is_vp9_malloc_addr(p))
				(*pages)[index] = vp9_malloc_to_page(p);
			else
				(*pages)[index] = kmap_to_page(p);
			p += PAGE_SIZE;
		}
		return len;
	}
}

/**
 * p9_virtio_zc_request - issue a zero copy request
 * @client: client instance issuing the request
 * @req: request to be issued
 * @uidata: user bffer that should be ued for zero copy read
 * @uodata: user buffer that shoud be user for zero copy write
 * @inlen: read buffer size
 * @olen: write buffer size
 * @hdrlen: reader header size, This is the size of response protocol data
 *
 */
static int
p9_virtio_zc_request(struct p9_client *client, struct p9_req_t *req,
		     struct iov_iter *uidata, struct iov_iter *uodata,
		     int inlen, int outlen, int in_hdr_len)
{
	int in, out, err, out_sgs, in_sgs;
	unsigned long flags;
	int in_nr_pages = 0, out_nr_pages = 0;
	struct page **in_pages = NULL, **out_pages = NULL;
	struct vchan_softc *chan = client->trans;
	struct scatterlist *sgs[4];
	size_t offs;
	int need_drop = 0;

	p9_debug(P9_DEBUG_TRANS, "virtio request\n");

	if (uodata) {
		int n = p9_get_mapped_pages(chan, &out_pages, uodata,
					    outlen, &offs, &need_drop);
		if (n < 0)
			return n;
		out_nr_pages = DIV_ROUND_UP(n + offs, PAGE_SIZE);
		if (n != outlen) {
			__le32 v = cpu_to_le32(n);
			memcpy(&req->tc->sdata[req->tc->size - 4], &v, 4);
			outlen = n;
		}
	} else if (uidata) {
		int n = p9_get_mapped_pages(chan, &in_pages, uidata,
					    inlen, &offs, &need_drop);
		if (n < 0)
			return n;
		in_nr_pages = DIV_ROUND_UP(n + offs, PAGE_SIZE);
		if (n != inlen) {
			__le32 v = cpu_to_le32(n);
			memcpy(&req->tc->sdata[req->tc->size - 4], &v, 4);
			inlen = n;
		}
	}
	req->status = REQ_STATUS_SENT;
req_retry_pinned:
	spin_lock_irqsave(&chan->lock, flags);

	out_sgs = in_sgs = 0;

	/* out data */
	out = pack_sg_list(chan->sg, 0,
			   VIRTQUEUE_NUM, req->tc->sdata, req->tc->size);

	if (out)
		sgs[out_sgs++] = chan->sg;

	if (out_pages) {
		sgs[out_sgs++] = chan->sg + out;
		out += pack_sg_list_p(chan->sg, out, VIRTQUEUE_NUM,
				      out_pages, out_nr_pages, offs, outlen);
	}
		
	/*
	 * Take care of in data
	 * For example TREAD have 11.
	 * 11 is the read/write header = PDU Header(7) + IO Size (4).
	 * Arrange in such a way that server places header in the
	 * alloced memory and payload onto the user buffer.
	 */
	in = pack_sg_list(chan->sg, out,
			  VIRTQUEUE_NUM, req->rc->sdata, in_hdr_len);
	if (in)
		sgs[out_sgs + in_sgs++] = chan->sg + out;

	if (in_pages) {
		sgs[out_sgs + in_sgs++] = chan->sg + out + in;
		in += pack_sg_list_p(chan->sg, out + in, VIRTQUEUE_NUM,
				     in_pages, in_nr_pages, offs, inlen);
	}

	BUG_ON(out_sgs + in_sgs > ARRAY_SIZE(sgs));
	err = virtqueue_add_sgs(chan->vq, sgs, out_sgs, in_sgs, req,
				GFP_ATOMIC);
	if (err < 0) {
		if (err == -ENOSPC) {
			chan->ring_bufs_avail = 0;
			spin_unlock_irqrestore(&chan->lock, flags);
			err = wait_event_interruptible(*chan->vc_wq,
						       chan->ring_bufs_avail);
			if (err  == -ERESTARTSYS)
				goto err_out;

			p9_debug(P9_DEBUG_TRANS, "Retry virtio request\n");
			goto req_retry_pinned;
		} else {
			spin_unlock_irqrestore(&chan->lock, flags);
			p9_debug(P9_DEBUG_TRANS,
				 "virtio rpc add_sgs returned failure\n");
			err = -EIO;
			goto err_out;
		}
	}
	virtqueue_kick(chan->vq);
	spin_unlock_irqrestore(&chan->lock, flags);
	p9_debug(P9_DEBUG_TRANS, "virtio request kicked\n");
	err = wait_event_interruptible(*req->wq,
				       req->status >= REQ_STATUS_RCVD);
	/*
	 * Non kernel buffers are pinned, unpin them
	 */
err_out:
	if (need_drop) {
		if (in_pages) {
			p9_release_pages(in_pages, in_nr_pages);
			atomic_sub(in_nr_pages, &vp_pinned);
		}
		if (out_pages) {
			p9_release_pages(out_pages, out_nr_pages);
			atomic_sub(out_nr_pages, &vp_pinned);
		}
		/* wakeup anybody waiting for slots to pin pages */
		wake_up(&vp_wq);
	}
	kp9_free(in_pages);
	kp9_free(out_pages);
	return err;
}
#endif 
/*
static ssize_t p9_mount_tag_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct vchan_softc *chan;
	struct virtio_device *vdev;

	vdev = dev_to_virtio(dev);
	chan = vdev->priv;

	memcpy(buf, chan->tag, chan->tag_len);
	buf[chan->tag_len] = 0;

	return chan->tag_len + 1;
}

static DEVICE_ATTR(mount_tag, 0444, p9_mount_tag_show, NULL);


static void
p9_done_completed(struct vchan_softc *sc, struct p9_req_t *queue)
{
        struct p9_req_t *req;

        TAILQ_FOREACH(req, queue, req_queue) {
                if (bp->bio_error != 0)
                        disk_err(bp, "hard error", -1, 1);
                p9_client_cb(sc, req);
        }
}


static void
p9_queue_completed(struct vchan_softc *chan, struct req_queue *queue)
{
	struct p9_req_t *req;

	while ((req = virtqueue_dequeue(chan->vq, NULL)) != NULL) {
		if (req != NULL) {
			// Client side callback complete.
			TAILQ_INSERT_TAIL(queue, req);
		}
        }
}*/

// Completion of the request from the virt queue.
static void
p9_intr_complete(void *xsc)
{
	struct vchan_softc *chan;
	struct virtqueue *vq;
	struct p9_req_t *req;
	//struct req_queue queue;

	chan = (struct vchan_softc *)xsc;
	vq = chan->vq;

    	while (1) {
		mtx_lock_spin(&chan->lock);
		req = virtqueue_dequeue(chan->vq, NULL);
		if (req == NULL) {
			mtx_unlock_spin(&chan->lock);
			break;
		}
	}
	chan->ring_bufs_avail = 1;
 	mtx_unlock_spin(&chan->lock);
	/* Wakeup if anyone waiting for VirtIO ring space. */
	cv_signal(&chan->submit_cv);
	p9_client_cb(chan->client, req);
}


#if 0
gain:
	//p9_queue_completed(chan, &queue);

	p9_client_cb(chan, req); 
	// check if we need to start ?
	if (virtqueue_enable_intr(vq) != 0) {
		virtqueue_disable_intr(vq);
		goto again;
	}

	// Signal for submit queue.
//out:
	//p9_done_completed(chan, &queue);
}
#endif 

static int virtio_alloc_queue(struct vchan_softc *sc)
{
    struct vq_alloc_info vq_info;
    device_t dev = sc->vdev;

    VQ_ALLOC_INFO_INIT(&vq_info, sc->max_nsegs,
            p9_intr_complete, sc, &sc->vq,
            "%s request", device_get_nameunit(dev));

       return (virtio_alloc_virtqueues(dev, 0, 1, &vq_info));
}

/**
 * p9_virtio_probe - probe for existence of 9P virtio channels
 * @vdev: virtio device to probe
 *
 * This probes for existing virtio channels.
 *
 */

static int p9_virtio_probe(device_t dev)
{
    if (virtio_get_device_type(dev) != 0x09) // This is the VIRTIO_9p dev
        return (ENXIO);
    device_set_desc(dev, "VirtIO Trans FS ");

    return (BUS_PROBE_DEFAULT); 
}

struct vchan_softc *global_ctx; // For now.. we ll
static int p9_virtio_attach(device_t dev)
{
	uint16_t name_len;
	int err;
	struct vchan_softc *chan;

	chan = device_get_softc(dev);
	chan->vdev = dev;

	/* We expect one virtqueue, for requests. */
	err = virtio_alloc_queue(chan);

	if (err < 0) {
		goto out_p9_free_vq;
	}

	mtx_init(&chan->lock, "chan_lock", NULL, MTX_SPIN);

	chan->sg = sglist_alloc(VIRTQUEUE_NUM, M_NOWAIT);

	if (chan->sg == NULL) {
		err = ENOMEM;
		printf("cannot allocate sglist\n");
		goto out_p9_free_vq;
	}

	chan->inuse = false;
	name_len = strlen("ravi");
    	// Name of the transport being used.
	chan->chan_name = p9_malloc(name_len);
	if (!chan->chan_name) {
		err = -ENOMEM;
		goto out_p9_free_vq;
	}

	chan->chan_name_len = name_len;
	chan->chan_name ="ravi"; // This will be replaced with the trans from mount

	// Add to this wait queue which will later be woken up.
	///TAILQ_INIT(&chan->vc_wq);
	chan->ring_bufs_avail = 1;
	/* Ceiling limit to avoid denial of service attacks */
	//chan->p9_max_pages = nr_p9_free_buffer_pages()/4;

	// Add all of them to the channel list so that we can create(mount) only to one.
	mtx_lock(&virtio_9p_lock);
	//SLIST_INSERT_TAIL(&chan->chan_list, &vchan_softc_list);
	mtx_unlock(&virtio_9p_lock);

	err = virtio_setup_intr(dev, INTR_ENTROPY);
	if (err) {
		printf("cannot setup virtqueue interrupt\n");
		goto out_p9_free_vq;
	}
	virtqueue_enable_intr(chan->vq);
	global_ctx = chan;
	return 0;

out_p9_free_vq:
	p9_free(chan->chan_name, name_len);
	/// Free the vq here otherwise it might leak.
	p9_free(chan, sizeof(*chan));
	return err;
}


/**
 * p9_virtio_create - allocate a new virtio channel
 * @client: client instance invoking this transport
 * @devname: string identifying the channel to connect to (unused)
 * @args: args passed from sys_mount() for per-transport options (unused)
 *
 * This sets up a transport channel for 9p communication.  Right now
 * we only match the first available channel, but eventually we couldlook up
 * alternate channels by matching devname versus a virtio_config entry.
 * We use a simple reference count mechanism to ensure that only a single
 * mount has a channel open at a time.
 *
 */

static int
p9_virtio_create(struct p9_client *client, const char *devname)
{
	struct vchan_softc *chan;
	int ret = -ENOENT;
	int found = 0;

	mtx_lock(&virtio_9p_lock);
	/*STAILQ_FOREACH(chan, &vchan_softc_list, chan_list) {
		if (!strncmp(devname, chan->chan_name, chan->chan_name_len) &&
		    strlen(devname) == chan->chan_name_len) {
			if (!chan->inuse) {
				chan->inuse = true;
				found = 1;
				break;
			}
			ret = -EBUSY;
		}
	}*/
	// This hack will be cleaned up after POC with SLISTs.
	if (global_ctx)
	chan = global_ctx; 
	
	mtx_unlock(&virtio_9p_lock);

	if (!found) {
		printf("no channels available for device %s\n", devname);
		return ret;
	}

	client->trans = (void *)chan;
	client->status = Connected;
	chan->client = client;

	return 0;
}

/**
 * p9_virtio_remove - clean up resources associated with a virtio device
 * @vdev: virtio device to remove
 *
 */

static int p9_virtio_remove(device_t vdev)
{
	struct vchan_softc *chan = device_get_softc(vdev);

	mtx_lock(&virtio_9p_lock);

	/* Remove self from list so we don't get new users. */
	//SLIST_REMOVE(&vchan_softc_list, chan, vchan_softc, chan_list);

	/* Wait for existing users to close. 
	while (chan->inuse) {
		mtx_unlock(&virtio_9p_lock);
		msleep(250);
		mtx_lock(&virtio_9p_lock);
	}
	*/
	chan->inuse = false; 
	mtx_unlock(&virtio_9p_lock);

	// AGain call the vq deletion here otherwise it might leak.

	p9_free(chan->chan_name, strlen(chan->chan_name));
	return 0;
}

#if 0 // No unnecessary stuff.
static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_9P, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_9P_MOUNT_TAG,
};
#endif 

static struct p9_trans_module p9_virtio_trans = {
	.name = "virtio",
	.create = p9_virtio_create,
	.close = p9_virtio_close,
	.request = p9_virtio_request,
	.zc_request = NULL, //p9_virtio_zc_request,
	.cancel = p9_virtio_cancel,
	/*
	 * We leave one entry for input and one entry for response
	 * headers. We also skip one more entry to accomodate, address
	 * that are not at page boundary, that can result in an extra
	 * page in zero copy.
	 */
///	.maxsize = PAGE_SIZE * (VIRTQUEUE_NUM - 3),
	.def = 1,
};

// move it to mod.c after POC and then get the list setting right later.
struct p9_trans_module *v9fs_get_trans_by_name(char *s)
{
	//struct p9_trans_module *t, *found = NULL;

	//mtx_lock_spin(&v9fs_trans_lock);
	(void)s;

	/*STAILQ_FOREACH(t, &v9fs_trans_list, list) {
		if (strcmp(t->name, s) == 0 ) {
			found = t;
			break;
		}
	}*/
	
	//mtx_unlock_spin(&v9fs_trans_lock);
	return &p9_virtio_trans;
	//return found;
}

static device_method_t p9_virtio_mthds[] = {
    /* Device methods. */
    DEVMETHOD(device_probe,     p9_virtio_probe),
    DEVMETHOD(device_attach,    p9_virtio_attach),
    DEVMETHOD(device_detach,    p9_virtio_remove),
#if 0
    DEVMETHOD(device_suspend,   vtblk_suspend),
    DEVMETHOD(device_resume,    vtblk_resume),
    DEVMETHOD(device_shutdown,  vtblk_shutdown),
    /* VirtIO methods. */
    DEVMETHOD(virtio_config_change, vtblk_config_change),
#endif
    DEVMETHOD_END
};

static driver_t p9_virtio_drv = {
    "9p_virtio",
    p9_virtio_mthds,
    sizeof(struct vchan_softc)
};
static devclass_t p9_virtio_class;

static int
virtio_9p_modevent(module_t mod, int type, void *unused)
{

    int error;
    error = 0;

    switch (type) {
        case MOD_LOAD: {
            //INIT_LIST_HEAD(&vchan_softc_list);
	       //v9fs_register_trans(&p9_virtio_trans);
            break;
        }
        case MOD_UNLOAD: { 
	       //v9fs_unregister_trans(&p9_virtio_trans);
            break;
        }
        case MOD_SHUTDOWN:
            break;
        default:
            error = EOPNOTSUPP;
            break;
    }
    return (error);
}

DRIVER_MODULE(virtio_blk, virtio_pci, p9_virtio_drv, p9_virtio_class, 
	virtio_9p_modevent, 0);
MODULE_VERSION(p9_virtio, 1);
MODULE_DEPEND(p9_virtio, virtio, 1, 1, 1);
