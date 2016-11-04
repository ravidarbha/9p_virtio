/*
 * The Virtio 9p transport driver
 */

#include <sys/errno.h>
#include "../9p.h"
#include "../client.h"
#include "transport.h"
#include "../protocol.h"

#include <sys/module.h>
#include <sys/sglist.h>
#include <sys/queue.h>
#include <sys/bus.h>
#include <machine/bus.h>

#include "dev/virtio/virtio.h"
#include "dev/virtio/virtqueue.h"

#include <sys/condvar.h>

#define VIRTQUEUE_NUM	128
#define VT9P_MTX(_sc) &(_sc)->vt9p_mtx
#define VT9P_LOCK(_sc) mtx_lock(VT9P_MTX(_sc))
#define VT9P_UNLOCK(_sc) mtx_unlock(VT9P_MTX(_sc))

/* a single mutex to manage channel initialization and attachment */
struct mtx virtio_9p_lock;

/* We can move this to a new header later if we need.
 * For now we re the only ones using this struct .
 */
struct vt9p_softc {
	device_t vt9p_dev;
	struct mtx vt9p_mtx;
	struct sglist *vt9p_sglist;
	struct cv  submit_cv;
	struct mtx submit_cv_lock;
	struct p9_client *client;
	struct virtqueue *vt9p_vq;
	int ring_bufs_avail;
	int max_nsegs;
	int inuse;
	int chan_name_len;
	char *chan_name;
};

//static SLIST_HEAD (,vt9p_softc) vt9p_softc_list;


static void vt9p_close(struct p9_client *client)
{
	struct vt9p_softc *chan = client->trans;

	mtx_lock(&virtio_9p_lock);
	if (chan)
		chan->inuse = false;

	mtx_unlock(&virtio_9p_lock);
}

/* We don't currently allow canceling of virtio requests */
static int vt9p_cancel(struct p9_client *client, struct p9_req_t *req)
{
	return 1;
}

static int
vt9p_request(struct p9_client *client, struct p9_req_t *req)
{
	int err, out, in;
	struct vt9p_softc *chan = client->trans;

	p9_debug(TRANS, "9p debug: virtio request\n");

	req->status = REQ_STATUS_SENT;
req_retry:
	VT9P_LOCK(chan);

	/* Handle out VirtIO ring buffers */
	out = sglist_append(chan->vt9p_sglist, req->tc->sdata, req->tc->size);

	in = sglist_append(chan->vt9p_sglist, req->rc->sdata, req->rc->capacity);

	err = virtqueue_enqueue(chan->vt9p_vq, req, chan->vt9p_sglist, in, out);

	/* Retry mechanism for the requeue. We could either
	 * do it this way - Where we sleep in this context and
	 * wakeup again when we have resources or create a new
	 * queue to enqueue and return back. */
	if (err < 0) {
		if (err == -ENOSPC) {
			chan->ring_bufs_avail = 0;
			VT9P_UNLOCK(chan);
			/* Condvar for the submit queue.*/
			cv_wait(&chan->submit_cv, &chan->submit_cv_lock);
			p9_debug(TRANS, "Retry virtio request\n");
			goto req_retry;
		} else {
			VT9P_UNLOCK(chan);
			p9_debug(TRANS,
				 "virtio rpc add_sgs returned failure\n");
			return -EIO;
		}
	}

	p9_debug(TRANS, "virtio request kicked\n");
	/* We return back to the client and wait there for the submission. */
	return 0;
}

/* Completion of the request from the virt queue. */
static void
p9_intr_complete(void *xsc)
{
	struct vt9p_softc *chan;
	struct virtqueue *vq;
	struct p9_req_t *req;
	//struct req_queue queue;

	chan = (struct vt9p_softc *)xsc;
	vq = chan->vt9p_vq;

    	while (1) {
		VT9P_LOCK(chan);
		req = virtqueue_dequeue(chan->vt9p_vq, NULL);
		if (req == NULL) {
			VT9P_UNLOCK(chan);
			break;
		}
	}
	chan->ring_bufs_avail = 1;
 	VT9P_UNLOCK(chan);
	/* Wakeup if anyone waiting for VirtIO ring space. */
	cv_signal(&chan->submit_cv);
	p9_client_cb(chan->client, req);
}


#if 0 /* This will be uncommented when we run in queue */
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

static int virtio_alloc_queue(struct vt9p_softc *sc)
{
    struct vq_alloc_info vq_info;
    device_t dev = sc->vt9p_dev;

    VQ_ALLOC_INFO_INIT(&vq_info, sc->max_nsegs,
            p9_intr_complete, sc, &sc->vt9p_vq,
            "%s request", device_get_nameunit(dev));

       return (virtio_alloc_virtqueues(dev, 0, 1, &vq_info));
}

static int vt9p_probe(device_t dev)
{
    /* VIRTIO_ID_9P is already defined */
    if (virtio_get_device_type(dev) != VIRTIO_ID_9P)
        return (ENXIO);
    device_set_desc(dev, "VirtIO 9P Transport");

    return (BUS_PROBE_DEFAULT); 
}

struct vt9p_softc *global_ctx; // For now.. theres only one channel
static int vt9p_attach(device_t dev)
{
	uint16_t name_len;
	int err;
	struct vt9p_softc *chan;

	chan = device_get_softc(dev);
	chan->vt9p_dev = dev;

	/* We expect one virtqueue, for requests. */
	err = virtio_alloc_queue(chan);

	if (err < 0) {
		goto out_p9_free_vq;
	}

	mtx_init(&chan->vt9p_mtx, "chan_lock", NULL, MTX_SPIN);

	chan->vt9p_sglist = sglist_alloc(VIRTQUEUE_NUM, M_NOWAIT);

	if (chan->vt9p_sglist == NULL) {
		err = ENOMEM;
		printf("cannot allocate sglist\n");
		goto out_p9_free_vq;
	}

	chan->inuse = false;
	/* This is the mount tag for now. Qemu server has to export the device using this mount	
	 * tag.*/
	/* /usr/bin/qemu-kvm -m 1024 -name f15 -drive file=/images/f15.img,if=virtio
	 * -fsdev local,security_model=passthrough,id=fsdev0,path=/tmp/share -device virtio-9p-pci,
	 * id=fs0,fsdev=fsdev0,mount_tag=hostshare
	 */
	name_len = strlen("hostshare");
	chan->chan_name = p9_malloc(name_len);
	if (!chan->chan_name) {
		err = -ENOMEM;
		goto out_p9_free_vq;
	}

	chan->chan_name_len = name_len;
	chan->chan_name ="hostshare";

	// Add to this wait queue which will later be woken up.
	///TAILQ_INIT(&chan->vc_wq);
	chan->ring_bufs_avail = 1;

	// Add all of them to the channel list so that we can create(mount) only to one.
	mtx_lock(&virtio_9p_lock);
	//SLIST_INSERT_TAIL(&chan->chan_list, &vt9p_softc_list);
	mtx_unlock(&virtio_9p_lock);

	err = virtio_setup_intr(dev, INTR_ENTROPY);
	if (err) {
		printf("cannot setup virtqueue interrupt\n");
		goto out_p9_free_vq;
	}
	virtqueue_enable_intr(chan->vt9p_vq);
	global_ctx = chan;
	return 0;

out_p9_free_vq:
	p9_free(chan->chan_name, name_len);
	/// Free the vq here otherwise it might leak.
	p9_free(chan, sizeof(*chan));
	return err;
}


/**
 * vt9p_create - allocate a new virtio channel
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
vt9p_create(struct p9_client *client)
{
	struct vt9p_softc *chan;
	int ret = -ENOENT;
	int found = 0;

	mtx_lock(&virtio_9p_lock);
	/*STAILQ_FOREACH(chan, &vt9p_softc_list, chan_list) {
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
		printf("no channels available for device %s\n", client->name);
		return ret;
	}

	client->trans = (void *)chan;
	client->status = Connected;
	chan->client = client;

	return 0;
}

/**
 * vt9p_remove - clean up resources associated with a virtio device
 * @vt9p_dev: virtio device to remove
 *
 */

static int vt9p_remove(device_t vt9p_dev)
{
	struct vt9p_softc *chan = device_get_softc(vt9p_dev);

	mtx_lock(&virtio_9p_lock);

	/* Remove self from list so we don't get new users. */
	//SLIST_REMOVE(&vt9p_softc_list, chan, vt9p_softc, chan_list);

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

static struct p9_trans_module vt9p_trans = {
	.name = "virtio",
	.create = vt9p_create,
	.close = vt9p_close,
	.request = vt9p_request,
	.cancel = vt9p_cancel,
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
	return &vt9p_trans;
	//return found;
}

static device_method_t vt9p_mthds[] = {
    /* Device methods. */
    DEVMETHOD(device_probe,     vt9p_probe),
    DEVMETHOD(device_attach,    vt9p_attach),
    DEVMETHOD(device_detach,    vt9p_remove),
    DEVMETHOD_END
};

static driver_t vt9p_drv = {
    "9p_virtio",
    vt9p_mthds,
    sizeof(struct vt9p_softc)
};
static devclass_t vt9p_class;

static int
vt9p_modevent(module_t mod, int type, void *unused)
{
    int error = 0;

    switch (type) {
        case MOD_LOAD: {
            //INIT_LIST_HEAD(&vt9p_softc_list);
            break;
        }
        case MOD_UNLOAD: {
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

DRIVER_MODULE(virtio_blk, virtio_pci, vt9p_drv, vt9p_class,
	vt9p_modevent, 0);
MODULE_VERSION(vt9p, 1);
MODULE_DEPEND(vt9p, virtio, 1, 1, 1);
