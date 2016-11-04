#ifndef _VIRTIO_9P_H
#define _VIRTIO_9P_H

struct vt9p_softc {                                                                     
        int inuse;                                                                       
        struct mtx lock;                                                                 
        struct cv  submit_cv; /*                                                         
        struct mtx submit_cv_lock;                                                       
        struct p9_client *client;                                                        
        device_t vdev;                                                                   
        struct virtqueue *vq;                                                            
        int ring_bufs_avail;                                                             
        int max_nsegs;                                                                   
        struct sglist *sg;                                                               
                                                                                         
        int chan_name_len;                                                               
        char *chan_name;                                                                 
};   


#endif /* _VIRTIO_9P_H */
