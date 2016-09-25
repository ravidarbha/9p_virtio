# Note: It is important to make sure you include the <bsd.kmod.mk> makefile after declaring the KMOD and SRCS variables.
# Declare Name of kernel module
KMOD    =  9p_net_virtio

# Enumerate Source files for kernel module
SRCS    =  device_if.h bus_if.h opt_cam.h virtio.h client.c protocol.c trans_virtio.c mod.c  

#INC=-I/usr/share/mk/
# Include kernel module makefile
.include <bsd.kmod.mk>
