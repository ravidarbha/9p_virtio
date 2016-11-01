# Note: It is important to make sure you include the <bsd.kmod.mk> makefile after declaring the KMOD and SRCS variables.
# Declare Name of kernel module
KMOD    =  9p_trans_virtio

# Enumerate Source files for kernel module
SRCS    =  device_if.h bus_if.h opt_cam.h trans_virtio.c client.c protocol.c

#INC=-I/usr/share/mk/
# Include kernel module makefile
.include <bsd.kmod.mk>
