///The subsystem allocation used for allocation flags.
#define p9_malloc(size) malloc(size, M_TEMP, M_NOWAIT) /// make this WAIT and NON_WAIT based on the call later.
#define p9_free(ptr,size) free(ptr, M_TEMP) // Scam free for now.
#define ERESTARTSYS 10
#define NOCLIENT_ERROR 12

int p9pdu_vwritef(struct p9_fcall *pdu, int proto_version, const char *fmt,
								__va_list ap);
int p9pdu_readf(struct p9_fcall *pdu, int proto_version, const char *fmt, ...);
int p9pdu_prepare(struct p9_fcall *pdu, int8_t type);
int p9pdu_finalize(struct p9_client *clnt, struct p9_fcall *pdu);
void p9pdu_reset(struct p9_fcall *pdu);
size_t pdu_read(struct p9_fcall *pdu, void *data, size_t size);
/* This ones used for dirent reads.*/
int p9dirent_read(struct p9_client *clnt, char *buf, int len,
                  struct p9_dirent *dirent);
