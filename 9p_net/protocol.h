/*
 * net/protocol.h
 *
 * 9P Protocol Support Code
 */

int p9pdu_vwritef(struct p9_fcall *pdu, int proto_version, const char *fmt,
								va_list ap);
int p9pdu_readf(struct p9_fcall *pdu, int proto_version, const char *fmt, ...);
int p9pdu_prepare(struct p9_fcall *pdu, int16_t tag, int8_t type);
int p9pdu_finalize(struct p9_client *clnt, struct p9_fcall *pdu);
void p9pdu_reset(struct p9_fcall *pdu);
size_t pdu_read(struct p9_fcall *pdu, void *data, size_t size);
