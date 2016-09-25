/*
 * net/9p/protocol.c
 *
 * 9P Protocol Support Code
 * This file provides the standard fot the FS interactions with the Qemu interface as it can understand
 * only this protocol.
 *
 */

#include <sys/types.h>
#include "../9p.h"
#include "../client.h"
#include "../protocol.h"

#define cpu_to_le16(x) htons(x)
#define cpu_to_le32(x) htonl(x)
#define cpu_to_le64(x) (x)
#define le16_to_cpu(x) ntohs(x)
#define le32_to_cpu(x) ntohl(x)
#define le64_to_cpu(x) (x)




static int
p9pdu_writef(struct p9_fcall *pdu, int proto_version, const char *fmt, ...);
void p9stat_p9_free(struct p9_wstat *stbuf);

void p9stat_p9_free(struct p9_wstat *stbuf)
{
	p9_free(stbuf->name, strlen(stbuf->name));
	p9_free(stbuf->uid, sizeof(stbuf->uid));
	p9_free(stbuf->gid, sizeof(stbuf->gid));
	p9_free(stbuf->muid, sizeof(stbuf->muid));
	p9_free(stbuf->extension, sizeof(stbuf->extension));
}

size_t pdu_read(struct p9_fcall *pdu, void *data, size_t size)
{
	size_t len = min(pdu->size - pdu->offset, size);
	memcpy(data, &pdu->sdata[pdu->offset], len);
	pdu->offset += len;
	return size - len;
}

static size_t pdu_write(struct p9_fcall *pdu, const void *data, size_t size)
{
	size_t len = min(pdu->capacity - pdu->size, size);
	memcpy(&pdu->sdata[pdu->size], data, len);
	pdu->size += len;
	return size - len;
}

          


static size_t
pdu_write_u(struct p9_fcall *pdu, struct iovec *from, size_t size)
{
#if 0
	size_t len = min(pdu->capacity - pdu->size, size);
	struct iov_iter i = *from;

	for (i = 0, cur_offset = 0; i < data->sg_count; i++) {
                        bcopy(data->iovec[i].iov_base,
                            &file_dev->tmp_buf[cur_offset],
                            data->iovec[i].iov_len);
                        cur_offset += data->iovec[i].iov_len;
   
	if (copy_from_iter(&pdu->sdata[pdu->size], len, &i) != len)
		len = 0;

	pdu->size += len;
	return size - len;
#endif
	return 0;
}

/*
	b - int8_t
	w - int16_t
	d - int32_t
	q - int64_t
	s - string
	u - numeric uid
	g - numeric gid
	S - stat
	Q - qid
	D - data blob (int32_t size followed by void *, results are not p9_freed)
	T - array of strings (int16_t count, followed by strings)
	R - array of qids (int16_t count, followed by qids)
	A - stat for 9p2000.L (p9_stat_dotl)
	? - if optional = 1, continue parsing
*/

static int
p9pdu_vreadf(struct p9_fcall *pdu, int proto_version, const char *fmt,
	va_list ap)
{
	const char *ptr;
	int errcode = 0;

	for (ptr = fmt; *ptr; ptr++) {
		switch (*ptr) {
		case 'b':{
				int8_t *val = va_arg(ap, int8_t *);
				if (pdu_read(pdu, val, sizeof(*val))) {
					errcode = -EFAULT;
					break;
				}
			}
			break;
		case 'w':{
				int16_t *val = va_arg(ap, int16_t *);
				int16_t le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*val = le16_to_cpu(le_val);
			}
			break;
		case 'd':{
				int32_t *val = va_arg(ap, int32_t *);
				int32_t le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*val = le32_to_cpu(le_val);
			}
			break;
		case 'q':{
				int64_t *val = va_arg(ap, int64_t *);
				int64_t le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*val = le64_to_cpu(le_val);
			}
			break;
		case 's':{
				char **sptr = va_arg(ap, char **);
				uint16_t len;

				errcode = p9pdu_readf(pdu, proto_version,
								"w", &len);
				if (errcode)
					break;

				*sptr = p9_malloc(len + 1);
				if (*sptr == NULL) {
					errcode = -EFAULT;
					break;
				}
				if (pdu_read(pdu, *sptr, len)) {
					errcode = -EFAULT;
					p9_free(*sptr, sizeof(*sptr));
					*sptr = NULL;
				} else
					(*sptr)[len] = 0;
			}
			break;
		case 'u': {
#if 0
				kuid_t *uid = va_arg(ap, kuid_t *);
				__le32 le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*uid = make_kuid(&init_user_ns,
						 le32_to_cpu(le_val));
#endif
			} break;
		case 'g': {
#if 0
				kgid_t *gid = va_arg(ap, kgid_t *);
				__le32 le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*gid = make_kgid(&init_user_ns,
						 le32_to_cpu(le_val));
#endif 
			} break;
		case 'Q':{
				struct p9_qid *qid =
				    va_arg(ap, struct p9_qid *);

				errcode = p9pdu_readf(pdu, proto_version, "bdq",
						      &qid->type, &qid->version,
						      &qid->path);
			}
			break;
		case 'S':{
				struct p9_wstat *stbuf =
				    va_arg(ap, struct p9_wstat *);

				memset(stbuf, 0, sizeof(struct p9_wstat));
				stbuf->n_uid = stbuf->n_muid = 0; //INVALID_UID;
				stbuf->n_gid = 0;//INVALID_GID;

				errcode =
				    p9pdu_readf(pdu, proto_version,
						"wwdQdddqssss?sugu",
						&stbuf->size, &stbuf->type,
						&stbuf->dev, &stbuf->qid,
						&stbuf->mode, &stbuf->atime,
						&stbuf->mtime, &stbuf->length,
						&stbuf->name, &stbuf->uid,
						&stbuf->gid, &stbuf->muid,
						&stbuf->extension,
						&stbuf->n_uid, &stbuf->n_gid,
						&stbuf->n_muid);
				if (errcode)
					p9stat_p9_free(stbuf);
			}
			break;
		case 'D':{
				uint32_t *count = va_arg(ap, uint32_t *);
				void **data = va_arg(ap, void **);

				errcode =
				    p9pdu_readf(pdu, proto_version, "d", count);
				if (!errcode) {
					*count = MIN(*count,
						  pdu->size - pdu->offset);
					*data = &pdu->sdata[pdu->offset];
				}
			}
			break;
		case 'T':{
				uint16_t *nwname = va_arg(ap, uint16_t *);
				char ***wnames = va_arg(ap, char ***);

				errcode = p9pdu_readf(pdu, proto_version,
								"w", nwname);
				if (!errcode) {
					*wnames = p9_malloc(sizeof(char *) * *nwname);
					if (!*wnames)
						errcode = -ENOMEM;
				}

				if (!errcode) {
					int i;

					for (i = 0; i < *nwname; i++) {
						errcode =
						    p9pdu_readf(pdu,
								proto_version,
								"s",
								&(*wnames)[i]);
						if (errcode)
							break;
					}
				}

				if (errcode) {
					if (*wnames) {
						int i;

						for (i = 0; i < *nwname; i++)
							p9_free((*wnames)[i], sizeof(*wnames[i]));
					}
					p9_free(*wnames, sizeof(*wnames));
					*wnames = NULL;
				}
			}
			break;
		case 'R':{
				uint16_t *nwqid = va_arg(ap, uint16_t *);
				struct p9_qid **wqids =
				    va_arg(ap, struct p9_qid **);

				*wqids = NULL;

				errcode =
				    p9pdu_readf(pdu, proto_version, "w", nwqid);
				if (!errcode) {
					*wqids =
					    p9_malloc(*nwqid *
						    sizeof(struct p9_qid));
					if (*wqids == NULL)
						errcode = -ENOMEM;
				}

				if (!errcode) {
					int i;

					for (i = 0; i < *nwqid; i++) {
						errcode =
						    p9pdu_readf(pdu,
								proto_version,
								"Q",
								&(*wqids)[i]);
						if (errcode)
							break;
					}
				}

				if (errcode) {
					p9_free(*wqids, sizeof(*wqids));
					*wqids = NULL;
				}
			}
			break;
		case 'A': {
				struct p9_stat_dotl *stbuf =
				    va_arg(ap, struct p9_stat_dotl *);

				memset(stbuf, 0, sizeof(struct p9_stat_dotl));
				errcode =
				    p9pdu_readf(pdu, proto_version,
					"qQdugqqqqqqqqqqqqqqq",
					&stbuf->st_result_mask,
					&stbuf->qid,
					&stbuf->st_mode,
					&stbuf->st_uid, &stbuf->st_gid,
					&stbuf->st_nlink,
					&stbuf->st_rdev, &stbuf->st_size,
					&stbuf->st_blksize, &stbuf->st_blocks,
					&stbuf->st_atime_sec,
					&stbuf->st_atime_nsec,
					&stbuf->st_mtime_sec,
					&stbuf->st_mtime_nsec,
					&stbuf->st_ctime_sec,
					&stbuf->st_ctime_nsec,
					&stbuf->st_btime_sec,
					&stbuf->st_btime_nsec,
					&stbuf->st_gen,
					&stbuf->st_data_version);
			}
			break;
		case '?':
			if ((proto_version != p9_proto_2000u) &&
				(proto_version != p9_proto_2000L))
				return 0;
			break;
		default:
			break;
		}

		if (errcode)
			break;
	}

	return errcode;
}

int
p9pdu_vwritef(struct p9_fcall *pdu, int proto_version, const char *fmt,
	va_list ap)
{
	const char *ptr;
	int errcode = 0;

	for (ptr = fmt; *ptr; ptr++) {
		switch (*ptr) {
		case 'b':{
				int8_t val = va_arg(ap, int);
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			}
			break;
		case 'w':{
				int16_t val = cpu_to_le16(va_arg(ap, int));
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			}
			break;
		case 'd':{
				int32_t val = cpu_to_le32(va_arg(ap, int32_t));
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			}
			break;
		case 'q':{
				int64_t val = cpu_to_le64(va_arg(ap, int64_t));
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			}
			break;
		case 's':{
				const char *sptr = va_arg(ap, const char *);
				uint16_t len = 0;
				if (sptr)
					len = MIN(strlen(sptr), 16);

				errcode = p9pdu_writef(pdu, proto_version,
								"w", len);
				if (!errcode && pdu_write(pdu, sptr, len))
					errcode = -EFAULT;
			}
			break;
		case 'u': {
				uid_t uid = va_arg(ap, uid_t);
				# if 0
				int32_t val = cpu_to_le32(from_uid(&init_user_ns, uid));
				if (pdu_write(pdu, &val, sizeof(val)))
				#endif // No support for the u flag here/
				(void)uid;
				errcode = -EFAULT;
			} break;
		case 'g': {
				gid_t gid = va_arg(ap, gid_t);
				#if 0
				__le32 val = cpu_to_le32(
						from_kgid(&init_user_ns, gid));
				if (pdu_write(pdu, &val, sizeof(val)))
				#endif //
				(void)gid;
				errcode = -EFAULT;
			} break;
		case 'Q':{
				const struct p9_qid *qid =
				    va_arg(ap, const struct p9_qid *);
				errcode =
				    p9pdu_writef(pdu, proto_version, "bdq",
						 qid->type, qid->version,
						 qid->path);
			} break;
		case 'S':{
				const struct p9_wstat *stbuf =
				    va_arg(ap, const struct p9_wstat *);
				errcode =
				    p9pdu_writef(pdu, proto_version,
						 "wwdQdddqssss?sugu",
						 stbuf->size, stbuf->type,
						 stbuf->dev, &stbuf->qid,
						 stbuf->mode, stbuf->atime,
						 stbuf->mtime, stbuf->length,
						 stbuf->name, stbuf->uid,
						 stbuf->gid, stbuf->muid,
						 stbuf->extension, stbuf->n_uid,
						 stbuf->n_gid, stbuf->n_muid);
			} break;
		case 'V':{
				// Get the count first and then do the loop.	
				uint32_t count = va_arg(ap, uint32_t);
				struct iovec *from =
						va_arg(ap, struct iovec *);
				errcode = p9pdu_writef(pdu, proto_version, "d",
									count);
				// FOr now avoid the vector operations.
				if (!errcode && pdu_write_u(pdu, from, count))
					errcode = -EFAULT;
			}
			break;
		case 'T':{
				uint16_t nwname = va_arg(ap, int);
				const char **wnames = va_arg(ap, const char **);

				errcode = p9pdu_writef(pdu, proto_version, "w",
									nwname);
				if (!errcode) {
					int i;

					for (i = 0; i < nwname; i++) {
						errcode =
						    p9pdu_writef(pdu,
								proto_version,
								 "s",
								 wnames[i]);
						if (errcode)
							break;
					}
				}
			}
			break;
		case 'R':{
				uint16_t nwqid = va_arg(ap, int);
				struct p9_qid *wqids =
				    va_arg(ap, struct p9_qid *);

				errcode = p9pdu_writef(pdu, proto_version, "w",
									nwqid);
				if (!errcode) {
					int i;

					for (i = 0; i < nwqid; i++) {
						errcode =
						    p9pdu_writef(pdu,
								proto_version,
								 "Q",
								 &wqids[i]);
						if (errcode)
							break;
					}
				}
			}
			break;
		case 'I':{
				struct p9_iattr_dotl *p9attr = va_arg(ap,
							struct p9_iattr_dotl *);

				errcode = p9pdu_writef(pdu, proto_version,
							"ddugqqqqq",
							p9attr->valid,
							p9attr->mode,
							p9attr->uid,
							p9attr->gid,
							p9attr->size,
							p9attr->atime_sec,
							p9attr->atime_nsec,
							p9attr->mtime_sec,
							p9attr->mtime_nsec);
			}
			break;
		case '?':
			if ((proto_version != p9_proto_2000u) &&
				(proto_version != p9_proto_2000L))
				return 0;
			break;
		default:
			break;
		}

		if (errcode)
			break;
	}

	return errcode;
}

int p9pdu_readf(struct p9_fcall *pdu, int proto_version, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = p9pdu_vreadf(pdu, proto_version, fmt, ap);
	va_end(ap);

	return ret;
}

static int
p9pdu_writef(struct p9_fcall *pdu, int proto_version, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = p9pdu_vwritef(pdu, proto_version, fmt, ap);
	va_end(ap);

	return ret;
}

int p9stat_read(struct p9_client *clnt, char *buf, int len, struct p9_wstat *st)
{
	struct p9_fcall fake_pdu;
	int ret;

	fake_pdu.size = len;
	fake_pdu.capacity = len;
	fake_pdu.sdata = buf;
	fake_pdu.offset = 0;

	ret = p9pdu_readf(&fake_pdu, clnt->proto_version, "S", st);
	if (ret) {
		p9_debug(P9_DEBUG_9P, "<<< p9stat_read failed: %d\n", ret);
		//trace_9p_protocol_dump(clnt, &fake_pdu);
	}

	return ret;
}

int p9pdu_prepare(struct p9_fcall *pdu, int8_t type)
{
	pdu->id = type;
	return p9pdu_writef(pdu, 0, "dbw", 0, type);
}

int p9pdu_finalize(struct p9_client *clnt, struct p9_fcall *pdu)
{
	int size = pdu->size;
	int err;

	pdu->size = 0;
	err = p9pdu_writef(pdu, 0, "d", size);
	pdu->size = size;

//	trace_9p_protocol_dump(clnt, pdu);
	p9_debug(P9_DEBUG_9P, ">>> size=%d type: %d tag: %d\n",
		 pdu->size, pdu->id, pdu->tag);

	return err;
}

void p9pdu_reset(struct p9_fcall *pdu)
{
	pdu->offset = 0;
	pdu->size = 0;
}

int p9dirent_read(struct p9_client *clnt, char *buf, int len,
		  struct p9_dirent *dirent)
{
	struct p9_fcall fake_pdu;
	int ret;
	char *nameptr;

	fake_pdu.size = len;
	fake_pdu.capacity = len;
	fake_pdu.sdata = buf;
	fake_pdu.offset = 0;

	ret = p9pdu_readf(&fake_pdu, clnt->proto_version, "Qqbs", &dirent->qid,
			  &dirent->d_off, &dirent->d_type, &nameptr);
	if (ret) {
		p9_debug(P9_DEBUG_9P, "<<< p9dirent_read failed: %d\n", ret);
		//trace_9p_protocol_dump(clnt, &fake_pdu);
		goto out;
	}

	strcpy(dirent->d_name, nameptr);
	p9_free(nameptr, sizeof(*nameptr));

out:
	return fake_pdu.offset;
}
