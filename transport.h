
#ifndef NET_9P_TRANSPORT_H
#define NET_9P_TRANSPORT_H

#define P9_DEF_MIN_RESVPORT	(665U)
#define P9_DEF_MAX_RESVPORT	(1023U)
#include "../client.h"

struct p9_trans_module {
	SLIST_ENTRY(p9_trans_module) list;
	char *name;		/* name of transport */
	int maxsize;		/* max message size of transport */
	int def;		/* this transport should be default */
	struct module *owner;
	int (*create)(struct p9_client *, const char *);
	void (*close) (struct p9_client *);
	int (*request) (struct p9_client *, struct p9_req_t *req);
	int (*cancel) (struct p9_client *, struct p9_req_t *req);
	int (*cancelled)(struct p9_client *, struct p9_req_t *req);
	int (*zc_request)(struct p9_client *, struct p9_req_t *,
			  struct iov_iter *, struct iov_iter *, int , int, int);
};

void v9fs_register_trans(struct p9_trans_module *m);
void v9fs_unregister_trans(struct p9_trans_module *m);
int p9fs_proto_dotl(struct p9fs_session *p9s);
struct p9_trans_module *v9fs_get_trans_by_name(char *s);
struct p9_trans_module *v9fs_get_default_trans(void);
void v9fs_put_trans(struct p9_trans_module *m);
#endif /* NET_9P_TRANSPORT_H */
