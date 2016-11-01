
#ifndef NET_9P_TRANSPORT_H
#define NET_9P_TRANSPORT_H

struct p9_trans_module {
	SLIST_ENTRY(p9_trans_module) list;
	char *name;		/* name of transport */
	int maxsize;		/* max message size of transport */
	int def;		/* this transport should be default */
	int (*create)(struct p9_client *);
	void (*close) (struct p9_client *);
	int (*request) (struct p9_client *, struct p9_req_t *req);
	int (*cancel) (struct p9_client *, struct p9_req_t *req);
	int (*cancelled)(struct p9_client *, struct p9_req_t *req);
};

void p9_register_trans(struct p9_trans_module *m);
void p9_unregister_trans(struct p9_trans_module *m);
struct p9_trans_module *p9_get_trans_by_name(char *s);
struct p9_trans_module *p9_get_default_trans(void);
void p9_put_trans(struct p9_trans_module *m);
#endif /* NET_9P_TRANSPORT_H */
