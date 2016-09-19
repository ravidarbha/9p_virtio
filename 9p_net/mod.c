//// ADD the headers which are needed here. Not Just everything.
#include "../../transport.h"

unsigned int p9_debug_level = 1;	/* feature-rific global debug level  */

void p9_debug(enum p9_debug_flags level, const char *func,
		const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if ((p9_debug_level & level) != level)
		return;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	if (level == P9_DEBUG_9P)
		pr_notice("(%8.8d) %pV", task_pid_nr(current), &vaf);
	else
		pr_notice("-- %s (%d): %pV", func, task_pid_nr(current), &vaf);

	va_end(args);
}

/*
 * Dynamic Transport Registration Routines
 *
 */

mtx_init(&v9fs_trans_lock, "v9fs_trans_lock", NULL, MTX_DEF);
static SLIST_HEAD(,p9_trans_module) v9fs_trans_list;

/**
 * v9fs_register_trans - register a new transport with 9p
 * @m: structure describing the transport module and entry points
 *
 */
void v9fs_register_trans(struct p9_trans_module *m)
{
	mtx_lock_spin(&v9fs_trans_lock);
	SLIST_TAILQ_INSERT(m, &v9fs_trans_list);
	mtx_unlock_spin(&v9fs_trans_lock);
}

/**
 * v9fs_unregister_trans - unregister a 9p transport
 * @m: the transport to remove
 *
 */
void v9fs_unregister_trans(struct p9_trans_module *m)
{
	mtx_lock_spin(&v9fs_trans_lock);
	SLIST_REMOVE(&v9fs_trans_list, m, p9_trans_module, trans_mod);
	mtx_unlock_spin(&v9fs_trans_lock);
}

/**
 * v9fs_get_trans_by_name - get transport with the matching name
 * @name: string identifying transport
 *
 */
struct p9_trans_module *v9fs_get_trans_by_name(char *s)
{
	struct p9_trans_module *t, *found = NULL;

	mtx_lock_spin(&v9fs_trans_lock);

	STAILQ_FOREACH(t, &v9fs_trans_list, list) {
		if (strcmp(t->name, s) == 0 ) {
			found = t;
			break;
		}
	}

	mtx_unlock_spin(&v9fs_trans_lock);
	return found;
}

/**
 * v9fs_get_default_trans - get the default transport
 *
 */


#if 0
struct p9_trans_module *v9fs_get_default_trans(void)
{
	struct p9_trans_module *t, *found = NULL;

	mtx_lock_spin(&v9fs_trans_lock);

	list_for_each_entry(t, &v9fs_trans_list, list)
		if (t->def && try_module_get(t->owner)) {
			found = t;
			break;
		}

	if (!found)
		list_for_each_entry(t, &v9fs_trans_list, list)
			if (try_module_get(t->owner)) {
				found = t;
				break;
			}

	mtx_unlock_spin(&v9fs_trans_lock);
	return found;
}
#endif // no default functions for now.
