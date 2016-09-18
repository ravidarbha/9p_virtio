/*
 * net/9p/protocol.h
 *
 * 9P Protocol Support Code
 *
 *  Copyright (C) 2008 by Eric Van Hensbergen <ericvh@gmail.com>
 *
 *  Base on code from Anthony Liguori <aliguori@us.ibm.com>
 *  Copyright (C) 2008 by IBM, Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

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
