/*
 * VDE - libvdeplug_vlan
 * Copyright (C) 2017 Renzo Davoli VirtualSquare
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
 */

#define __USE_GNU
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <libvdeplug.h>
#include <libvdeplug_mod.h>

static VDECONN *vde_vlan_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_vlan_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_vlan_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_vlan_datafd(VDECONN *conn);
static int vde_vlan_ctlfd(VDECONN *conn);
static int vde_vlan_close(VDECONN *conn);

/* Left to Right ----> packet sent by the VM */
#define LR 0
/* Right to Left <---- packet recvd by the VM */
#define RL 1

/* Declaration of the connection sructure of the module */
struct vde_vlan_conn {
	void *handle;
	struct vdeplug_module *module;
	VDECONN *conn;
	/* Traffic tagged with this tag will be seen as untagged by the VM */
	uint16_t untagged;
	/* Untagged traffic will be seen as tagged with this tag by the VM (dual of untagged) */
	uint16_t tag2untag;
	uint16_t ntag;	/* lenght of tag[0] and tag[1] arrays */
	uint16_t *tag[2]; /* remap vlans */
	char trunk;		/* boolean */
	// char qinq;
};

/* Structure of the VLAN header:
	TCI (2 bytes) + EtherType (2 bytes).
	TCI = Priority (3 bits) + DEI (1 bit) + VLAN Id (12 bits).
	As the EtherType of the Ethernet frame will be overwrited by
	ETHERTYPE_VLAN (0x8100) this EtherType will store the old value. */

/* Mask used to select the VLAN id. */
#define VLANMASK 0x0fff

/* Structure of the header added by the module */
struct vlan_hdr {
	uint16_t vlan;
	uint16_t ether_type;
};

/* Declaration of the module sructure */
struct vdeplug_module vdeplug_ops={
	/* .flags is not initialized */
	.vde_open_real=vde_vlan_open,
	.vde_recv=vde_vlan_recv,
	.vde_send=vde_vlan_send,
	.vde_datafd=vde_vlan_datafd,
	.vde_ctlfd=vde_vlan_ctlfd,
	.vde_close=vde_vlan_close
};

/* VLAN ids 0, 1 and 4095 are reserved */
/* returns true if vlan & VLANMASK != 0, 1, 4095 */
static inline int vlanok(uint16_t vlan) {
						/* VLANMASK */
	return (((vlan + 1) & 0xfff) > 2);
}

/* Preconditions:
	tagstr is the string containing tags separated by '.' or ':'.
	A tag could be one number or two numbers separated by '-'.
	tag: vde_vlan_conn.tag
   Postconditions:
    If tagstr contains tags, as a side effect tag is initialized for containing
	all tags.
   return value: number of tags
*/
static uint16_t tag_parse(char *tagstr, uint16_t **tag) {
	uint16_t count;
	size_t len = strlen(tagstr);
	/* local copy of tagstr */
	char tagstrcpy[len+1];
	char *saveptr;
	char *scan;
	/* Copy the whole tagstr in tagstrcpy */
	strncpy(tagstrcpy, tagstr, len);
	tagstrcpy[len] = 0;
	/* Count the number of tokens in the string (tokens limited by '.' or ':') */
	for (count = 0, scan = tagstrcpy; strtok_r(scan, ".:", &saveptr); scan = NULL)
		count++;
	if (count == 0) { /* No tags found. */
		tag[LR] = NULL;
		tag[RL] = NULL;
	} else { /* Tags found */
		tag[LR] = calloc(count, sizeof(uint16_t));
		tag[RL] = calloc(count, sizeof(uint16_t));
		/* Initialize the tag array */
		for (count = 0; (scan = strtok_r(tagstr, ".:", &saveptr)) != NULL; tagstr = NULL, count++) {
			char *more;
			/* tag[LR] is decided by the first number */
			tag[LR][count] = strtol(scan, &more, 0) & VLANMASK;
			if (*more == '-') /* number terminates with '-' (there is another number after it) */
				/* vlan is remapped */
				tag[RL][count] = strtol(more + 1, NULL, 0) & VLANMASK;
			else
				/* vlan is not remapped */
				tag[RL][count] = tag[LR][count];
		}
	}
	return count;
}

/* Check tagged packets
   Preconditions:
	vde_conn
	vlan
	dir is weather LR or RL
   Return value: value of the complementar vlan tag, 0 on error */
static uint16_t tagck(struct vde_vlan_conn *vde_conn, uint16_t vlan, int dir) {
	uint16_t retval = 0;	/* 0 is a sentinel value; not legal as vlan number */
	int i;
	/* Find vlan tag and get its complementar */
	for (i=0; i<vde_conn->ntag; i++) {
		if (vde_conn->tag[dir][i] == vlan) {
			retval = vde_conn->tag[1-dir][i];
			break;
		}
	}
	/* The tag wasn't listed && the connection uses trunking && vlan tag is ok */
	if (retval == 0 && vde_conn->trunk && vlanok(vlan))
		retval = vlan;
	return retval;
}

static VDECONN *vde_vlan_open(char *vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	/* Return value on success; dynamically allocated */
	struct vde_vlan_conn *newconn=NULL;
	char *nested_url;
	char *tagstr = "";
	char *untagstr = "";
	char *trunkstr = NULL;
	// char *qinqstr = NULL;
	struct vdeparms parms[] = {
		{"u", &untagstr},
		{"untag", &untagstr},
		{"t", &tagstr},
		{"tag", &tagstr},
		{"x", &trunkstr},
		{"trunk", &trunkstr},
		// {"q", &qinqstr},
		// {"qinq", &qinqstr},
		{NULL, NULL}};
	VDECONN *conn;

	/* Get nested parameters */
	nested_url = vde_parsenestparms(vde_url);
	if (vde_parseparms(vde_url, parms) != 0)
		return NULL;
	/* Open connection using the nested url */
	conn = vde_open(nested_url, descr, open_args);
	if (conn == NULL)
		return  NULL;
	/* calloc initializes the memory */
	if ((newconn=calloc(1,sizeof(struct vde_vlan_conn)))==NULL) {
		errno = ENOMEM;
		goto error;
	}
	newconn->conn=conn;
	newconn->untagged = strtol(vde_url, NULL, 0) & VLANMASK;
	newconn->tag2untag = strtol(untagstr, NULL, 0) & VLANMASK;
	newconn->ntag = tag_parse(tagstr, newconn->tag);
	newconn->trunk = (trunkstr != NULL);
	// newconn->qinq = (qinqstr != NULL);
	return (VDECONN *) newconn;

error:
	vde_close(conn);
	return NULL;
}

#if 0
void dump(void *buf, size_t len) {
	unsigned char *b=buf;
	size_t i;
	for (i=0; i<len; i++)
		printf("%02x ",b[i]);
	printf("\n\n");
}
#endif

/* Right to Left <---- */
static ssize_t vde_vlan_recv(VDECONN *conn,void *buf,size_t len,int flags) {
	struct vde_vlan_conn *vde_conn = (struct vde_vlan_conn *)conn;
	/* Length of the received packet */
	ssize_t retval = vde_recv(vde_conn->conn, buf, len, flags);
	if (retval >= sizeof(struct ether_header)) {
		struct ether_header *hdr = buf;		/* Cast in struct ether_header */
		/* Get VLAN header from Ethernet header:
		 	The VLAN header is after the Ethernet header */
		struct vlan_hdr *vlanhdr = (void *) (hdr + 1);
		if (hdr->ether_type == htons(ETHERTYPE_VLAN)) { /* TAGGED received */
			/* VLAN number */
			uint16_t vlan = ntohs(vlanhdr->vlan) & VLANMASK;
			if (vlan == vde_conn->untagged) {
				size_t newlen = retval - sizeof(struct vlan_hdr);
				hdr->ether_type = vlanhdr->ether_type;	/* Restore the old EtherType */
				/* Remove the VLAN header */
				memmove(vlanhdr, vlanhdr + 1, newlen - sizeof(struct ether_header));
				return newlen;
			} else if ((vlan = tagck(vde_conn, vlan, RL)) != 0 && vlanok(vlan)) {
				/* Remap vlan */
				vlanhdr->vlan = htons(vlan);
				return len;
			} else
				goto error;
		} else { /* UNTAGGED received */
			/* vlanhdr points to the payload */
			if (vde_conn->tag2untag != 0) {
				size_t newlen = retval + sizeof(struct vlan_hdr);
				if (newlen > len) newlen = len;
				/* Add header with vlan tag tag2untag */
				memmove(vlanhdr + 1, vlanhdr, newlen - (sizeof(struct ether_header) + sizeof(struct vlan_hdr)));
				vlanhdr->ether_type = hdr->ether_type;
				vlanhdr->vlan = htons(vde_conn->tag2untag);
				hdr->ether_type = htons(ETHERTYPE_VLAN);
				return newlen;
			} else if (vde_conn->untagged != 0) /* if tag2untag == 0 should be untagged == 0 */
				goto error;
			else
			/* tag2untag not specified; packet discarded */
				return retval;
		}
	}
	return retval;
error:
	errno = EAGAIN;
	return 1;
}

/* Left to Right ----> */
static ssize_t vde_vlan_send(VDECONN *conn,const void *buf, size_t len,int flags) {
	struct vde_vlan_conn *vde_conn = (struct vde_vlan_conn *)conn;
	ssize_t retval;

	if (len >= sizeof(struct ether_header)) {
		const struct ether_header *hdr = buf;
		if (hdr->ether_type == htons(ETHERTYPE_VLAN) /*&& !vde_conn->qinq*/) { /* TAGGED to send */
			/* The packet is already tagged */
			struct vlan_hdr *vlanhdr = (void *) (hdr + 1);
			/* Get vlan number of the packet */
			uint16_t vlan = ntohs(vlanhdr->vlan) & VLANMASK;
			if (vlan == vde_conn->tag2untag) {
			/* The packet has been previously received untagged */
				size_t newlen = len - sizeof(struct vlan_hdr);
				/* Buffer for containing the packet without vlan header */
				char newbuf[newlen];
				struct ether_header *newhdr = (void *) newbuf;
				/* Remove vlan header */
				*newhdr = *hdr;
				newhdr->ether_type = vlanhdr->ether_type;
				memcpy(newhdr + 1, vlanhdr + 1, newlen - sizeof(struct ether_header));
				retval = vde_send(vde_conn->conn, newbuf, newlen, flags);
				if (retval == newlen) retval = len;
				return retval;
			} else if ((vlan = tagck(vde_conn, vlan, LR)) != 0 && vlanok(vlan)) {
				/* Remap vlan */
				vlanhdr->vlan = htons(vlan);
				return vde_send(vde_conn->conn, buf, len, flags);
			} else
				/* Packet discarded */
				return len;
		} else { /* UNTAGGED send */
			switch (vde_conn->untagged) {
				case 0:
					if (vde_conn->tag2untag == 0) /* untagged traffic is not seen as tagged */
						/* Packet sent untagged */
						return vde_send(vde_conn->conn, buf, len, flags);
					else
						/* Packet is discarded */
						return len;
				case 0xfff:
					/* Packet is discarded */
					return len;
				default:
					;
					size_t newlen = len + sizeof(struct vlan_hdr);
					char newbuf[newlen];	/* Local buffer */
					struct ether_header *newhdr = (void *) newbuf;
					struct vlan_hdr *newvlanhdr = (void *) (newhdr + 1);
					/* Copy ethernet header in the local buffer */
					*newhdr = *hdr;
					newhdr->ether_type = htons(ETHERTYPE_VLAN);
					/* Fill vlan header with the untagged VLAN's tag */
					newvlanhdr->vlan = htons(vde_conn->untagged);
					newvlanhdr->ether_type = hdr->ether_type;
					/* Copy payload in local buffer */
					memcpy(newvlanhdr + 1, hdr + 1, len - sizeof(struct ether_header));
					retval = vde_send(vde_conn->conn, newbuf, newlen, flags);
					/* The caller is expecting to send a certain amount of bytes */
					if (retval > len) retval = len;
					return retval;
			}
		}
	} else
		/* Packet is discarded */
		return len;
}

static int vde_vlan_datafd(VDECONN *conn) {
	struct vde_vlan_conn *vde_conn = (struct vde_vlan_conn *)conn;
	return vde_datafd(vde_conn->conn);
}

static int vde_vlan_ctlfd(VDECONN *conn) {
	struct vde_vlan_conn *vde_conn = (struct vde_vlan_conn *)conn;
	return vde_ctlfd(vde_conn->conn);
}

static int vde_vlan_close(VDECONN *conn) {
	struct vde_vlan_conn *vde_conn = (struct vde_vlan_conn *)conn;
	if (vde_conn->tag[LR] != NULL) free(vde_conn->tag[LR]);
	if (vde_conn->tag[RL] != NULL) free(vde_conn->tag[RL]);
	return vde_close(vde_conn->conn);
}
