/*
 * Linux Security Module interfaces
 *
 * Copyright (C) 2001 WireX Communications, Inc <chris@wirex.com>
 * Copyright (C) 2001 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2001 Networks Associates Technology, Inc <ssmalley@nai.com>
 * Copyright (C) 2001 James Morris <jmorris@intercode.com.au>
 * Copyright (C) 2001 Silicon Graphics, Inc. (Trust Technology Group)
 * Copyright (C) 2015 Intel Corporation.
 * Copyright (C) 2015 Casey Schaufler <casey@schaufler-ca.com>
 * Copyright (C) 2016 Mellanox Techonologies
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Due to this file being licensed under the GPL there is controversy over
 *	whether this permits you to write a module that #includes this file
 *	without placing your module under the GPL.  Please consult a lawyer for
 *	advice before doing this.
 *
 */

#ifndef __LINUX_LSM_HOOKS_H
#define __LINUX_LSM_HOOKS_H

#include <linux/security.h>
#include <linux/init.h>
#include <linux/rculist.h>

/* IAMROOT20 20240203 
 * union security_list_options {
 *     int (*binder_set_context_mgr)(const struct cred *mgr);
 *     int (*binder_transaction)(const struct cred *from,const struct cred *to);
 *     ...
 * };
 */
union security_list_options {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...) RET (*NAME)(__VA_ARGS__);
	#include "lsm_hook_defs.h"
	#undef LSM_HOOK
};

/* IAMROOT20 20240203 
 * struct security_hook_heads {
 *     struct hlist_head binder_set_context_mgr;
 *     struct hlist_head binder_transaction;
 *     ....
 * } __attribute__((__designated_init__)) __attribute__((randomize_layout));
 * __attribute__((__designated_init__)): 지정된 초기화 사용
 * __attribute__((randomize_layout)): 구조체 필드 배치 무작위화
 * 구조체 필드 위치가 랜덤하게 결정되면 초기화시 의도했던대로 안되기 때문에 지정된 초기화 옵션을 사용하는 것으로 보임
 */
struct security_hook_heads {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...) struct hlist_head NAME;
	#include "lsm_hook_defs.h"
	#undef LSM_HOOK
} __randomize_layout;

/*
 * Security module hook list structure.
 * For use with generic list macros for common operations.
 */
struct security_hook_list {
	struct hlist_node		list;
	struct hlist_head		*head;
	union security_list_options	hook;
	const char			*lsm;
} __randomize_layout;

/*
 * Security blob size or offset data.
 */
struct lsm_blob_sizes {
	int	lbs_cred;
	int	lbs_file;
	int	lbs_inode;
	int	lbs_superblock;
	int	lbs_ipc;
	int	lbs_msg_msg;
	int	lbs_task;
};

/*
 * LSM_RET_VOID is used as the default value in LSM_HOOK definitions for void
 * LSM hooks (in include/linux/lsm_hook_defs.h).
 */
#define LSM_RET_VOID ((void) 0)

/*
 * Initializing a security_hook_list structure takes
 * up a lot of space in a source file. This macro takes
 * care of the common case and reduces the amount of
 * text involved.
 */
#define LSM_HOOK_INIT(HEAD, HOOK) \
	{ .head = &security_hook_heads.HEAD, .hook = { .HEAD = HOOK } }

extern struct security_hook_heads security_hook_heads;
extern char *lsm_names;

extern void security_add_hooks(struct security_hook_list *hooks, int count,
				const char *lsm);

#define LSM_FLAG_LEGACY_MAJOR	BIT(0)
#define LSM_FLAG_EXCLUSIVE	BIT(1)

enum lsm_order {
	LSM_ORDER_FIRST = -1,	/* This is only for capabilities. */
	LSM_ORDER_MUTABLE = 0,
	LSM_ORDER_LAST = 1,	/* This is only for integrity. */
};

struct lsm_info {
	const char *name;	/* Required. */
	enum lsm_order order;	/* Optional: default is LSM_ORDER_MUTABLE */
	unsigned long flags;	/* Optional: flags describing LSM */
	int *enabled;		/* Optional: controlled by CONFIG_LSM */
	int (*init)(void);	/* Required. */
	struct lsm_blob_sizes *blobs; /* Optional: for blob sharing. */
};

extern struct lsm_info __start_lsm_info[], __end_lsm_info[];
extern struct lsm_info __start_early_lsm_info[], __end_early_lsm_info[];

#define DEFINE_LSM(lsm)							\
	static struct lsm_info __lsm_##lsm				\
		__used __section(".lsm_info.init")			\
		__aligned(sizeof(unsigned long))

#define DEFINE_EARLY_LSM(lsm)						\
	static struct lsm_info __early_lsm_##lsm			\
		__used __section(".early_lsm_info.init")		\
		__aligned(sizeof(unsigned long))

extern int lsm_inode_alloc(struct inode *inode);

#endif /* ! __LINUX_LSM_HOOKS_H */
