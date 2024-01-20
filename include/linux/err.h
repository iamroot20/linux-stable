/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ERR_H
#define _LINUX_ERR_H

#include <linux/compiler.h>
#include <linux/types.h>

#include <asm/errno.h>

/*
 * Kernel pointers have redundant information, so we can use a
 * scheme where we can return either an error code or a normal
 * pointer with the same return value.
 *
 * This should be a per-architecture thing, to allow different
 * error and pointer decisions.
 */
/* IAMROOT20 20240120
 * 커널 포인터에는 중복된 정보가 있으므로 오류 코드나 동일한 반환 값을 가진 일반
 * 포인터를 반환할 수 있는 체계를 사용할 수 있습니다.
 * 이는 다양한 오류 및 포인터 결정을 허용하기 위해 아키텍처별로 이루어져야 합니다.
 */
#define MAX_ERRNO	4095

#ifndef __ASSEMBLY__

/* IAMROOT20 20240120
 * x > (unsigned long)-4095 
 *	->   x > 0xffff_ffff_ffff_f000
 *	커널영역주소는 0xffff_0000_0000_0000 ~ 0xffff_ffff_ffff_ffff
 *	-1(0xffff_ffff_ffff_ffff) ~ -4095(0xffff_ffff_ffff_f000)가 에러, 그 외에는 주소
 *
 * 에러 번호는 1 ~ 34까지 할당되어 있으며 ERR_PTR함수를 호출할때 -를 붙여 호출한다
 * exam) ERR_PTR(-ENOMEM)
 * 따라서 에러 번호는 -1 ~ -34까지 해당되며 unsigned long으로 바꾸면
 * 0xffff_ffff_ffff_ffff(-1) ~ 0xffff_ffff_ffff_ffde(-34)에 해당된다.
 *
 * include/uapi/asm-generic/errno-base.h 참고
 */
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void * __must_check ERR_PTR(long error)
{
	return (void *) error;
}

static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}

static inline bool __must_check IS_ERR(__force const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return unlikely(!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

/**
 * ERR_CAST - Explicitly cast an error-valued pointer to another pointer type
 * @ptr: The pointer to cast.
 *
 * Explicitly cast an error-valued pointer to another pointer type in such a
 * way as to make it clear that's what's going on.
 */
static inline void * __must_check ERR_CAST(__force const void *ptr)
{
	/* cast away the const */
	return (void *) ptr;
}

static inline int __must_check PTR_ERR_OR_ZERO(__force const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return 0;
}

#endif

#endif /* _LINUX_ERR_H */
