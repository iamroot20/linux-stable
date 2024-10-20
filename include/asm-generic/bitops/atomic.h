/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS_ATOMIC_H_
#define _ASM_GENERIC_BITOPS_ATOMIC_H_

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <asm/barrier.h>

/*
 * Implementation of atomic bitops using atomic-fetch ops.
 * See Documentation/atomic_bitops.txt for details.
 */

static __always_inline void
arch_set_bit(unsigned int nr, volatile unsigned long *p)
{
	p += BIT_WORD(nr);
	/* IAMROOT20 20240608
	 * nr번째 비트 필드의 값을 1로 세팅한다
	 * *p |= BIT_MASK(nr)
	 */
	arch_atomic_long_or(BIT_MASK(nr), (atomic_long_t *)p);
}

static __always_inline void
arch_clear_bit(unsigned int nr, volatile unsigned long *p)
{
	p += BIT_WORD(nr);
	arch_atomic_long_andnot(BIT_MASK(nr), (atomic_long_t *)p);
}

static __always_inline void
arch_change_bit(unsigned int nr, volatile unsigned long *p)
{
	p += BIT_WORD(nr);
	arch_atomic_long_xor(BIT_MASK(nr), (atomic_long_t *)p);
}

static __always_inline int
arch_test_and_set_bit(unsigned int nr, volatile unsigned long *p)
{
	long old;
	/* IAMROOT20 20240127
	 * BIT_WORD() : 몇 번째 word(long)을 쓸 것인지
	 * BIT_MASK() : word 내에서 해당 bit를 set 
	 */
	unsigned long mask = BIT_MASK(nr);

	p += BIT_WORD(nr);
	old = arch_atomic_long_fetch_or(mask, (atomic_long_t *)p);
	/* IAMROOT20 20240127
	 * ex)
	 * 1) old값에 mask bit가 set되어 있지 않은 경우
	 * 	old = 0001
	 * 	mask = 0010
	 *
	 * 	old & mask = 0000
	 * 	!!(old & mask) -> false
	 *
	 * 2) old값에 mask bit가 set되어 있는 경우
	 * 	old = 0011
	 * 	mask = 0010
	 *
	 * 	old & mask = 0010
	 * 	!!(0ld & mask) -> true
	 */
	return !!(old & mask);
}

static __always_inline int
arch_test_and_clear_bit(unsigned int nr, volatile unsigned long *p)
{
	long old;
	unsigned long mask = BIT_MASK(nr);

	p += BIT_WORD(nr);
	old = arch_atomic_long_fetch_andnot(mask, (atomic_long_t *)p);
	return !!(old & mask);
}

static __always_inline int
arch_test_and_change_bit(unsigned int nr, volatile unsigned long *p)
{
	long old;
	unsigned long mask = BIT_MASK(nr);

	p += BIT_WORD(nr);
	old = arch_atomic_long_fetch_xor(mask, (atomic_long_t *)p);
	return !!(old & mask);
}

#include <asm-generic/bitops/instrumented-atomic.h>

#endif /* _ASM_GENERIC_BITOPS_ATOMIC_H */
