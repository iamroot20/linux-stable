/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS___FLS_H_
#define _ASM_GENERIC_BITOPS___FLS_H_

#include <asm/types.h>

/**
 * __fls - find last (most-significant) set bit in a long word
 * @word: the word to search
 *
 * Undefined if no set bit exists, so code should check against 0 first.
 */
static __always_inline unsigned long __fls(unsigned long word)
{
	int num = BITS_PER_LONG - 1;

/* IAMROOT20 20240629
 * 값이 있는 비트가 나올 때까지 절반씩 범위를 줄여가며 찾는다.
 * word = 0x0000_0000_0000_0003
 * - (word & (0xffff_ffff_0000_0000)), num = 31, word = 0x0000_0003_0000_0000
 * - (word & (0xffff_0000_0000_0000)), num = 15, word = 0x0003_0000_0000_0000
 * - (word & (0xff00_0000_0000_0000)), num = 7,  word = 0x0300_0000_0000_0000
 * - (word & (0xf000_0000_0000_0000)), num = 3,  word = 0x3000_0000_0000_0000
 * - (word & (0xC000_0000_0000_0000)), num = 1,  word = 0xC000_0000_0000_0000
 * - (word & (0x8000_0000_0000_0000)), num = 1
 *
 * word = 0x0000_0000_0000_0005
 * - (word & (0xffff_ffff_0000_0000)), num = 31, word = 0x0000_0005_0000_0000
 * - (word & (0xffff_0000_0000_0000)), num = 15, word = 0x0005_0000_0000_0000
 * - (word & (0xff00_0000_0000_0000)), num = 7,  word = 0x0500_0000_0000_0000
 * - (word & (0xf000_0000_0000_0000)), num = 3,  word = 0x5000_0000_0000_0000
 * - (word & (0xC000_0000_0000_0000)), num = 3,  word = 0x5000_0000_0000_0000
 * - (word & (0x8000_0000_0000_0000)), num = 2
 */
#if BITS_PER_LONG == 64
	if (!(word & (~0ul << 32))) {
		num -= 32;
		word <<= 32;
	}
#endif
	if (!(word & (~0ul << (BITS_PER_LONG-16)))) {
		num -= 16;
		word <<= 16;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-8)))) {
		num -= 8;
		word <<= 8;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-4)))) {
		num -= 4;
		word <<= 4;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-2)))) {
		num -= 2;
		word <<= 2;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-1))))
		num -= 1;
	return num;
}

#endif /* _ASM_GENERIC_BITOPS___FLS_H_ */
