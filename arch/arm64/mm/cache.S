/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Cache maintenance
 *
 * Copyright (C) 2001 Deep Blue Solutions Ltd.
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/errno.h>
#include <linux/linkage.h>
#include <linux/init.h>
#include <asm/assembler.h>
#include <asm/cpufeature.h>
#include <asm/alternative.h>
#include <asm/asm-uaccess.h>

/*
 *	caches_clean_inval_pou_macro(start,end) [fixup]
 *
 *	Ensure that the I and D caches are coherent within specified region.
 *	This is typically used when code has been written to a memory region,
 *	and will be executed.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 *	- fixup   - optional label to branch to on user fault
 */
.macro	caches_clean_inval_pou_macro, fixup
alternative_if ARM64_HAS_CACHE_IDC
	dsb     ishst
	b       .Ldc_skip_\@
alternative_else_nop_endif
	mov     x2, x0
	mov     x3, x1
	dcache_by_line_op cvau, ish, x2, x3, x4, x5, \fixup
.Ldc_skip_\@:
alternative_if ARM64_HAS_CACHE_DIC
	isb
	b	.Lic_skip_\@
alternative_else_nop_endif
	invalidate_icache_by_line x0, x1, x2, x3, \fixup
.Lic_skip_\@:
.endm

/*
 *	caches_clean_inval_pou(start,end)
 *
 *	Ensure that the I and D caches are coherent within specified region.
 *	This is typically used when code has been written to a memory region,
 *	and will be executed.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
SYM_FUNC_START(caches_clean_inval_pou)
	caches_clean_inval_pou_macro
	ret
SYM_FUNC_END(caches_clean_inval_pou)
SYM_FUNC_ALIAS(__pi_caches_clean_inval_pou, caches_clean_inval_pou)

/*
 *	caches_clean_inval_user_pou(start,end)
 *
 *	Ensure that the I and D caches are coherent within specified region.
 *	This is typically used when code has been written to a memory region,
 *	and will be executed.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
SYM_FUNC_START(caches_clean_inval_user_pou)
	uaccess_ttbr0_enable x2, x3, x4

	caches_clean_inval_pou_macro 2f
	mov	x0, xzr
1:
	uaccess_ttbr0_disable x1, x2
	ret
2:
	mov	x0, #-EFAULT
	b	1b
SYM_FUNC_END(caches_clean_inval_user_pou)

/*
 *	icache_inval_pou(start,end)
 *
 *	Ensure that the I cache is invalid within specified region.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
SYM_FUNC_START(icache_inval_pou)
alternative_if ARM64_HAS_CACHE_DIC
	isb
	ret
alternative_else_nop_endif

	invalidate_icache_by_line x0, x1, x2, x3
	ret
SYM_FUNC_END(icache_inval_pou)

/*
 *	dcache_clean_inval_poc(start, end)
 *
 *	Ensure that any D-cache lines for the interval [start, end)
 *	are cleaned and invalidated to the PoC.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
SYM_FUNC_START(__pi_dcache_clean_inval_poc)
	dcache_by_line_op civac, sy, x0, x1, x2, x3
	ret
SYM_FUNC_END(__pi_dcache_clean_inval_poc)
SYM_FUNC_ALIAS(dcache_clean_inval_poc, __pi_dcache_clean_inval_poc)

/*
 *	dcache_clean_pou(start, end)
 *
 * 	Ensure that any D-cache lines for the interval [start, end)
 * 	are cleaned to the PoU.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
SYM_FUNC_START(dcache_clean_pou)
alternative_if ARM64_HAS_CACHE_IDC
	dsb	ishst
	ret
alternative_else_nop_endif
	dcache_by_line_op cvau, ish, x0, x1, x2, x3
	ret
SYM_FUNC_END(dcache_clean_pou)

/*
 *	dcache_inval_poc(start, end)
 *
 * 	Ensure that any D-cache lines for the interval [start, end)
 * 	are invalidated. Any partial lines at the ends of the interval are
 *	also cleaned to PoC to prevent data loss.
 *
 *	- start   - kernel start address of region
 *	- end     - kernel end address of region
 */
SYM_FUNC_START(__pi_dcache_inval_poc)
	/* IAMROOT20 20230722
	 * x2에 cache line-size를 저장하고(64byte), x3에는 ctr_el0[19:16]의 값이 저장되어있다. 
	 * 매크로 위치 : /arch/arm64/include/asm/assembler.h
	 */	
	 // dcache_line_size(&x[2], &x[3]);
	dcache_line_size x2, x3
/* IAMROOT20_END 20230722 *//* IAMROOT20_START 20230729 */
	/* 
	 * IAMROOT20 20230729
	 * 하위 비트를 mask off 하기 위한 준비.
	*/
	// x[3] = x[2] - 1;
	sub	x3, x2, #1
	// ARM_ASM(tst, x[1], x[3]);
	tst	x1, x3				// end cache line aligned?
	// x[1] = x[1]&(~x[3]);
	bic	x1, x1, x3
	/*
	 * IAMROOT20 20230729
	 * bic 다음에 b.eq 가 나오는 이유 : 파이프라인 flush로 인한 reload 방지
	 * - https://developer.arm.com/documentation/ddi0337/e/BABBCJII
	*/
	// if ( COND_EQ ) goto lable_1;
	b.eq	1f
	/*
	 * IAMROOT20 20230729
	 * DC CIVAC : 지정한 주소의 데이터 캐시를 PoC까지 Clean & Invalidate를 수행.
	*/
	// ARM_ASM(dc, CIVAC, x[1]);
	dc	civac, x1			// clean & invalidate D / U line
//lable_1:
	// ARM_ASM(tst, x[0], x[3]);
1:	tst	x0, x3				// start cache line aligned?
	// x[0] &= ~x[3];
	bic	x0, x0, x3
	// if ( COND_EQ ) goto lable_2;
	b.eq	2f
	// ARM_ASM(dc, CIVAC, x[0]);
	dc	civac, x0			// clean & invalidate D / U line
	// goto lable_3;
	b	3f
//lable_2:
	// ARM_ASM(dc, IVAC, x[0]);
2:	dc	ivac, x0			// invalidate D / U line
//lable_3:
	// x[0] += x[2];		// walker + cache line size
3:	add	x0, x0, x2
	// ARM_ASM(cmp, x[0], x[1]);
	cmp	x0, x1
	// if ( COND_LO ) goto lable_2;
	b.lo	2b
	/*
	 * IAMROOT20 20230729
	 * dsb : https://developer.arm.com/documentation/dui0473/m/arm-and-thumb-instructions/dsb
	*/
	// ARM_ASM(dsb,ARM_ASM_B_SY);
	dsb	sy
	// return 1;
	ret
SYM_FUNC_END(__pi_dcache_inval_poc)
SYM_FUNC_ALIAS(dcache_inval_poc, __pi_dcache_inval_poc)

/*
 *	dcache_clean_poc(start, end)
 *
 * 	Ensure that any D-cache lines for the interval [start, end)
 * 	are cleaned to the PoC.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
SYM_FUNC_START(__pi_dcache_clean_poc)
	dcache_by_line_op cvac, sy, x0, x1, x2, x3
	ret
SYM_FUNC_END(__pi_dcache_clean_poc)
SYM_FUNC_ALIAS(dcache_clean_poc, __pi_dcache_clean_poc)

/*
 *	dcache_clean_pop(start, end)
 *
 * 	Ensure that any D-cache lines for the interval [start, end)
 * 	are cleaned to the PoP.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
SYM_FUNC_START(__pi_dcache_clean_pop)
	alternative_if_not ARM64_HAS_DCPOP
	b	dcache_clean_poc
	alternative_else_nop_endif
	dcache_by_line_op cvap, sy, x0, x1, x2, x3
	ret
SYM_FUNC_END(__pi_dcache_clean_pop)
SYM_FUNC_ALIAS(dcache_clean_pop, __pi_dcache_clean_pop)
