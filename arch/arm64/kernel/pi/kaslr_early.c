// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

// NOTE: code in this file runs *very* early, and is not permitted to use
// global variables or anything that relies on absolute addressing.

#include <linux/libfdt.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/string.h>

#include <asm/archrandom.h>
#include <asm/memory.h>

/* taken from lib/string.c */
static char *__strstr(const char *s1, const char *s2)
{
	size_t l1, l2;

	l2 = strlen(s2);
	if (!l2)
		return (char *)s1;
	l1 = strlen(s1);
	while (l1 >= l2) {
		l1--;
		if (!memcmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	}
	return NULL;
}
static bool cmdline_contains_nokaslr(const u8 *cmdline)
{
	const u8 *str;

	str = __strstr(cmdline, "nokaslr");
	return str == cmdline || (str > cmdline && *(str - 1) == ' ');
}

static bool is_kaslr_disabled_cmdline(void *fdt)
{
	if (!IS_ENABLED(CONFIG_CMDLINE_FORCE)) {
		int node;
		const u8 *prop;

		node = fdt_path_offset(fdt, "/chosen");
		if (node < 0)
			goto out;

		prop = fdt_getprop(fdt, node, "bootargs", NULL);
		if (!prop)
			goto out;

		if (cmdline_contains_nokaslr(prop))
			return true;

		if (IS_ENABLED(CONFIG_CMDLINE_EXTEND))
			goto out;

		return false;
	}
out:
	return cmdline_contains_nokaslr(CONFIG_CMDLINE);
}

static u64 get_kaslr_seed(void *fdt)
{
	int node, len;
	fdt64_t *prop;
	u64 ret;

	node = fdt_path_offset(fdt, "/chosen");
	if (node < 0)
		return 0;

	prop = fdt_getprop_w(fdt, node, "kaslr-seed", &len);
	if (!prop || len != sizeof(u64))
		return 0;

	ret = fdt64_to_cpu(*prop);
	*prop = 0;
	return ret;
}

asmlinkage u64 kaslr_early_init(void *fdt)
{
	u64 seed;
	
	/* IAMROOT20 20231028
	 * cmdline에서 kaslr이 disable되어 있는지 확인
	 */
	if (is_kaslr_disabled_cmdline(fdt))
		return 0;

	/* IAMROOT20 20231028
	 * DT에서 kaslr seed 값을 read
	 */
	seed = get_kaslr_seed(fdt);
	/* IAMROOT20 20231028
	 * DT에 seed 값이 존재하지 않으면, 
	 * RNDR 레지스터를 읽어 seed를 얻음
	 */
	if (!seed) {
		if (!__early_cpu_has_rndr() ||
		    !__arm64_rndr((unsigned long *)&seed))
			return 0;
	}

	/*
	 * OK, so we are proceeding with KASLR enabled. Calculate a suitable
	 * kernel image offset from the seed. Let's place the kernel in the
	 * middle half of the VMALLOC area (VA_BITS_MIN - 2), and stay clear of
	 * the lower and upper quarters to avoid colliding with other
	 * allocations.
	 */
	/* IAMROOT20 20231028
	 * seed, VA_BITS_MIN을 이용하여 kaslr offset을 return
	 */
	return BIT(VA_BITS_MIN - 3) + (seed & GENMASK(VA_BITS_MIN - 3, 0));
}
