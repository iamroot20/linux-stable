// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/mm/init.c
 *
 * Copyright (C) 1995-2005 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/cache.h>
#include <linux/mman.h>
#include <linux/nodemask.h>
#include <linux/initrd.h>
#include <linux/gfp.h>
#include <linux/memblock.h>
#include <linux/sort.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/dma-direct.h>
#include <linux/dma-map-ops.h>
#include <linux/efi.h>
#include <linux/swiotlb.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/kexec.h>
#include <linux/crash_dump.h>
#include <linux/hugetlb.h>
#include <linux/acpi_iort.h>
#include <linux/kmemleak.h>

#include <asm/boot.h>
#include <asm/fixmap.h>
#include <asm/kasan.h>
#include <asm/kernel-pgtable.h>
#include <asm/kvm_host.h>
#include <asm/memory.h>
#include <asm/numa.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <linux/sizes.h>
#include <asm/tlb.h>
#include <asm/alternative.h>
#include <asm/xen/swiotlb-xen.h>

/*
 * We need to be able to catch inadvertent references to memstart_addr
 * that occur (potentially in generic code) before arm64_memblock_init()
 * executes, which assigns it its actual value. So use a default value
 * that cannot be mistaken for a real physical address.
 */
s64 memstart_addr __ro_after_init = -1;
EXPORT_SYMBOL(memstart_addr);

/*
 * If the corresponding config options are enabled, we create both ZONE_DMA
 * and ZONE_DMA32. By default ZONE_DMA covers the 32-bit addressable memory
 * unless restricted on specific platforms (e.g. 30-bit on Raspberry Pi 4).
 * In such case, ZONE_DMA32 covers the rest of the 32-bit addressable memory,
 * otherwise it is empty.
 */
/* IAMROOT20 20240810
 * arm64_dma_phys_limit	0x1_0000_0000
 *	zone_sizes_init()
 */
phys_addr_t __ro_after_init arm64_dma_phys_limit;

/* Current arm64 boot protocol requires 2MB alignment */
#define CRASH_ALIGN			SZ_2M

#define CRASH_ADDR_LOW_MAX		arm64_dma_phys_limit
#define CRASH_ADDR_HIGH_MAX		(PHYS_MASK + 1)

#define DEFAULT_CRASH_KERNEL_LOW_SIZE	(128UL << 20)

static int __init reserve_crashkernel_low(unsigned long long low_size)
{
	unsigned long long low_base;

	low_base = memblock_phys_alloc_range(low_size, CRASH_ALIGN, 0, CRASH_ADDR_LOW_MAX);
	if (!low_base) {
		pr_err("cannot allocate crashkernel low memory (size:0x%llx).\n", low_size);
		return -ENOMEM;
	}

	pr_info("crashkernel low memory reserved: 0x%08llx - 0x%08llx (%lld MB)\n",
		low_base, low_base + low_size, low_size >> 20);

	crashk_low_res.start = low_base;
	crashk_low_res.end   = low_base + low_size - 1;
	insert_resource(&iomem_resource, &crashk_low_res);

	return 0;
}

/*
 * reserve_crashkernel() - reserves memory for crash kernel
 *
 * This function reserves memory area given in "crashkernel=" kernel command
 * line parameter. The memory reserved is used by dump capture kernel when
 * primary kernel is crashing.
 */
static void __init reserve_crashkernel(void)
{
	unsigned long long crash_base, crash_size;
	unsigned long long crash_low_size = 0;
	unsigned long long crash_max = CRASH_ADDR_LOW_MAX;
	char *cmdline = boot_command_line;
	int ret;
	bool fixed_base = false;

	if (!IS_ENABLED(CONFIG_KEXEC_CORE))
		return;

	/* crashkernel=X[@offset] */
	ret = parse_crashkernel(cmdline, memblock_phys_mem_size(),
				&crash_size, &crash_base);
	if (ret == -ENOENT) {
		ret = parse_crashkernel_high(cmdline, 0, &crash_size, &crash_base);
		if (ret || !crash_size)
			return;

		/*
		 * crashkernel=Y,low can be specified or not, but invalid value
		 * is not allowed.
		 */
		ret = parse_crashkernel_low(cmdline, 0, &crash_low_size, &crash_base);
		if (ret == -ENOENT)
			crash_low_size = DEFAULT_CRASH_KERNEL_LOW_SIZE;
		else if (ret)
			return;

		crash_max = CRASH_ADDR_HIGH_MAX;
	} else if (ret || !crash_size) {
		/* The specified value is invalid */
		return;
	}

	crash_size = PAGE_ALIGN(crash_size);

	/* User specifies base address explicitly. */
	if (crash_base) {
		fixed_base = true;
		crash_max = crash_base + crash_size;
	}

retry:
	crash_base = memblock_phys_alloc_range(crash_size, CRASH_ALIGN,
					       crash_base, crash_max);
	if (!crash_base) {
		/*
		 * If the first attempt was for low memory, fall back to
		 * high memory, the minimum required low memory will be
		 * reserved later.
		 */
		if (!fixed_base && (crash_max == CRASH_ADDR_LOW_MAX)) {
			crash_max = CRASH_ADDR_HIGH_MAX;
			crash_low_size = DEFAULT_CRASH_KERNEL_LOW_SIZE;
			goto retry;
		}

		pr_warn("cannot allocate crashkernel (size:0x%llx)\n",
			crash_size);
		return;
	}

	if ((crash_base > CRASH_ADDR_LOW_MAX - crash_low_size) &&
	     crash_low_size && reserve_crashkernel_low(crash_low_size)) {
		memblock_phys_free(crash_base, crash_size);
		return;
	}

	pr_info("crashkernel reserved: 0x%016llx - 0x%016llx (%lld MB)\n",
		crash_base, crash_base + crash_size, crash_size >> 20);

	/*
	 * The crashkernel memory will be removed from the kernel linear
	 * map. Inform kmemleak so that it won't try to access it.
	 */
	kmemleak_ignore_phys(crash_base);
	if (crashk_low_res.end)
		kmemleak_ignore_phys(crashk_low_res.start);

	crashk_res.start = crash_base;
	crashk_res.end = crash_base + crash_size - 1;
	insert_resource(&iomem_resource, &crashk_res);
}

/*
 * Return the maximum physical address for a zone accessible by the given bits
 * limit. If DRAM starts above 32-bit, expand the zone to the maximum
 * available memory, otherwise cap it at 32-bit.
 */
static phys_addr_t __init max_zone_phys(unsigned int zone_bits)
{
	/* IAMROOT20 20240803
	 * DMA_BIT_MASK(32) = 0xFFFF_FFFF
	 */
	phys_addr_t zone_mask = DMA_BIT_MASK(zone_bits);
	phys_addr_t phys_start = memblock_start_of_DRAM();

	/* IAMROOT20 20240803
	 * phys_start > 4G 인 경우
	 * - zone_mask = 0xFFFF_FFFF_FFFF_FFFF
	 *
	 * 4G >= phys_start > zone_mask
	 * - zone_mask = 0xFFFF_FFFF
	 */
	if (phys_start > U32_MAX)
		zone_mask = PHYS_ADDR_MAX;
	else if (phys_start > zone_mask)
		zone_mask = U32_MAX;

	return min(zone_mask, memblock_end_of_DRAM() - 1) + 1;
}

static void __init zone_sizes_init(void)
{
	/* IAMROOT20 20240803
	 * MAX_NR_ZONES	4
	 * - config에 따라 MAX_NR_ZONES가 달라짐
	 * - default config에서는 ZONE_DMA, ZONE_DMA32, ZONE_NORMAL, ZONE_MOVABLE
	 *
	 * dma32_phys_limit = 0xFFFF_FFFF
	 */
	/* IAMROOT20 20240810
	 * max_zone_pfns[ZONE_DMA]	= 0x100000
	 * max_zone_pfns[ZONE_DMA32]	= 0x100000
	 * max_zone_pfns[ZONE_NORMAL]	= max_pfn
	 */
	unsigned long max_zone_pfns[MAX_NR_ZONES]  = {0};
	unsigned int __maybe_unused acpi_zone_dma_bits;
	unsigned int __maybe_unused dt_zone_dma_bits;
	phys_addr_t __maybe_unused dma32_phys_limit = max_zone_phys(32);

#ifdef CONFIG_ZONE_DMA
	acpi_zone_dma_bits = fls64(acpi_iort_dma_get_max_cpu_address());
	/* IAMROOT20 20240810
	 * of_dma_get_max_cpu_address(NULL)
	 * - "dma-ranges"의 dma 주소를 cpu 주소로 변환했을 때, max 주소 값을 return
	 */
	dt_zone_dma_bits = fls64(of_dma_get_max_cpu_address(NULL));
	zone_dma_bits = min3(32U, dt_zone_dma_bits, acpi_zone_dma_bits);
	arm64_dma_phys_limit = max_zone_phys(zone_dma_bits);
	max_zone_pfns[ZONE_DMA] = PFN_DOWN(arm64_dma_phys_limit);
#endif
#ifdef CONFIG_ZONE_DMA32
	max_zone_pfns[ZONE_DMA32] = PFN_DOWN(dma32_phys_limit);
	if (!arm64_dma_phys_limit)
		arm64_dma_phys_limit = dma32_phys_limit;
#endif
	if (!arm64_dma_phys_limit)
		arm64_dma_phys_limit = PHYS_MASK + 1;
	max_zone_pfns[ZONE_NORMAL] = max_pfn;

	free_area_init(max_zone_pfns);
}

int pfn_is_map_memory(unsigned long pfn)
{
	phys_addr_t addr = PFN_PHYS(pfn);

	/* avoid false positives for bogus PFNs, see comment in pfn_valid() */
	if (PHYS_PFN(addr) != pfn)
		return 0;

	return memblock_is_map_memory(addr);
}
EXPORT_SYMBOL(pfn_is_map_memory);

static phys_addr_t memory_limit __ro_after_init = PHYS_ADDR_MAX;

/*
 * Limit the memory size that was specified via FDT.
 */
static int __init early_mem(char *p)
{
	if (!p)
		return 1;

	memory_limit = memparse(p, &p) & PAGE_MASK;
	pr_notice("Memory limited to %lldMB\n", memory_limit >> 20);

	return 0;
}
early_param("mem", early_mem);

void __init arm64_memblock_init(void)
{
	/* IAMROOT20 20240330
	 * ex) PAGE_END = 0xffff_8000_0000_0000
	 *     _PAGE_OFFSET(vabits_actual) = 0xffff_0000_0000_0000
	 *     0xffff_0000_0000_0000 ~ 0xffff_8000_0000_0000은 linear
	 */
	s64 linear_region_size = PAGE_END - _PAGE_OFFSET(vabits_actual);

	/*
	 * Corner case: 52-bit VA capable systems running KVM in nVHE mode may
	 * be limited in their ability to support a linear map that exceeds 51
	 * bits of VA space, depending on the placement of the ID map. Given
	 * that the placement of the ID map may be randomized, let's simply
	 * limit the kernel's linear map to 51 bits as well if we detect this
	 * configuration.
	 */
	if (IS_ENABLED(CONFIG_KVM) && vabits_actual == 52 &&
	    is_hyp_mode_available() && !is_kernel_in_hyp_mode()) {
		pr_info("Capping linear region to 51 bits for KVM in nVHE mode on LVA capable hardware.\n");
		linear_region_size = min_t(u64, linear_region_size, BIT(51));
	}

	/* Remove memory above our supported physical address size */
	/* IAMROOT20 20240330
	 * ex) pa 48bit 사용 시
	 *     0x0001_0000_0000_0000 ~ 0xffff_ffff_ffff_ffff의 범위의 물리 메모리는 사용되지 않음으로 memblock.memory에서 제거
	 */
	memblock_remove(1ULL << PHYS_MASK_SHIFT, ULLONG_MAX);

	/*
	 * Select a suitable value for the base of physical memory.
	 */
	/* IAMROOT20 20240330 
	 * memblock.memory.regions[0]의 base를 ARM64_MEMSTART_ALIGN(ex 1GB)에 맞춰서 내림하여 memstart_addr을 설정
	 * ex) memstart_addr = 0x0000_0000_4000_0000
	 */
	memstart_addr = round_down(memblock_start_of_DRAM(),
				   ARM64_MEMSTART_ALIGN);

	if ((memblock_end_of_DRAM() - memstart_addr) > linear_region_size)
		pr_warn("Memory doesn't fit in the linear mapping, VA_BITS too small\n");

	/*
	 * Remove the memory that we will not be able to cover with the
	 * linear mapping. Take care not to clip the kernel which may be
	 * high in memory.
	 */
	/* IAMROOT20 20240330
	 * ex) memstart_addr = 0x0000_0000_4000_0000
	 *     linear_region_size = 0x0000_8000_0000_0000
	 * memstart_addr + linear_region_size과 __pa_symbol(_end) 중 더 큰 값부터 0xffff_ffff_ffff_ffff까지 범위를 memblock.memory에서 제거
	 */
	memblock_remove(max_t(u64, memstart_addr + linear_region_size,
			__pa_symbol(_end)), ULLONG_MAX);
	/* IAMROOT20 20240330
	 * memstart_addr부터 memblock_end_of_DRAM()까지의 크기가 linear_region_size보다 큰 경우
	 */
	if (memstart_addr + linear_region_size < memblock_end_of_DRAM()) {
		/* ensure that memstart_addr remains sufficiently aligned */
		/* IAMROOT20 20240330 
		 * memblock_end_of_DRAM()에서 아래쪽으로 linear_region_size만큼으로 memstart_addr을 재설정
		 */
		memstart_addr = round_up(memblock_end_of_DRAM() - linear_region_size,
					 ARM64_MEMSTART_ALIGN);
		/* IAMROOT20 20240330
		 * 0부터 새로운 memstart_addr까지 memblock.memory에서 제거
		 */
		memblock_remove(0, memstart_addr);
	}

	/*
	 * If we are running with a 52-bit kernel VA config on a system that
	 * does not support it, we have to place the available physical
	 * memory in the 48-bit addressable part of the linear region, i.e.,
	 * we have to move it upward. Since memstart_addr represents the
	 * physical address of PAGE_OFFSET, we have to *subtract* from it.
	 */
	/* IAMROOT20 20240330
	 * CONFIG_VA_52bit이고 vabits_actual이 52bit가 아닐 경우
	 * 52bit 기준으로 설정된 가상 주소를 48bit 기준으로 변경
	 */
	if (IS_ENABLED(CONFIG_ARM64_VA_BITS_52) && (vabits_actual != 52))
		memstart_addr -= _PAGE_OFFSET(48) - _PAGE_OFFSET(52);

	/*
	 * Apply the memory limit if it was set. Since the kernel may be loaded
	 * high up in memory, add back the kernel region that must be accessible
	 * via the linear mapping.
	 */
	/* IAMROOT20 20240330
	 * arm64의 경우 memory_limit는 PHYS_ADDR_MAX로 선언할때 초기화되어 있음
	 * 만약 boot parameter의 mem으로 값이 설정되어 들어왔다면 memory_limit는 해당 값으로 변경되어 있었을 것
	 */
	if (memory_limit != PHYS_ADDR_MAX) {
		memblock_mem_limit_remove_map(memory_limit);
		memblock_add(__pa_symbol(_text), (u64)(_end - _text));
	}

	/* IAMROOT20 20240330
	 * fdt에서 initrd의 메모리 영역을 설정했다면
	 */
	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/*
		 * Add back the memory we just removed if it results in the
		 * initrd to become inaccessible via the linear mapping.
		 * Otherwise, this is a no-op
		 */
		/* IAMROOT20 20240330
		 * base와 size를 설정
		 */
		u64 base = phys_initrd_start & PAGE_MASK;
		u64 size = PAGE_ALIGN(phys_initrd_start + phys_initrd_size) - base;

		/*
		 * We can only add back the initrd memory if we don't end up
		 * with more memory than we can address via the linear mapping.
		 * It is up to the bootloader to position the kernel and the
		 * initrd reasonably close to each other (i.e., within 32 GB of
		 * each other) so that all granule/#levels combinations can
		 * always access both.
		 */
		/* IAMROOT20 20240330
		 * base가 memblock_start_of_DRAM()보다 작거나
		 * (base + size)가 (memblock_start_of_DRAm() + linear_region_size)보다 크면
		 * initrd의 메모리 영역이 linear mapping될 수 없으므로 warning
		 */
		if (WARN(base < memblock_start_of_DRAM() ||
			 base + size > memblock_start_of_DRAM() +
				       linear_region_size,
			"initrd not fully accessible via the linear mapping -- please check your bootloader ...\n")) {
			phys_initrd_size = 0;
		} else {
			/* IAMROOT20 20240330
			 * initrd의 메모리 영역을 memblock.memory에 등록
			 */
			memblock_add(base, size);
			/* IAMROOT20 20240330
			 * memblock.memory에서 해당 region에서 MEMBLOCK_NOMAP flag를 clear
			 */
			memblock_clear_nomap(base, size);
			/* IAMROOT20 20240330
			 * initrd의 메모리 영역을 memblock.reserved에 등록
			 */
			memblock_reserve(base, size);
		}
	}

	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE)) {
		extern u16 memstart_offset_seed;
		/* IAMROOT20 20240330
		 * id_aa64mmfr0_el1 레지스터 값을 읽음
		 */
		u64 mmfr0 = read_cpuid(ID_AA64MMFR0_EL1);
		/* IAMROOT20 20240330
		 * id_aa64mmfr0_el1.parange 필드 값을 추출
		 * ex) pa 48bit, parange = 0b0101
		 */
		int parange = cpuid_feature_extract_unsigned_field(
					mmfr0, ID_AA64MMFR0_EL1_PARANGE_SHIFT);
		/* IAMROOT20 20240330
		 * ex) pa 48bit
		 *     range = 0x0000_8000_0000_0000 - 0x0001_0000_0000_0000
		 *     range = -0x0000_8000_0000_0000
		 */
		s64 range = linear_region_size -
			    BIT(id_aa64mmfr0_parange_to_phys_shift(parange));

		/*
		 * If the size of the linear region exceeds, by a sufficient
		 * margin, the size of the region that the physical memory can
		 * span, randomize the linear region as well.
		 */
		/* IAMROOT20 20240330
		 * ex) pa 48bit일 경우 range가 음수이므로 해당 if문에 진입하지 못함
		 */
		if (memstart_offset_seed > 0 && range >= (s64)ARM64_MEMSTART_ALIGN) {
			range /= ARM64_MEMSTART_ALIGN;
			memstart_addr -= ARM64_MEMSTART_ALIGN *
					 ((range * memstart_offset_seed) >> 16);
		}
	}

	/*
	 * Register the kernel text, kernel data, initrd, and initial
	 * pagetables with memblock.
	 */
	/* IAMROOT20 20240330
	 * kernel image 물리 주소 region을 memblock.reserved에 저장
	 */
	memblock_reserve(__pa_symbol(_stext), _end - _stext);
	/* IAMROOT20 20240330
	 * initrd_start, initrd_end에 가상주소를 저장
	 */
	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/* the generic initrd code expects virtual addresses */
		initrd_start = __phys_to_virt(phys_initrd_start);
		initrd_end = initrd_start + phys_initrd_size;
	}

	early_init_fdt_scan_reserved_mem();

	/* IAMROOT20 20240413
	 * __va : 물리 주소를 '리니어 커널 메모리 매핑 영역'의 가상 주소로 변환
	 *  - 리니어 커널 메모리 매핑 영역(4K, VA_BITS=48)
	 *    : PAGE_OFFSET(0xffff_0000_0000_0000) ~ 0xffff_8000_0000_0000
	 */
	high_memory = __va(memblock_end_of_DRAM() - 1) + 1;
}

void __init bootmem_init(void)
{
	unsigned long min, max;

	min = PFN_UP(memblock_start_of_DRAM());
	max = PFN_DOWN(memblock_end_of_DRAM());

	early_memtest(min << PAGE_SHIFT, max << PAGE_SHIFT);

	max_pfn = max_low_pfn = max;
	min_low_pfn = min;

	arch_numa_init();

	/*
	 * must be done after arch_numa_init() which calls numa_init() to
	 * initialize node_online_map that gets used in hugetlb_cma_reserve()
	 * while allocating required CMA size across online nodes.
	 */
#if defined(CONFIG_HUGETLB_PAGE) && defined(CONFIG_CMA)
	arm64_hugetlb_cma_reserve();
#endif

	dma_pernuma_cma_reserve();

	/* IAMROOT20 20240720
	 * kvm은 분석하지 않음
	 */
	kvm_hyp_reserve();

	/*
	 * sparse_init() tries to allocate memory from memblock, so must be
	 * done after the fixed reservations
	 */
	sparse_init();
	zone_sizes_init();

	/*
	 * Reserve the CMA area after arm64_dma_phys_limit was initialised.
	 */
	dma_contiguous_reserve(arm64_dma_phys_limit);

	/*
	 * request_standard_resources() depends on crashkernel's memory being
	 * reserved, so do it here.
	 */
	reserve_crashkernel();

	memblock_dump_all();
}

/*
 * mem_init() marks the free areas in the mem_map and tells us how much memory
 * is free.  This is done after various parts of the system have claimed their
 * memory after the kernel image.
 */
void __init mem_init(void)
{
	swiotlb_init(max_pfn > PFN_DOWN(arm64_dma_phys_limit), SWIOTLB_VERBOSE);

	/* this will put all unused low memory onto the freelists */
	memblock_free_all();

	/*
	 * Check boundaries twice: Some fundamental inconsistencies can be
	 * detected at build time already.
	 */
#ifdef CONFIG_COMPAT
	BUILD_BUG_ON(TASK_SIZE_32 > DEFAULT_MAP_WINDOW_64);
#endif

	/*
	 * Selected page table levels should match when derived from
	 * scratch using the virtual address range and page size.
	 */
	BUILD_BUG_ON(ARM64_HW_PGTABLE_LEVELS(CONFIG_ARM64_VA_BITS) !=
		     CONFIG_PGTABLE_LEVELS);

	if (PAGE_SIZE >= 16384 && get_num_physpages() <= 128) {
		extern int sysctl_overcommit_memory;
		/*
		 * On a machine this small we won't get anywhere without
		 * overcommit, so turn it on by default.
		 */
		sysctl_overcommit_memory = OVERCOMMIT_ALWAYS;
	}
}

void free_initmem(void)
{
	free_reserved_area(lm_alias(__init_begin),
			   lm_alias(__init_end),
			   POISON_FREE_INITMEM, "unused kernel");
	/*
	 * Unmap the __init region but leave the VM area in place. This
	 * prevents the region from being reused for kernel modules, which
	 * is not supported by kallsyms.
	 */
	vunmap_range((u64)__init_begin, (u64)__init_end);
}

void dump_mem_limit(void)
{
	if (memory_limit != PHYS_ADDR_MAX) {
		pr_emerg("Memory Limit: %llu MB\n", memory_limit >> 20);
	} else {
		pr_emerg("Memory Limit: none\n");
	}
}
