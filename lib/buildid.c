// SPDX-License-Identifier: GPL-2.0

#include <linux/buildid.h>
#include <linux/cache.h>
#include <linux/elf.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>

#define BUILD_ID 3

/*
 * Parse build id from the note segment. This logic can be shared between
 * 32-bit and 64-bit system, because Elf32_Nhdr and Elf64_Nhdr are
 * identical.
 */
static int parse_build_id_buf(unsigned char *build_id,
			      __u32 *size,
			      const void *note_start,
			      Elf32_Word note_size)
{
	Elf32_Word note_offs = 0, new_offs;

	/* IAMROOT20 20240113
	 * sizeof(Elf32_Nhdr) = 12
	 *
	 * exam)
	 *    +-------------------------+
	 *    |<--------Elf32_Nhdr----->|
	 *    |namesz |descsz  | type   |
	 *    +-------------------------+
	 *    04000000 14000000 03000000 474e5500  ............GNU.
	 *    |<---------------------- build id -  ---------------
	 *    b752b23a ddbcb03d 42316e26 804bbcba  .R.:...=B1n&.K..
	 *    |------>|
	 *    415c0cb6 06000000 04000000 01010000  A\..............
	 *    4c696e75 78000000 00000000 06000000  Linux...........
	 *    01000000 00010000 4c696e75 78000000  ........Linux...
	 *    00000000  
	 *
	 *    build_id = b752b23a ddbcb03d 42316e26 804bbcba 415c0cb6
	 */
	while (note_offs + sizeof(Elf32_Nhdr) < note_size) {
		Elf32_Nhdr *nhdr = (Elf32_Nhdr *)(note_start + note_offs);

		if (nhdr->n_type == BUILD_ID &&
		    nhdr->n_namesz == sizeof("GNU") &&
		    !strcmp((char *)(nhdr + 1), "GNU") &&
		    nhdr->n_descsz > 0 &&
		    nhdr->n_descsz <= BUILD_ID_SIZE_MAX) {
			/* IAMROOT20 20240113
			 * Elf32_Nhdr과 name 다음에 있는 build id를 build_id에 복사한다.
			 */
			memcpy(build_id,
			       note_start + note_offs +
			       ALIGN(sizeof("GNU"), 4) + sizeof(Elf32_Nhdr),
			       nhdr->n_descsz);
			/* IAMROOT20 20240113
			 * build_id 남은 부분을 0으로 셋팅한다.
			 */
			memset(build_id + nhdr->n_descsz, 0,
			       BUILD_ID_SIZE_MAX - nhdr->n_descsz);
			if (size)
				*size = nhdr->n_descsz;
			return 0;
		}
		new_offs = note_offs + sizeof(Elf32_Nhdr) +
			ALIGN(nhdr->n_namesz, 4) + ALIGN(nhdr->n_descsz, 4);
		if (new_offs <= note_offs)  /* overflow */
			break;
		note_offs = new_offs;
	}

	return -EINVAL;
}

static inline int parse_build_id(const void *page_addr,
				 unsigned char *build_id,
				 __u32 *size,
				 const void *note_start,
				 Elf32_Word note_size)
{
	/* check for overflow */
	if (note_start < page_addr || note_start + note_size < note_start)
		return -EINVAL;

	/* only supports note that fits in the first page */
	if (note_start + note_size > page_addr + PAGE_SIZE)
		return -EINVAL;

	return parse_build_id_buf(build_id, size, note_start, note_size);
}

/* Parse build ID from 32-bit ELF */
static int get_build_id_32(const void *page_addr, unsigned char *build_id,
			   __u32 *size)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)page_addr;
	Elf32_Phdr *phdr;
	int i;

	/* only supports phdr that fits in one page */
	if (ehdr->e_phnum >
	    (PAGE_SIZE - sizeof(Elf32_Ehdr)) / sizeof(Elf32_Phdr))
		return -EINVAL;

	phdr = (Elf32_Phdr *)(page_addr + sizeof(Elf32_Ehdr));

	for (i = 0; i < ehdr->e_phnum; ++i) {
		if (phdr[i].p_type == PT_NOTE &&
		    !parse_build_id(page_addr, build_id, size,
				    page_addr + phdr[i].p_offset,
				    phdr[i].p_filesz))
			return 0;
	}
	return -EINVAL;
}

/* Parse build ID from 64-bit ELF */
static int get_build_id_64(const void *page_addr, unsigned char *build_id,
			   __u32 *size)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)page_addr;
	Elf64_Phdr *phdr;
	int i;

	/* only supports phdr that fits in one page */
	if (ehdr->e_phnum >
	    (PAGE_SIZE - sizeof(Elf64_Ehdr)) / sizeof(Elf64_Phdr))
		return -EINVAL;

	phdr = (Elf64_Phdr *)(page_addr + sizeof(Elf64_Ehdr));

	for (i = 0; i < ehdr->e_phnum; ++i) {
		if (phdr[i].p_type == PT_NOTE &&
		    !parse_build_id(page_addr, build_id, size,
				    page_addr + phdr[i].p_offset,
				    phdr[i].p_filesz))
			return 0;
	}
	return -EINVAL;
}

/*
 * Parse build ID of ELF file mapped to vma
 * @vma:      vma object
 * @build_id: buffer to store build id, at least BUILD_ID_SIZE long
 * @size:     returns actual build id size in case of success
 *
 * Return: 0 on success, -EINVAL otherwise
 */
int build_id_parse(struct vm_area_struct *vma, unsigned char *build_id,
		   __u32 *size)
{
	Elf32_Ehdr *ehdr;
	struct page *page;
	void *page_addr;
	int ret;

	/* only works for page backed storage  */
	if (!vma->vm_file)
		return -EINVAL;

	page = find_get_page(vma->vm_file->f_mapping, 0);
	if (!page)
		return -EFAULT;	/* page not mapped */

	ret = -EINVAL;
	page_addr = kmap_atomic(page);
	ehdr = (Elf32_Ehdr *)page_addr;

	/* compare magic x7f "ELF" */
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	/* only support executable file and shared object file */
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		goto out;

	if (ehdr->e_ident[EI_CLASS] == ELFCLASS32)
		ret = get_build_id_32(page_addr, build_id, size);
	else if (ehdr->e_ident[EI_CLASS] == ELFCLASS64)
		ret = get_build_id_64(page_addr, build_id, size);
out:
	kunmap_atomic(page_addr);
	put_page(page);
	return ret;
}

/**
 * build_id_parse_buf - Get build ID from a buffer
 * @buf:      ELF note section(s) to parse
 * @buf_size: Size of @buf in bytes
 * @build_id: Build ID parsed from @buf, at least BUILD_ID_SIZE_MAX long
 *
 * Return: 0 on success, -EINVAL otherwise
 */
int build_id_parse_buf(const void *buf, unsigned char *build_id, u32 buf_size)
{
	return parse_build_id_buf(build_id, NULL, buf, buf_size);
}

#if IS_ENABLED(CONFIG_STACKTRACE_BUILD_ID) || IS_ENABLED(CONFIG_CRASH_CORE)
unsigned char vmlinux_build_id[BUILD_ID_SIZE_MAX] __ro_after_init;

/**
 * init_vmlinux_build_id - Compute and stash the running kernel's build ID
 */
void __init init_vmlinux_build_id(void)
{
	/* IAMROOT20 20240113
	 * __weak : https://kldp.org/node/40383
	 *	같은 이름의 심볼이 있으면 weak symbol이 strong symbol에게 overriding이 되게 하는 것입니다.
	 *	예를 들어 shared library에 a라는 weak symbol이 있을 때 이를 사용하는 프로그램에서 a라는
	 *	심볼이 있으면 프로그램에서는 shared library가 아닌 자신에 있는 것을 사용하게 됩니다.
	 */
	extern const void __start_notes __weak;
	extern const void __stop_notes __weak;
	unsigned int size = &__stop_notes - &__start_notes;

	build_id_parse_buf(&__start_notes, vmlinux_build_id, size);
}
#endif
