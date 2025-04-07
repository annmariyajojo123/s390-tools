/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * ELF core dump input format
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/util_libc.h"
#include "lib/util_log.h"

#include "zgetdump.h"
#include "zg.h"
#include "df_elf.h"
#include "dfi.h"
#include "dfi_mem_chunk.h"
#include "dfi_elf_common.h"

/*
 * Read memory for given memory chunk
 */
static void dfi_elf_mem_chunk_read_fn(struct dfi_mem_chunk *mem_chunk, u64 off,
				      void *buf, u64 cnt)
{
	u64 elf_load_off = *((u64 *) mem_chunk->data);

	zg_seek(g.fh, elf_load_off + off, ZG_CHECK);
	zg_read(g.fh, buf, cnt, ZG_CHECK);
}

/*
 * Ensure that CPU is already defined by prstatus note
 */
static void check_cpu(struct dfi_cpu *cpu, const char *note_str)
{
	if (cpu)
		return;
	ERR_EXIT("Invalid ELF dump (%s before prstatus found)", note_str);
}

/*
 * Read prstatus note and return new DFI CPU
 */
static struct dfi_cpu *nt_prstatus_read(const struct zg_fh *fh, const Elf64_Nhdr *note)
{
	struct dfi_cpu *cpu = dfi_cpu_alloc();
	struct nt_prstatus_64 nt_prstatus;

	if (nt_read(fh, note, &nt_prstatus, sizeof(nt_prstatus)))
		return NULL;

	memcpy(cpu->gprs, &nt_prstatus.gprs, sizeof(cpu->gprs));
	memcpy(cpu->psw, &nt_prstatus.psw, sizeof(cpu->psw));
	memcpy(cpu->acrs, &nt_prstatus.acrs, sizeof(cpu->acrs));

	dfi_cpu_add(cpu);
	return cpu;
}

/*
 * Read fpregset note
 */
static int nt_fpregset_read(const struct zg_fh *fh, struct dfi_cpu *cpu, const Elf64_Nhdr *note)
{
	struct nt_fpregset_64 nt_fpregset;

	check_cpu(cpu, "FPREGSET");
	if (nt_read(fh, note, &nt_fpregset, sizeof(nt_fpregset)))
		return -EINVAL;

	memcpy(&cpu->fpc, &nt_fpregset.fpc, sizeof(cpu->fpc));
	memcpy(cpu->fprs, &nt_fpregset.fprs, sizeof(cpu->fprs));
	return 0;
}

/*
 * Read s390 timer note
 */
static int nt_s390_timer_read(const struct zg_fh *fh, struct dfi_cpu *cpu, const Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_TIMER");
	return nt_read(fh, note, &cpu->timer, sizeof(cpu->timer));
}

/*
 * Read s390 todcmp note
 */
static int nt_s390_todcmp_read(const struct zg_fh *fh, struct dfi_cpu *cpu, const Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_TODCMP");
	return nt_read(fh, note, &cpu->todcmp, sizeof(cpu->todcmp));
}

/*
 * Read s390 todpreg note
 */
static int nt_s390_todpreg_read(const struct zg_fh *fh, struct dfi_cpu *cpu, const Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_TODPREG");
	return nt_read(fh, note, &cpu->todpreg, sizeof(cpu->todpreg));
}

/*
 * Read s390 ctrs note
 */
static int nt_s390_ctrs_read(const struct zg_fh *fh, struct dfi_cpu *cpu, const Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_CTRS");
	return nt_read(fh, note, &cpu->ctrs, sizeof(cpu->ctrs));
}

/*
 * Read s390 prefix note
 */
static int nt_s390_prefix_read(const struct zg_fh *fh, struct dfi_cpu *cpu, const Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_PREFIX");
	return nt_read(fh, note, &cpu->prefix, sizeof(cpu->prefix));
}

/*
 * Read s390 vxrs_low note
 */
static int nt_s390_vxrs_low_read(const struct zg_fh *fh, struct dfi_cpu *cpu,
				 const Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_VXRS_LOW");
	return nt_read(fh, note, &cpu->vxrs_low, sizeof(cpu->vxrs_low));
}

/*
 * Read s390 vxrs_high note
 */
static int nt_s390_vxrs_high_read(const struct zg_fh *fh, struct dfi_cpu *cpu,
				  const Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_VXRS_HIGH");
	return nt_read(fh, note, &cpu->vxrs_high, sizeof(cpu->vxrs_high));
}

/*
 * Read s390 gs_cb note
 */
static int nt_s390_gs_cb_read(const struct zg_fh *fh, struct dfi_cpu *cpu, const Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_GSCB");
	return nt_read(fh, note, &cpu->gscb, sizeof(cpu->gscb));
}

/*
 * Add all notes for notes phdr
 */
static int pt_notes_add(const Elf64_Phdr *phdr)
{
	struct dfi_cpu *cpu_current = NULL;
	const struct zg_fh *fh = g.fh;
	int rc;

	zg_seek(fh, phdr->p_offset, ZG_CHECK);
	while (zg_tell(fh, ZG_CHECK) - phdr->p_offset < phdr->p_filesz) {
		Elf64_Nhdr note;

		rc = zg_read(fh, &note, sizeof(note), ZG_CHECK_ERR);
		if (rc != sizeof(note))
			return -EINVAL;
		util_log_print(UTIL_LOG_DEBUG, "DFI ELF n_type 0x%x\n",
			       note.n_type);
		switch (note.n_type) {
		case NT_PRSTATUS:
			cpu_current = nt_prstatus_read(fh, &note);
			if (!cpu_current)
				return -EINVAL;
			break;
		case NT_FPREGSET:
			if (nt_fpregset_read(fh, cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_TIMER:
			if (nt_s390_timer_read(fh, cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_TODCMP:
			if (nt_s390_todcmp_read(fh, cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_TODPREG:
			if (nt_s390_todpreg_read(fh, cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_CTRS:
			if (nt_s390_ctrs_read(fh, cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_PREFIX:
			if (nt_s390_prefix_read(fh, cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_VXRS_LOW:
			if (nt_s390_vxrs_low_read(fh, cpu_current, &note))
				return -EINVAL;
			dfi_cpu_content_fac_add(DFI_CPU_CONTENT_FAC_VX);
			break;
		case NT_S390_VXRS_HIGH:
			if (nt_s390_vxrs_high_read(fh, cpu_current, &note))
				return -EINVAL;
			dfi_cpu_content_fac_add(DFI_CPU_CONTENT_FAC_VX);
			break;
		case NT_S390_GS_CB:
			if (nt_s390_gs_cb_read(fh, cpu_current, &note))
				return -EINVAL;
			dfi_cpu_content_fac_add(DFI_CPU_CONTENT_FAC_GS);
			break;
		default:
			nt_skip(fh, &note);
			break;
		}
	}
	return 0;
}

/*
 * Initialize ELF input dump format
 */
static int dfi_elf_init(void)
{
	unsigned int phnum, i;
	Elf64_Phdr *phdrs;
	Elf64_Ehdr *ehdr;
	int rc = -ENODEV;

	util_log_print(UTIL_LOG_DEBUG, "DFI ELF initialization\n");

	ehdr = read_elf_hdr(g.fh);
	if (!ehdr)
		return -ENODEV;

	if (ehdr_check_s390x(ehdr) < 0)
		goto free_ehdr;

	df_elf_ensure_s390x();
	dfi_cpu_info_init(DFI_CPU_CONTENT_ALL);

	phdrs = read_elf_phdrs(g.fh, ehdr, &phnum);
	util_log_print(UTIL_LOG_DEBUG, "DFI ELF e_phnum %u\n", phnum);
	for (i = 0; i < phnum; i++) {
		const Elf64_Phdr *phdr = &phdrs[i];

		util_log_print(UTIL_LOG_DEBUG, "DFI ELF p_type[%d] 0x%lx\n", i, phdr->p_type);
		switch (phdr->p_type) {
		case PT_LOAD: {
			u64 *off_ptr = zg_alloc(sizeof(*off_ptr));
			*off_ptr = phdr->p_offset;

			if (pt_load_add(g.fh, phdr, (void **)&off_ptr, dfi_elf_mem_chunk_read_fn,
					free) < 0) {
				free(off_ptr);
				rc = -EINVAL;
				goto free_phdrs;
			}
		} break;
		case PT_NOTE:
			if (pt_notes_add(phdr)) {
				rc = -EINVAL;
				goto free_phdrs;
			}
			break;
		default:
			break;
		}
	}

	dfi_attr_version_set(ehdr->e_ident[EI_VERSION]);
	rc = 0;

free_phdrs:
	free(phdrs);
free_ehdr:
	free(ehdr);
	return rc;
}

/*
 * ELF DFI operations
 */
struct dfi dfi_elf = {
	.name		= "elf",
	.init		= dfi_elf_init,
	.feat_bits	= DFI_FEAT_COPY | DFI_FEAT_SEEK,
};
