/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Single-volume SCSI dump tool
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdint.h>
#include <linux/fs.h>

#include "lib/zt_common.h"
#include "lib/util_part.h"
#include "boot/boot_defs.h"

#include "zgetdump.h"
#include "zg.h"
#include "dt.h"

/*
 * File local static data
 */
static struct {
	struct scsi_dump_sb	sb;
	int			blk_size;
} l;

/*
 * Check the zIPL magic number
 */
static int check_zipl_magic(void *buf)
{
	if (memcmp(buf, ZIPL_MAGIC, ZIPL_MAGIC_SIZE))
		return -1;
	return 0;
}

/*
 * Final step looks into program to find dump flag
 */
static int check_dump_program(struct linear_blockptr *blockptr)
{
	uint64_t off = blockptr->blockno * l.blk_size;
	struct component_header header;

	zg_seek(g.fh, off, ZG_CHECK_ERR);
	zg_read(g.fh, &header, sizeof(header), ZG_CHECK_ERR);
	if (check_zipl_magic(&header.magic))
		return -1;
	return (header.type == COMPONENT_HEADER_DUMP) ? 0 : -1;
}

/*
 * Parse program table, see zipl docu to understand table structures
 */
static int check_program_table(uint64_t blockno)
{
	struct linear_blockptr entries[l.blk_size / sizeof(struct linear_blockptr)];
	unsigned int i;

	/* Entry 0, holds the magic, entry 1 the default */
	zg_seek(g.fh, blockno * l.blk_size, ZG_CHECK);
	zg_read(g.fh, &entries, l.blk_size, ZG_CHECK);
	if (check_zipl_magic(&entries[0]))
		return -1;
	for (i = 1; i < l.blk_size / sizeof(struct linear_blockptr); i++) {
		if (entries[i].blockno == 0)
			break;
		if (check_dump_program(&entries[i]) == 0)
			return 0;
	}
	return -1;
}

/*
 * Check magic number and checksum of superblock at given offset
 */
static int check_sb(void)
{
	char buf[l.sb.csum_size];

	if (l.sb.magic != SCSI_DUMP_SB_MAGIC)
		return -1;
	/*
	 * Verify checksum
	 */
	zg_seek(g.fh, l.sb.part_start + l.sb.csum_offset, ZG_CHECK);
	zg_read(g.fh, &buf, sizeof(buf), ZG_CHECK);
	if (zg_csum_partial(&buf, l.sb.csum_size, SCSI_DUMP_SB_SEED) != l.sb.csum)
		return -1;
	return 0;
}

/*
 * Check the SCSI dump boot info
 */
static int check_boot_info(struct boot_info *info)
{
	if (memcmp(&info->magic, BOOT_INFO_MAGIC, sizeof(info->magic)))
		return -1;
	if (info->dev_type != BOOT_INFO_DEV_TYPE_SCSI)
		return -1;
	if (info->bp_type != BOOT_INFO_BP_TYPE_DUMP)
		return -1;
	zg_seek(g.fh, info->bp.dump.param.scsi.block, ZG_CHECK);
	zg_read(g.fh, &l.sb, sizeof(l.sb), ZG_CHECK);
	return check_sb();
}

/*
 * Detect if the bootmap contains ZFCPDUMP.
 * Walks through bootmap structs to find the dump flag
 */
static int dt_scsi_init(void)
{
	struct scsi_mbr mbr;

	zg_read(g.fh, &mbr, sizeof(mbr), ZG_CHECK);
	if (zg_ioctl(g.fh, BLKSSZGET, &l.blk_size, "BLKSSZGET", ZG_CHECK_NONE))
		return -1;
	if (check_zipl_magic(mbr.magic))
		return -1;
	if (check_program_table(mbr.program_table_pointer.blockno))
		return -1;
	if (check_boot_info(&mbr.boot_info))
		return -1;
	dt_version_set(l.sb.version);
	return 0;
}

/*
 * Print partition information for dump device
 */
static void dt_scsi_info(void)
{
	int part_num, part_ext;
	size_t start, cnt;

	start = l.sb.part_start / l.blk_size;
	cnt = l.sb.part_size / l.blk_size;
	part_num = util_part_search_fh(g.fh->fh, start, cnt, l.blk_size,
				       &part_ext);

	STDERR("Partition info:\n");
	if (part_num > 0)
		STDERR("  Partition number..: %d\n", part_num);
	else
		STDERR("  Partition number..: unknown\n");
	STDERR("  Maximum dump size.: %llu MB\n",
	       (unsigned long long) TO_MIB(l.sb.dump_size));
}

/*
 * Single-volume SCSI DT operations
 */
struct dt dt_scsi = {
	.desc	= "Single-volume SCSI dump tool",
	.init	= dt_scsi_init,
	.info	= dt_scsi_info,
};
