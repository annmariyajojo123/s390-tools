/*
 * s390-tools/zipl/include/bootmap.h
 *   Functions to build the bootmap file.
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef BOOTMAP_H
#define BOOTMAP_H

#include "lib/zt_common.h"

#include "disk.h"
#include "job.h"
#include "zipl.h"
#include "stddef.h"

#define BOOTMAP_HEADER_VERSION  1

#define PROGRAM_TABLE_BLOCK_SIZE  512
#define SIGNATURE_MAGIC  "~Module signature appended~\n"
#define	PKCS7_FORMAT 0x01

struct bootmap_header {
	char header_text[48];
	u64 version;
	u64 envblk_offset;
	char reserved[448];
};

/*
 * The file_signature structure and the PKEY_ID definition
 * are based on linux/scripts/sign-file.c
 */
struct file_signature {
	u8 algorithm;
	u8 hash;
	u8 id_type;
	u8 signer_len;
	u8 key_id_len;
	u8 __pad[3];
	u32 sig_len;
	char magic[28];
};

#define PKEY_ID_PKCS7 0x02

int bootmap_header_init(struct misc_fd *mfd);
int bootmap_header_read(struct misc_fd *mfd, struct bootmap_header *bh);
int bootmap_header_write(struct misc_fd *mfd, struct bootmap_header *bh);
void bootmap_store_blockptr(void *buffer, disk_blockptr_t *ptr,
			    struct disk_info *info, int fid);

#endif /* if not BOOTMAP_H */
