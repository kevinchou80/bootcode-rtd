/*
 * (C) Copyright 2013 Patrice Bouchand <pbfwdlist_gmail_com>
 * lzma uncompress command in Uboot
 *
 * made from existing cmd_unzip.c file of Uboot
 *
 * (C) Copyright 2000
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <command.h>

#include <lzma/LzmaTools.h>

static int do_lzmadec(cmd_tbl_t *cmdtp, int flag, int argc, char *const argv[])
{
	unsigned long src, dst;
	unsigned long src_len = ~0UL, dst_len = ~0UL;
	char buf[32];
	switch (argc) {
	case 4:
		dst_len = simple_strtoul(argv[3], NULL, 16);
		/* fall through */
	case 3:
		src = simple_strtoul(argv[1], NULL, 16);
		dst = simple_strtoul(argv[2], NULL, 16);
		break;
	default:
		return CMD_RET_USAGE;
	}

	if (lzmaBuffToBuffDecompress((uchar*) dst, &src_len, (uchar*) src, dst_len) != 0)
	{
		printf("[ERR] %s:Decompress using LZMA error!!\n", __FUNCTION__);
		return 1;
	}

	printf("Uncompressed size: %ld = 0x%lX\n", src_len, src_len);
	sprintf(buf, "%lX", src_len);
	setenv("filesize", buf);
	return 0;
}

U_BOOT_CMD(
	lzmadec,    4,    1,    do_lzmadec,
	"lzma uncompress a memory region",
	"srcaddr dstaddr [dstsize]"
);
