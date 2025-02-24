/*
 * Copyright 2000-2009
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <common.h>
#include <command.h>
#include <version.h>
#include <linux/compiler.h>

//const char __weak version_string[] = U_BOOT_VERSION_STRING;

/**
  4.1.0 New implementation for firmware upate
  4.1.1 Added code to boot into golden image
  4.1.2 KAM-12726 SATA Init failed in uboot
  4.1.3 Reset the bootstate after update_cbr has failed.
  4.1.4 Changed the default FAN speed to 20% 
  4.2.1 Update hwsetting of RTD1295(Monarch) and RTD1296(Pelican), sata driver, spi driver
  4.2.2 KAM200-789/KAM-29619: SATA device initialize failed
**/
const char version_string[] = "4.2.2";
const char version_string_prefix[] = "[WD_UBOOT]4.2.2";

#ifdef CONFIG_CMD_VERSION
int do_version(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	printf("\n%s\n", version_string);
#ifdef CC_VERSION_STRING
	puts(CC_VERSION_STRING "\n");
#endif
#ifdef LD_VERSION_STRING
	puts(LD_VERSION_STRING "\n");
#endif

	return 0;
}

U_BOOT_CMD(
	version,	1,		1,	do_version,
	"print monitor, compiler and linker version",
	""
);
#endif /* CONFIG_CMD_VERSION */

