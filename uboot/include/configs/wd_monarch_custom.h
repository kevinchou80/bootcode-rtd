 /*
 * Configuration settings for the Realtek 1195 qa board.
 *
 * Won't include this file.
 * Just type "make <board_name>_config" and will be included in source tree.
 */

#ifndef __CONFIG_RTK_RTD1295_QA_SPI_H
#define __CONFIG_RTK_RTD1295_QA_SPI_H

/*
 * Include the common settings of RTD1195 platform.
 */
#include <configs/rtd1295_common.h>
#include <configs/rtd1295_customized_feature.h>


/*
 * The followings were RTD1195 demo board specific configuration settings.
 */

/* Board config name */
#define CONFIG_BOARD_FPGA_RTD1295
#define CONFIG_BOARD_WD_MONARCH

/* Flash type is SPI or NAND or eMMC*/
#define CONFIG_SYS_RTK_SPI_FLASH
//#define CONFIG_SYS_RTK_NAND_FLASH
//#define CONFIG_SYS_RTK_EMMC_FLASH

#ifndef CONFIG_LZMA
	#define CONFIG_LZMA
#endif
#define CONFIG_CMD_LZMADEC

#define HDD0_POWER_GPIO 18
#undef CONFIG_INSTALL_GPIO_NUM
#define CONFIG_INSTALL_IGPIO_NUM 34  // igpio34 is the factory reset button for Monarch
#define SYS_LED_PWM_PORT_NUM 3  // system LED PWM Port Number is PWM3_0 for Monarch

#if defined(CONFIG_SYS_RTK_SPI_FLASH)
	/* Flash writer setting:
	*   The corresponding setting will be located at
	*   uboot/examples/flash_writer_u/$(CONFIG_FLASH_WRITER_SETTING).inc*/	
	#define CONFIG_FLASH_WRITER_SETTING            "1295_force_spi_nS_nE_a01_2ddr3_1GB"
	#define CONFIG_CHIP_ID            			   "rtd1295"
	#define CONFIG_CUSTOMER_ID            		   "demo" 
	#define CONFIG_CHIP_TYPE            		   "0001"

	#define CONFIG_FACTORY_BASE                    0x00010000
	#define CONFIG_FACTORY_SIZE                    0x00010000

	#define CONFIG_DTB_IN_SPI_NOR
	#define CONFIG_DTS_BASE                        0x00000000
	#define CONFIG_DTS_SIZE                        0x00010000
	#define CONFIG_BOOTCODE2_BASE                  0x00080000

	#define CONFIG_FW_TABLE_SIZE                   0x8000

	#define CONFIG_RTKSPI
	#define CONFIG_CMD_RTKSPI



	/* ENV */
	#undef CONFIG_ENV_SIZE
	#define CONFIG_ENV_SIZE (8192)

	#undef CONFIG_ENV_IS_NOWHERE
	#ifdef CONFIG_SYS_FACTORY
		#define CONFIG_ENV_IS_IN_FACTORY
		//#define CONFIG_SYS_FACTORY_READ_ONLY
	#endif
#endif
/* Boot Revision */
#define CONFIG_COMPANY_ID 		"0000"
#define CONFIG_BOARD_ID         "0705"
#define CONFIG_VERSION          "0000"
#define CONFIG_VERSION_VARIABLE
#define CONFIG_CMD_VERSION

/*
 * SDRAM Memory Map
 * Even though we use two CS all the memory
 * is mapped to one contiguous block
 */
#if 1
// undefine existed configs to prevent compile warning
#undef CONFIG_NR_DRAM_BANKS
#undef CONFIG_SYS_SDRAM_BASE
#undef CONFIG_SYS_RAM_DCU1_SIZE


#define ARM_ROMCODE_SIZE		(124*1024)
#define MIPS_RESETROM_SIZE              (0x1000UL)
#define CONFIG_NR_DRAM_BANKS		1
#define CONFIG_SYS_SDRAM_BASE		0
#define CONFIG_SYS_RAM_DCU1_SIZE	 0x40000000	//FIXME

#endif

#define CONFIG_SECOND_BOOTCODE_SUPPORT
#define CONFIG_GOLDENBOOT_SUPPORT
#ifdef CONFIG_GOLDENBOOT_SUPPORT
#define CONFIG_BOOTCODE_2ND_TMP_ADDR		0x01500000
#endif /* CONFIG_GOLDENBOOT_SUPPORT */

#define CONFIG_PRELOAD_BOOT_IMAGES


#undef V_NS16550_CLK
#define	V_NS16550_CLK				27000000 //(for ASIC 27MHz)

/* Bootcode Feature: Rescue linux read from USB */
#define CONFIG_RESCUE_FROM_USB
#ifdef CONFIG_RESCUE_FROM_USB
	#define CONFIG_RESCUE_FROM_USB_VMLINUX      "spi.uImage"
	#define CONFIG_RESCUE_FROM_USB_DTB          "rescue.spi.dtb"
	#define CONFIG_RESCUE_FROM_USB_ROOTFS       "rescue.root.spi.cpio.gz_pad.img"
	#define CONFIG_RESCUE_FROM_USB_AUDIO_CORE   "bluecore.audio"
#endif /* CONFIG_RESCUE_FROM_USB */

#undef CONFIG_CMD_GPT
#undef CONFIG_CMD_RTKGPT
#undef CONFIG_SYS_64BIT_LBA
#undef CONFIG_CMD_RTKMKFAT

						 
/* PWM */
#define CONFIG_RTD129X_PWM
#ifdef CONFIG_RTD129X_PWM
//#define CONFIG_CMD_PWM
//#define PWM_0_PIN_0
//#define PWM_0_PIN_1
//#define PWM_1_PIN_0
//#define PWM_1_PIN_1
//#define PWM_2_PIN_0
//#define PWM_2_PIN_1
#define PWM_3_PIN_0
//#define PWM_3_PIN_1
#endif /* CONFIG_RTD129X_PWM */

#undef CONFIG_SYS_PROMPT
#define CONFIG_SYS_PROMPT        		"monarch> "
#undef CONFIG_BOOTCOMMAND
#define CONFIG_BOOTCOMMAND                   \
	"run syno_bootargs;run rtk_spi_boot;env set bootcmd bootr;bootr"
	
#undef CONFIG_EXTRA_ENV_SETTINGS
#define CONFIG_EXTRA_ENV_SETTINGS                   \
   "bootcode2ndtmp_loadaddr=0x01500000\0"	\
   "bootcode2nd_loadaddr=0x00021000\0"		\
   "kernel_loadaddr=0x03000000\0"                  \
   "fdt_loadaddr=0x01F00000\0"                  \
   "rootfs_loadaddr=0x02200000\0"                   \
   "mtd_part=mtdparts=rtk_nand:\0"                  \
   "audio_loadaddr=0x01b00000\0"                 \
   "rtk_spi_boot=rtkspi read 0x100000 0x0b000000 0x2f0000;lzmadec 0x0b000000 $kernel_loadaddr 0x2f0000;rtkspi read 0xc0000 0x0b000000 0x40000;lzmadec 0x0b000000 $audio_loadaddr 0x40000;rtkspi read 0x000000 $fdt_loadaddr 0x10000;rtkspi read 0x3f0000 $rootfs_loadaddr 0x3ff000\0"                 \
   "syno_bootargs=env set bootargs ip=off console=ttyS0,115200 root=/dev/sda1 rw  syno_hdd_enable=18 syno_usb_vbus_gpio=19@xhci-hcd.2.auto@0 syno_hw_version=DS118 hd_power_on_seq=1 ihd_num=1 netif_num=1 phys_memsize=1024 audio_version=1012363 syno_fw_version=M.408\0"    \
   
#endif /* __CONFIG_RTK_RTD1295_QA_SPI_H */

