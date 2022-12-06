/*
 * (C) Copyright 2000-2003
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

/*
 * Misc boot support
 */
#include <common.h>
#include <command.h>
#include <net.h>
#include <asm/arch/rbus/crt_reg.h>
#include <asm/arch/system.h>
#include <asm/arch/fw_info.h>
#include <asm/arch/panelConfigParameter.h>
#include <asm/arch/extern_param.h>
#include <asm/arch/fw_info.h>
#include <asm/arch/flash_writer_u/mcp.h>
#include <watchdog.h>
#include <nand.h>
#include <asm/arch/rbus/nand_reg.h>
#include <asm/arch/rtk_ipc_shm.h>
#include <asm/sizes.h>
#include <rtkspi.h>
 
#ifdef CONFIG_LZMA
#include <lzma/LzmaTypes.h>
#include <lzma/LzmaDec.h>
#include <lzma/LzmaTools.h>
#endif /* CONFIG_LZMA */
#include "linux/lzo.h"



DECLARE_GLOBAL_DATA_PTR;

typedef enum{
	BOOT_FROM_USB_DISABLE,
	BOOT_FROM_USB_UNCOMPRESSED,
	BOOT_FROM_USB_COMPRESSED
}BOOT_FROM_USB_T;

typedef enum{
	BOOT_FROM_FLASH_NORMAL_MODE,
	BOOT_FROM_FLASH_MANUAL_MODE
}BOOT_FROM_FLASH_T;



#if defined(CONFIG_RTD1195) || defined(CONFIG_RTD1295)

//[fw] share memory.
extern struct RTK119X_ipc_shm ipc_shm;

//[fw] image display.
uchar boot_logo_enable=0;
uint custom_logo_src_width=0;
uint custom_logo_src_height=0;
uint custom_logo_dst_width=0;
uint custom_logo_dst_height=0;
uchar sys_logo_is_HDMI = 0;
//uchar sys_logo_enabled = 0;

uint eMMC_bootcode_area_size = 0x220000;		// eMMC bootcode area size
uint eMMC_fw_desc_table_start = 0;				// start address of valid fw desc table in emmc
uint nand_fw_desc_table_start = 0;				// start address of valid fw desc table in nand
uint sata_fw_desc_table_start = 34;				// start address of valid fw desc table in sata

BOOT_FROM_FLASH_T boot_from_flash = BOOT_FROM_FLASH_NORMAL_MODE;
BOOT_FROM_USB_T boot_from_usb = BOOT_FROM_USB_DISABLE;
extern BOOT_MODE boot_mode;

#ifdef CONFIG_TEE
uint tee_enable=0;
#endif
#ifdef NAS_ENABLE
uint nas_rescue=0;
uint initrd_size=0;
#endif

#endif // defined(CONFIG_RTD1195) || defined(CONFIG_RTD1295)

#ifdef CONFIG_CMD_GO

#ifdef CONFIG_UBOOT_DEFAULT
#if defined(CONFIG_RTD1195) || defined(CONFIG_RTD1295)

extern void delete_env(void);
extern void enable_clock(uint reg_reset, uint mask_reset, uint reg_clock, uint mask_clock);
extern int rtk_plat_boot_go(bootm_headers_t *images);

extern unsigned int mcp_dscpt_addr;
extern const unsigned int Kh_key_default[4];

int rtk_plat_prepare_fw_image_from_NAND(void);
int rtk_plat_prepare_fw_image_from_eMMC(void);
int rtk_plat_prepare_fw_image_from_SATA(void);
char *rtk_plat_prepare_fw_image_from_USB(int fw_type);
int rtk_plat_do_boot_linux(void);
int rtk_plat_boot_handler(void);
static int rtk_call_bootm(void);
int decrypt_image(char *src, char *dst, uint length, uint *key);
int rtk_get_secure_boot_type(void);
void rtk_hexdump( const char * str, unsigned char * pcBuf, unsigned int length );
void GetKeyFromSRAM(unsigned int sram_addr, unsigned char* key, unsigned int length);

static void reset_shared_memory(void);


static unsigned long do_go_kernel_image(void)
{
    int ret = RTK_PLAT_ERR_OK;

#ifdef CONFIG_SYS_RTK_NAND_FLASH
	ret = rtk_plat_prepare_fw_image_from_NAND();	
#elif defined(CONFIG_SYS_RTK_EMMC_FLASH)
	ret = rtk_plat_prepare_fw_image_from_eMMC();
#elif defined(CONFIG_SYS_RTK_SATA_STORAGE)
	ret = rtk_plat_prepare_fw_image_from_SATA();
#endif
	if (ret!= RTK_PLAT_ERR_OK)
		return ret;

	return rtk_plat_do_boot_linux();
}

static unsigned long do_go_audio_fw(void)
{
	int magic = SWAPEND32(0x16803001);
	int offset = SWAPEND32(MIPS_SHARED_MEMORY_ENTRY_ADDR);
	
	printf("Start Audio Firmware ...\n");

	reset_shared_memory();

	ipc_shm.audio_fw_entry_pt = SWAPEND32(MIPS_AUDIO_FW_ENTRY_ADDR | MIPS_KSEG0BASE);
			
	memcpy((unsigned char *)(MIPS_SHARED_MEMORY_ENTRY_ADDR+0xC4), &ipc_shm, sizeof(ipc_shm));
	memcpy((unsigned char *)(MIPS_SHARED_MEMORY_ENTRY_ADDR), &magic, sizeof(magic));
	memcpy((unsigned char *)(MIPS_SHARED_MEMORY_ENTRY_ADDR +4), &offset, sizeof(offset));
				
	flush_dcache_all();

	/* Enable ACPU */
	rtd_setbits(CLOCK_ENABLE2_reg,_BIT4);

	return 0;
	
}

static unsigned long do_go_all_fw(void)
{
	
	int ret = RTK_PLAT_ERR_OK;

	if (run_command("go a", 0) != 0) {
		printf("go a failed!\n");
		return RTK_PLAT_ERR_BOOT;
	}
	
	if (run_command("go k", 0) != 0) {
		printf("go k failed!\n");
		return RTK_PLAT_ERR_BOOT;
	}

	return ret;
}
#endif 

#ifdef CONFIG_RESCUE_FROM_USB
int rtk_decrypt_rescue_from_usb(char* filename, unsigned int target)
{
	char tmpbuf[128];
	unsigned char ks[16],kh[16],kimg[16];
    unsigned char aes_key[16],rsa_key[256];
    unsigned int real_body_size = 0;
#ifdef CONFIG_CMD_KEY_BURNING
	unsigned int * Kh_key_ptr = NULL; 
#else
	unsigned int * Kh_key_ptr = Kh_key_default; 
#endif
	unsigned int img_truncated_size = RSA_SIGNATURE_LENGTH*2+NP_INV32_LENGTH; // install_a will append 256-byte signature data to it
	int ret;
	unsigned int image_size=0;
	
	extern unsigned int mcp_dscpt_addr;
	mcp_dscpt_addr = 0;
	
	
	sprintf(tmpbuf, "fatload usb 0:1 %x %s",ENCRYPTED_FW_ADDR,filename);	
	if (run_command(tmpbuf, 0) != 0) {
			return RTK_PLAT_ERR_READ_FW_IMG;
	}
			
	image_size = getenv_ulong("filesize", 16, 0);
	
	memset(ks,0x00,16);
	memset(kh,0x00,16);
	memset(kimg,0x00,16);

    memset(aes_key,0x00,16);
	memset(rsa_key,0x00,256);

    GetKeyFromSRAM(KH_P_SRAM_ADDR, aes_key, AES_KEY_SIZE);
    GetKeyFromSRAM(RSA_KEY_FW_SRAM_ADDR, rsa_key, RSA_KEY_SIZE);
    flush_cache((unsigned int) aes_key, AES_KEY_SIZE);
    flush_cache((unsigned int) rsa_key, RSA_KEY_SIZE);

#ifdef CONFIG_CMD_KEY_BURNING
	OTP_Get_Byte(OTP_K_S, ks, 16);
	OTP_Get_Byte(OTP_K_H, kh, 16);
	sync();
	flush_cache((unsigned int) ks, 16);
	flush_cache((unsigned int) kh, 16);
#endif
	AES_ECB_encrypt(ks, 16, kimg, kh);
	flush_cache((unsigned int) kimg, 16);
	sync();
	
	//Kh_key_ptr = kimg;    
	//Kh_key_ptr[0] = swap_endian(Kh_key_ptr[0]);
	//Kh_key_ptr[1] = swap_endian(Kh_key_ptr[1]);
	//Kh_key_ptr[2] = swap_endian(Kh_key_ptr[2]);
	//Kh_key_ptr[3] = swap_endian(Kh_key_ptr[3]);
    Kh_key_ptr = aes_key; 
	flush_cache((unsigned int) aes_key, 16);
								
    // decrypt image
	printf("to decrypt...\n");						
	flush_cache((unsigned int) ENCRYPTED_FW_ADDR, image_size);
	if (decrypt_image((char *)ENCRYPTED_FW_ADDR,
		(char *)target,
		image_size - img_truncated_size,
		Kh_key_ptr))
	{
		printf("decrypt image:%s error!\n", filename);
		return RTK_PLAT_ERR_READ_FW_IMG;
	}
	
	sync();
	memset(ks,0x00,16);
	memset(kh,0x00,16);
	memset(kimg,0x00,16);
		
    copy_memory(target + image_size - img_truncated_size, ENCRYPTED_FW_ADDR + image_size - img_truncated_size, img_truncated_size);
	flush_cache((unsigned int) target, image_size);
	real_body_size = (UINT32)(REG32(target + (image_size - img_truncated_size) - 4));
    real_body_size = swap_endian(real_body_size);
	real_body_size /= 8;
    
	ret = Verify_SHA256_hash( (unsigned char *)target,
							real_body_size,
							(unsigned char *)(target + image_size - img_truncated_size),
							1, rsa_key);						  
	if( ret < 0 ) {
		printf("[ERR] %s: verify hash fail(%d)\n", __FUNCTION__, ret );
		return RTK_PLAT_ERR_READ_FW_IMG;
	}
	
	return RTK_PLAT_ERR_OK;
}


int boot_rescue_from_usb(void)
{
	char tmpbuf[128];
	int ret = RTK_PLAT_ERR_OK;
	char *filename;
	unsigned int secure_mode=0;
	
	printf("==== %s =====\n", __func__);

	secure_mode = rtk_get_secure_boot_type();

	run_command("usb start", 0);	/* "usb start" always return 0 */
	if (run_command("usb dev", 0) != 0) {
		printf("No USB device found!\n");
		return RTK_PLAT_ERR_READ_RESCUE_IMG;
	}

    filename = "dvrboot.exe.bin";
	sprintf(tmpbuf, "fatload usb 0:1 0x1500000 %s", filename);
	if (run_command(tmpbuf, 0) == 0){
		#if defined(CONFIG_BOARD_WD_MONARCH) || defined(CONFIG_BOARD_WD_PELICAN)
        pwm_set_freq(SYS_LED_PWM_PORT_NUM, 20);  // set the frequency to 1 HZ
        pwm_set_duty_rate(SYS_LED_PWM_PORT_NUM, 50);
        pwm_enable(SYS_LED_PWM_PORT_NUM, 1);
		#endif
		printf("Loading \"%s\" to 0x1500000 is OK.\n\n", filename);
        run_command_list("go 0x1500000", -1, 0);
	}else{
		printf("Loading \"%s\" from USB failed. Continue installing OS images\n", filename);
	}

    
	/* DTB */	
	if ((filename = getenv("rescue_dtb")) == NULL) {
		filename =(char*) CONFIG_RESCUE_FROM_USB_DTB;
	}	
	sprintf(tmpbuf, "fatload usb 0:1 %s %s", getenv("fdt_loadaddr"), filename);
	if (run_command(tmpbuf, 0) != 0) {
		goto loading_failed;
	}

	printf("Loading \"%s\" to %s is OK.\n\n", filename, getenv("fdt_loadaddr"));

	/* Linux kernel */
	if ((filename = getenv("rescue_vmlinux")) == NULL) {
		filename =(char*) CONFIG_RESCUE_FROM_USB_VMLINUX;
	}
	if(secure_mode == RTK_SECURE_BOOT)
	{	
		if (rtk_decrypt_rescue_from_usb(filename,getenv_ulong("kernel_loadaddr", 16, 0)))
		goto loading_failed;	
	}	
	else
	{	
		sprintf(tmpbuf, "fatload usb 0:1 %s %s", getenv("kernel_loadaddr"), filename);
		if (run_command(tmpbuf, 0) != 0) {
			goto loading_failed;
		}
	}

	printf("Loading \"%s\" to %s is OK.\n\n", filename, getenv("kernel_loadaddr"));

	/* rootfs */
	if ((filename = getenv("rescue_rootfs")) == NULL) {
		filename =(char*) CONFIG_RESCUE_FROM_USB_ROOTFS;
	}
	if(secure_mode == RTK_SECURE_BOOT)
	{	
		if (rtk_decrypt_rescue_from_usb(filename, getenv_ulong("rootfs_loadaddr", 16, 0)))
		goto loading_failed;	
	}	
	else
	{
		sprintf(tmpbuf, "fatload usb 0:1 %s %s", getenv("rootfs_loadaddr"), filename);
		if (run_command(tmpbuf, 0) != 0) {
			goto loading_failed;
		}
	}

	printf("Loading \"%s\" to %s is OK.\n\n", filename, getenv("rootfs_loadaddr"));


	/* audio firmware */
	if ((filename = getenv("rescue_audio")) == NULL) {
		filename =(char*) CONFIG_RESCUE_FROM_USB_AUDIO_CORE;
	}
	if(secure_mode == RTK_SECURE_BOOT)
	{	
		if (!rtk_decrypt_rescue_from_usb(filename, MIPS_AUDIO_FW_ENTRY_ADDR))
		{
			printf("Loading \"%s\" to 0x%08x is OK.\n", filename, MIPS_AUDIO_FW_ENTRY_ADDR);
			run_command("go a", 0);
		}
		else
			printf("Loading \"%s\" from USB failed.\n", filename);
			/* Go on without Audio firmware. */	
	}	
	else
	{	
		sprintf(tmpbuf, "fatload usb 0:1 0x%08x %s", MIPS_AUDIO_FW_ENTRY_ADDR, filename);
		if (run_command(tmpbuf, 0) == 0) {
			printf("Loading \"%s\" to 0x%08x is OK.\n", filename, MIPS_AUDIO_FW_ENTRY_ADDR);
			run_command("go a", 0);
		}
		else {
			printf("Loading \"%s\" from USB failed.\n", filename);
			/* Go on without Audio firmware. */
		}
    }
	boot_mode = BOOT_RESCUE_MODE;

	/* Clear the HYP ADDR since we don't want rescue jump to HYP mode */
	if (getenv("hyp_loadaddr"))
		setenv("hyp_loadaddr", "");

	ret = rtk_call_bootm();
	/* Should not reach here */

	return ret;

loading_failed:
	printf("Loading \"%s\" from USB failed.\n", filename);
	return RTK_PLAT_ERR_READ_RESCUE_IMG;	
}
#endif	 /* CONFIG_RESCUE_FROM_USB */
#endif

/* Allow ports to override the default behavior */
__attribute__((weak))
unsigned long do_go_exec (ulong (*entry)(int, char * const []), int argc, char * const argv[])
{
	return entry (argc, argv);
}


int reflash_bootloader(int argc, char * const argv[])
{
	char tmpbuf[128];
	int ret = RTK_PLAT_ERR_OK;
	char *filename;
	unsigned int secure_mode = 0;
	ulong	addr;

	printf("==== %s =====\n", __func__);

	secure_mode = rtk_get_secure_boot_type();

	run_command("usb start", 0);	/* "usb start" always return 0 */
	if (run_command("usb dev", 0) != 0) {
		printf("No USB device found!\n");
		return RTK_PLAT_ERR_READ_RESCUE_IMG;
	}

	/* load uboot.bin */
	filename = "dvrboot.exe.bin";
	sprintf(tmpbuf, "fatload usb 0:1 %s %s", "0x01500000", filename);
	if (run_command(tmpbuf, 0) != 0) {
		goto loading_failed;
	}

	addr = simple_strtoul("0x1500000", NULL, 16);
	do_go_exec((void *)addr, argc -1 , argv + 1 );


	return ret;

loading_failed:
	printf("Loading \"%s\" from USB failed.\n", filename);
	return RTK_PLAT_ERR_READ_RESCUE_IMG;
}



int do_go (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	ulong	addr, rc;
	int     rcode = 0;
	int     do_cleanup = 0;

	if (argc < 2)
		return CMD_RET_USAGE;

#ifdef CONFIG_UBOOT_DEFAULT
#if defined(CONFIG_RTD299X) || defined(CONFIG_RTD1195) || defined(CONFIG_RTD1295)
	if (argv[1][0] == 'a')
	{
		if (argv[1][1] == '\0')	// audio fw
		{
			return do_go_audio_fw();
		}
		else if (argv[1][1] == 'l' && argv[1][2] == 'l')	// all fw
		{
			return do_go_all_fw();
		}
		else
		{
			printf("Unknown command '%s'\n", argv[1]);
			return CMD_RET_USAGE;
		}
	}
	else if (argv[1][0] == 'i')
	{
		if( strncmp( argv[1], "info", 4 ) == 0 ) {
			printf("## boot_mode is %d\n", boot_mode);
			printf("## boot_flash_type is %d\n", boot_flash_type);
			printf("## fw_desc_table_v1 struct size    = 0x%08x\n", sizeof(fw_desc_table_v1_t));
			printf("## part_entry struct size          = 0x%08x\n", sizeof(part_desc_entry_v1_t));
			printf("## fw_entry struct size            = 0x%08x\n", sizeof(fw_desc_entry_v1_t));
			return 0;
		}
	}
	else if (argv[1][0] == 'k')
	{
		if (argv[1][1] == '\0')	// getkernel image from ddr;
		{
			return rtk_plat_do_boot_linux();
		}
		else if (argv[1][1] == 'f')	// get kernel image from flash;
		{
			boot_mode = BOOT_KERNEL_ONLY_MODE;
			return do_go_kernel_image();
		}
		else
		{
			printf("Unknown command '%s'\n", argv[1]);
			return CMD_RET_USAGE;
		}

	}
	else if (argv[1][0] == 'r')
	{
		if (argv[1][1] == '\0') // rescue from flash
		{			
			boot_mode = BOOT_RESCUE_MODE;
			return rtk_plat_boot_handler();			
		}
		else if (argv[1][1] == 'a') // rescue for android
		{
			boot_mode = BOOT_ANDROID_MODE;
			return rtk_plat_boot_handler();					
		}
		else if (argv[1][1] == 'b')
		{
			return reflash_bootloader(argc, argv);
		}
#ifdef CONFIG_RESCUE_FROM_USB
		else if (argv[1][1] == 'u') // rescue from usb
		{
			return boot_rescue_from_usb();
		}
#endif
		else
		{
			return 0;
		}
	}
#endif
#endif

	addr = simple_strtoul(argv[1], NULL, 16);

#ifdef CONFIG_CLEAR_ENV_AFTER_UPDATE_BOOTCODE
	if (addr == DVRBOOT_EXE_BIN_ENTRY_ADDR)
	{
		printf ("Clear env when updating bootcode ...\n");
		delete_env();
	}
#endif

	printf ("Starting application at 0x%08lX ...\n", addr);

	if( strncmp( argv[2], "nocache", 7 ) == 0 ) {
		do_cleanup = 1;
		printf ("Run application w/o any cache\n");
		cleanup_before_dvrbootexe();
	}

	/*
	 * pass address parameter as argv[0] (aka command name),
	 * and all remaining args
	 */
	rc = do_go_exec ((void *)addr, argc - 1 - do_cleanup, argv + 1 + do_cleanup);
	if (rc != 0) rcode = 1;

	printf ("Application terminated, rc = 0x%lX\n", rc);
	return rcode;
}

int do_goru (cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	//boot_mode = BOOT_CONSOLE_MODE;
	WATCHDOG_DISABLE();
	setenv("bootcmd", "bootr");
	return boot_rescue_from_usb();
}

/* -------------------------------------------------------------------- */

U_BOOT_CMD(
	go, CONFIG_SYS_MAXARGS, 1,	do_go,
	"start application at address 'addr' or start running fw",
	"[addr/a/v/v1/v2/k] [arg ...]\n"
	"\taddr   - start application at address 'addr'\n"
	"\ta      - start audio firmware\n"
	"\tk      - start kernel\n"
	"\tr      - start rescue linux\n"
#ifdef CONFIG_RESCUE_FROM_USB
	"\tru     - start rescue linux from usb\n"
#endif
	"\tall    - start all firmware\n"
	"\tinfo   - show curren mode info\n"
	"\t[arg]  - passing 'arg' as arguments\n"
);

/* -------------------------------------------------------------------- */

U_BOOT_CMD(
	goru, CONFIG_SYS_MAXARGS, 1,	do_goru,
	"start rescue linux from usb",
	""
);

#endif

#ifdef CONFIG_UBOOT_DEFAULT
U_BOOT_CMD(
	reset, 1, 0,	do_reset,
	"Perform RESET of the CPU",
	""
);

uint get_checksum(uchar *p, uint len) {
	uint checksum = 0;
	uint i;

	for(i = 0; i < len; i++) {
		checksum += *(p+i);

		if (i % 0x200000 == 0)
		{
			EXECUTE_CUSTOMIZE_FUNC(0); // insert execute customer callback at here
		}
	}
	return checksum;
}


uint get_mem_layout_when_read_image(MEM_LAYOUT_WHEN_READ_IMAGE_T *mem_layout)
{
	if (mem_layout->image_target_addr == 0)
	{
		printf("[ERROR] mem_layout->image_target_addr = 0x%08x\n", mem_layout->image_target_addr);

		return 1;
	}

	if (mem_layout->bIsEncrypted)
	{
#ifdef CONFIG_SYS_RTK_NAND_FLASH
		mem_layout->flash_to_ram_addr = mem_layout->image_target_addr;
#else		
		mem_layout->flash_to_ram_addr = mem_layout->encrpyted_addr = ENCRYPTED_FW_ADDR;
#endif
		if (mem_layout->bIsCompressed)
		{
			mem_layout->decrypted_addr = mem_layout->compressed_addr = COMPRESSED_FW_IMAGE_ADDR;
			mem_layout->decompressed_addr = mem_layout->image_target_addr;
		}
		else
		{
			mem_layout->decrypted_addr = mem_layout->image_target_addr;
		}
	}
	else
	{
		if (mem_layout->bIsCompressed)
		{
			mem_layout->flash_to_ram_addr = mem_layout->compressed_addr = COMPRESSED_FW_IMAGE_ADDR;
			mem_layout->decompressed_addr = mem_layout->image_target_addr;
		}
		else
		{
			mem_layout->flash_to_ram_addr = mem_layout->image_target_addr;
		}
	}

	return 0;
}

int decrypt_image(char *src, char *dst, uint length, uint *key)
{
	int i;
	uint sblock_len;
	uchar *sblock_dst, *sblock_src;

	printf("decrypt from 0x%08x to 0x%08x, len:0x%08x\n", (uint)src, (uint)dst, length);

    if (length & 0xf) {
        printf("%s %d, fail\n", __FUNCTION__, __LINE__);
        return -1;
    }

    if (AES_ECB_decrypt((uchar *)src, length, (uchar *)dst, key)) {
		printf("%s %d, fail\n", __FUNCTION__, __LINE__);
		return -1;
	}

	return 0;
}

//#define DUBUG_FW_DESC_TABLE
#ifdef DUBUG_FW_DESC_TABLE
void dump_fw_desc_table_v1(fw_desc_table_v1_t *fw_desc_table_v1)
{
	if (fw_desc_table_v1 != NULL) {
		printf("## Fw Desc Table ##############################\n");
		printf("## fw_desc_table_v1                = 0x%08x\n", fw_desc_table_v1);
		printf("## fw_desc_table_v1 struct size    = 0x%08x\n", sizeof(fw_desc_table_v1_t));
		printf("## fw_desc_table_v1->signature     = %s\n", fw_desc_table_v1->signature);
		printf("## fw_desc_table_v1->checksum      = 0x%08x\n", fw_desc_table_v1->checksum);
		printf("## fw_desc_table_v1->version       = 0x%08x\n", fw_desc_table_v1->version);
		printf("## fw_desc_table_v1->paddings      = 0x%08x\n", fw_desc_table_v1->paddings);
		printf("## fw_desc_table_v1->part_list_len = 0x%08x\n", fw_desc_table_v1->part_list_len);
		printf("## fw_desc_table_v1->fw_list_len   = 0x%08x\n", fw_desc_table_v1->fw_list_len);
		printf("###############################################\n\n");
	}
	else {
		printf("[ERR] %s:%d fw_desc_table_v1 is NULL.\n", __FUNCTION__, __LINE__);
	}
}

void dump_part_desc_entry_v1(part_desc_entry_v1_t *part_entry)
{
	if (part_entry != NULL) {
		printf("## Part Desc Entry ############################\n");
		printf("## part_entry                      = 0x%08x\n", part_entry);
		printf("## part_entry struct size          = 0x%08x\n", sizeof(part_desc_entry_v1_t));
		printf("## part_entry->type                = 0x%08x\n", part_entry->type);
		printf("## part_entry->ro                  = 0x%08x\n", part_entry->ro);
		printf("## part_entry->length              = ");
		printn(part_entry->length,16);
		printf("\n");
		printf("## part_entry->fw_count            = 0x%08x\n", part_entry->fw_count);
		printf("## part_entry->fw_type             = 0x%08x\n", part_entry->fw_type);
		printf("###############################################\n\n");
	}
	else {
		printf("[ERR] %s:%d part_entry is NULL.\n", __FUNCTION__, __LINE__);
	}
}

void dump_fw_desc_entry_v1(fw_desc_entry_v1_t *fw_entry)
{
	if (fw_entry != NULL) {
		printf("## Fw Desc Entry ##############################\n");
		printf("## fw_entry                        = 0x%08x\n", fw_entry);
		printf("## fw_entry struct size            = 0x%08x\n", sizeof(fw_desc_entry_v1_t));
		printf("## fw_entry->type                  = 0x%08x\n", fw_entry->type);
		printf("## fw_entry->lzma                  = 0x%08x\n", fw_entry->lzma);
		printf("## fw_entry->ro                    = 0x%08x\n", fw_entry->ro);
		printf("## fw_entry->version               = 0x%08x\n", fw_entry->version);
		printf("## fw_entry->target_addr           = 0x%08x\n", fw_entry->target_addr);
		printf("## fw_entry->offset                = 0x%08x\n", fw_entry->offset);
		printf("## fw_entry->length                = 0x%08x\n", fw_entry->length);
		printf("## fw_entry->paddings              = 0x%08x\n", fw_entry->paddings);
		printf("## fw_entry->checksum              = 0x%08x\n", fw_entry->checksum);
		printf("###############################################\n\n");
	}
	else {
		printf("[ERR] %s:%d fw_entry is NULL.\n", __FUNCTION__, __LINE__);
	}
}
#endif

//#define DUBUG_BOOT_AV_INFO
#ifdef DUBUG_BOOT_AV_INFO
void dump_boot_av_info(boot_av_info_t *boot_av)
{
	if (boot_av != NULL) {
		printf("\n");
		printf("## Boot AV Info (0x%08x) ##################\n", boot_av);
		printf("## boot_av->dwMagicNumber          = 0x%08x\n", boot_av->dwMagicNumber);
		printf("## boot_av->dwVideoStreamAddress   = 0x%08x\n", boot_av->dwVideoStreamAddress);
		printf("## boot_av->dwVideoStreamLength    = 0x%08x\n", boot_av->dwVideoStreamLength);
		printf("## boot_av->dwAudioStreamAddress   = 0x%08x\n", boot_av->dwAudioStreamAddress);
		printf("## boot_av->dwAudioStreamLength    = 0x%08x\n", boot_av->dwAudioStreamLength);
		printf("## boot_av->bVideoDone             = 0x%08x\n", boot_av->bVideoDone);
		printf("## boot_av->bAudioDone             = 0x%08x\n", boot_av->bAudioDone);
		printf("## boot_av->bHDMImode              = 0x%08x\n", boot_av->bHDMImode);
		printf("## boot_av->dwAudioStreamVolume    = 0x%08x\n", boot_av->dwAudioStreamVolume);
		printf("## boot_av->dwAudioStreamRepeat    = 0x%08x\n", boot_av->dwAudioStreamRepeat);
		printf("## boot_av->bPowerOnImage          = 0x%08x\n", boot_av->bPowerOnImage);
		printf("## boot_av->bRotate                = 0x%08x\n", boot_av->bRotate);
		printf("## boot_av->dwVideoStreamType      = 0x%08x\n", boot_av->dwVideoStreamType);
		printf("## boot_av->audio_buffer_addr      = 0x%08x\n", boot_av->audio_buffer_addr);
		printf("## boot_av->audio_buffer_size      = 0x%08x\n", boot_av->audio_buffer_size);
		printf("## boot_av->video_buffer_addr      = 0x%08x\n", boot_av->video_buffer_addr);
		printf("## boot_av->video_buffer_size      = 0x%08x\n", boot_av->video_buffer_size);
		printf("## boot_av->last_image_addr        = 0x%08x\n", boot_av->last_image_addr);
		printf("## boot_av->last_image_size        = 0x%08x\n", boot_av->last_image_size);
		printf("###############################################\n\n");
	}
}
#endif

static void reset_shared_memory(void)
{
	boot_av_info_t *boot_av;
    
	boot_av = (boot_av_info_t *) MIPS_BOOT_AV_INFO_ADDR;
	if(boot_av-> dwMagicNumber != SWAPEND32(BOOT_AV_INFO_MAGICNO))
	{	
		/* clear boot_av_info memory */		
		memset(boot_av, 0, sizeof(boot_av_info_t));
	}
}	

/*
 * read Efuse.
 */
int rtk_get_secure_boot_type(void)
{
#ifdef CONFIG_CMD_KEY_BURNING
	if(OTP_JUDGE_BIT(OTP_BIT_SECUREBOOT))
		return RTK_SECURE_BOOT;
#endif	
	//return RTK_SECURE_BOOT;
	return NONE_SECURE_BOOT;
}


/*
 * Use firmware description table to read images from usb.
 */
int rtk_plat_read_fw_image_from_USB(int skip)
{
	return RTK_PLAT_ERR_OK;
}


int rtk_plat_get_dtb_target_address(int dtb_address)
{
	if( (CONFIG_FDT_LOADADDR<= dtb_address) && (dtb_address < CONFIG_LOGO_LOADADDR))	
		return dtb_address;
	else
		{
			printf("original DT address=%x\n",dtb_address);
			return CONFIG_FDT_LOADADDR;
		}
}

#ifdef CONFIG_PRELOAD_BOOT_IMAGES

#ifdef CONFIG_RTKSPI
int rtk_preload_bootimages_spi(void)
{
	unsigned int img_addr;
	unsigned int iSPI_base_addr;
	unsigned int iSPI_bl31_addr;
	unsigned int iSPI_bl31_size;
	unsigned int iSPI_uboot64_addr;
	unsigned int iSPI_uboot64_size;

	img_addr = getenv_ulong("bootcode2ndtmp_loadaddr", 16, 0);
	fw_hw_setting_header_t hw_setting_header;

	// read hwsetting header
	iSPI_base_addr = SPI_RBUS_BASE_ADDR + 0x00020000 + 0x800; // HW settubg base
	rtkspi_read32( &hw_setting_header, iSPI_base_addr, sizeof(fw_hw_setting_header_t));
	
	printf("%s : header info\n", __func__);
	printf(" 0x%08x 0x%08x 0x%08x 0x%08x\n", hw_setting_header.hwsetting_size
	                                       , hw_setting_header.bootloader_size
	                                       , hw_setting_header.fsbl_size
	                                       , hw_setting_header.secure_os_size);
	printf(" 0x%08x 0x%08x 0x%08x 0x%08x\n", hw_setting_header.atf_bl31_size
	                                       , hw_setting_header.Kpublic_fw_size
	                                       , hw_setting_header.Kpublic_tee_size
	                                       , hw_setting_header.bootloader64_size);
	printf(" 0x%08x\n", hw_setting_header.rescue_size);	                                       
	
	// read uboot64
	iSPI_bl31_addr = (hw_setting_header.hwsetting_size + 96 + 32) +
	                 (hw_setting_header.bootloader_size + 32 );
	iSPI_uboot64_addr = (hw_setting_header.hwsetting_size + 96 + 32) +
	                    (hw_setting_header.bootloader_size + 32 );
	if( hw_setting_header.fsbl_size ) {
		iSPI_bl31_addr += (hw_setting_header.fsbl_size + 32);
	    iSPI_uboot64_addr += (hw_setting_header.fsbl_size + 32);
	}
	if( hw_setting_header.secure_os_size ) {
		iSPI_bl31_addr += (hw_setting_header.secure_os_size + 32);
	    iSPI_uboot64_addr += (hw_setting_header.secure_os_size + 32);
	}
	if( hw_setting_header.atf_bl31_size ) {
	    iSPI_uboot64_addr += (hw_setting_header.atf_bl31_size + 32);
	}
	if( hw_setting_header.Kpublic_fw_size ) {
	    iSPI_uboot64_addr += (hw_setting_header.Kpublic_fw_size + 32);
	}
	if( hw_setting_header.Kpublic_tee_size ) {
	    iSPI_uboot64_addr += (hw_setting_header.Kpublic_tee_size + 32);
	}
	iSPI_uboot64_addr += (SPI_RBUS_BASE_ADDR + 0x00020000 + 0x800); // Parameter size is 0x800
	iSPI_uboot64_size = hw_setting_header.bootloader64_size;
	
	iSPI_bl31_addr += (SPI_RBUS_BASE_ADDR + 0x00020000 + 0x800); // Parameter size is 0x800
	iSPI_bl31_size = hw_setting_header.atf_bl31_size;
	
	// read uboot64
	if( iSPI_uboot64_size ) {
		printf("%s : load U-Boot 64 from 0x%08x to 0x%08x with size 0x%08x\n", __func__, iSPI_uboot64_addr, img_addr, iSPI_uboot64_size);
		rtkspi_read32( img_addr, iSPI_uboot64_addr, iSPI_uboot64_size);
	}
	
	// read BL31
	if( iSPI_bl31_size ) {
		img_addr = CONFIG_BL31_ADDR;
		printf("%s : load BL31 from 0x%08x to 0x%08x with size 0x%08x\n", __func__, iSPI_bl31_addr, img_addr, iSPI_bl31_size);
		rtkspi_read32( img_addr, iSPI_bl31_addr, iSPI_bl31_size);
	}
	
	return 0;
}
#endif // CONFIG_RTKSPI


#endif // CONFIG_PRELOAD_BOOT_IMAGES

void GetKeyFromSRAM(unsigned int sram_addr, unsigned char* key, unsigned int length)
{
        #define REG8( addr )		(*(volatile unsigned char*) (addr))

        int i = 0;
 
        for(i = 0; i < length; i++) {
            *(key + i) = REG8(sram_addr + i);
        }
}

/*
 * Use firmware description table to read images from eMMC flash.
 */
int rtk_plat_read_fw_image_from_eMMC(
		uint fw_desc_table_base, part_desc_entry_v1_t* part_entry, int part_count,
		void* fw_entry, int fw_count,
		uchar version)
{
	return RTK_PLAT_ERR_OK;
}

/*
 * Use firmware description table to read images from SATAflash.
 */
int rtk_plat_read_fw_image_from_SATA(
		uint fw_desc_table_base, part_desc_entry_v1_t* part_entry, int part_count,
		void* fw_entry, int fw_count,
		uchar version)
{
	return RTK_PLAT_ERR_OK;
}

/*
 * Use firmware description table to read images from NAND flash.
 */
int rtk_plat_read_fw_image_from_NAND(
		uint fw_desc_table_base, part_desc_entry_v1_t* part_entry, int part_count,
		void* fw_entry, int fw_count,
		uchar version)
{
	return RTK_PLAT_ERR_OK;
}

/*
 * Use firmware description table to read images from SPI flash.
 */
int rtk_plat_read_fw_image_from_SPI(void)
{
#if defined(CONFIG_SYS_RTK_SPI_FLASH) && defined (CONFIG_DTB_IN_SPI_NOR)
	unsigned int ret;
	// load DTS	
	if (boot_mode == BOOT_RESCUE_MODE || boot_mode == BOOT_ANDROID_MODE)
	{
		ret = rtkspi_load_DT_for_rescure_android(0);
		if( ret ) {
			printf("Rescue DT:\n");
			printf("          fdt addr = 0x%08x, len = 0x%08x\n", CONFIG_FDT_LOADADDR, ret);
		}
		else {
			printf("Rescue DT: not found\n");
			return RTK_PLAT_ERR_PARSE_FW_DESC;
		}
	}
	else if (boot_mode == BOOT_MANUAL_MODE || boot_mode == BOOT_NORMAL_MODE || boot_mode == BOOT_CONSOLE_MODE)
	{
		ret = rtkspi_load_DT_for_kernel(0);
		if( ret ) {
			printf("DT:\n");
			printf("          fdt addr = 0x%08x, len = 0x%08x\n", CONFIG_FDT_LOADADDR, ret);
		}
		else {
			printf("DT: not found\n");
			return RTK_PLAT_ERR_PARSE_FW_DESC;
		}
	}
	else
	{
		printf("[TODO] boot from SPI is not ready! (boot mode=%d)\n", boot_mode);
		return RTK_PLAT_ERR_PARSE_FW_DESC;
	}
		
#endif	

	return RTK_PLAT_ERR_OK;
}



char *rtk_plat_prepare_fw_image_from_USB(int fw_type)
{
	return NULL; 
}

/*
 * Parse firmware description table and read all data from eMMC flash to ram except kernel image.
 */
int rtk_plat_prepare_fw_image_from_eMMC(void)
{
	int ret = RTK_PLAT_ERR_OK;
	return ret;
}

/*
 * Parse firmware description table and read all data from SATA to ram except kernel image.
 */
int rtk_plat_prepare_fw_image_from_SATA(void)
{
	int ret = RTK_PLAT_ERR_OK;
	return ret;
}

int rtk_plat_get_fw_desc_table_start(void)
{

	return 0;
}

/*
 * Parse firmware description table and read all data from NAND flash to ram except kernel image.
 */
int rtk_plat_prepare_fw_image_from_NAND(void)
{
	int ret = RTK_PLAT_ERR_OK;
	return ret;
}

/*
 * Parse firmware description table and read all data from SPI flash to ram except kernel image.
 */
int rtk_plat_prepare_fw_image_from_SPI(void)
{
	int ret = RTK_PLAT_ERR_OK;

#if 0 // for nor
	/* Get flash size. */
	if((rcode = SYSCON_read(SYSCON_BOARD_MONITORFLASH_SIZE_ID,
				&flash_size, sizeof(flash_size))) != OK) {
		printf("get flash size fail!!\n");
		return NULL;
	}

	flash_end_addr = 0xbec00000 + flash_size ;

	/* SCIT signature address */
	scit_signature_addr = (void*)0xbec00000 + 0x100000 + 0x10000 - 0x100;


	memcpy(&fw_desc_table, (void*)(flash_end_addr - sizeof(fw_desc_table)), sizeof(fw_desc_table));
	fw_desc_table.checksum = BE32_TO_CPU(fw_desc_table.checksum);
	memcpy(fw_desc_entry, (void*)(flash_end_addr - sizeof(fw_desc_table) -sizeof(fw_desc_entry)),
					sizeof(fw_desc_entry));

	checksum = get_checksum((uchar*)&fw_desc_table +
			offsetof(fw_desc_table_t, version),
			sizeof(fw_desc_table_t) - offsetof(fw_desc_table_t, version));
	checksum += get_checksum((uchar*)fw_desc_entry, sizeof(fw_desc_entry));

	memcpy(signature_str_buf, fw_desc_table.signature, sizeof(fw_desc_table.signature));

	/* Check checksum and signature. */
	if(fw_desc_table.checksum != checksum ||
			strncmp(fw_desc_table.signature,
			FIRMWARE_DESCRIPTION_TABLE_SIGNATURE,
			sizeof(fw_desc_table.signature)) != 0) {
		printf("Checksum(0x%x) or signature(%s) error! Entering rescue linux...\n",
			fw_desc_table.checksum, signature_str_buf);
#if defined(Rescue_Source_USB) && defined(Board_USB_Driver_Enabled)
		return run_rescue_from_usb(RESCUE_LINUX_FILE_NAME);
#elif defined(Rescue_Source_FLASH)
#if defined(Logo_Source_FLASH)
#if defined(Logo6_Source_FLASH)
		LOGO_DISP_change(5);
#endif
#endif
		return run_rescue_from_flash();
#else
		return NULL;
#endif /* defined(Rescue_Source_USB) && defined(Board_USB_Driver_Enabled) */
	}


	if(strncmp((char*)scit_signature_addr, VERONA_SCIT_SIGNATURE_STRING,
			strlen(VERONA_SCIT_SIGNATURE_STRING)) != 0) {
		printf("Can not find signature string, \"%s\"! Entering rescue linux...\n",
			VERONA_SCIT_SIGNATURE_STRING);
#if defined(Rescue_Source_USB) && defined(Board_USB_Driver_Enabled)
		return run_rescue_from_usb(rescue_file);
#elif defined(Rescue_Source_FLASH)
#if defined(Logo_Source_FLASH)
#if defined(Logo6_Source_FLASH)
		LOGO_DISP_change(5);
#endif
#endif
		return run_rescue_from_flash();
#else
		return NULL;
#endif /* defined(Rescue_Source_USB) && defined(Board_USB_Driver_Enabled) */
	}

	fw_desc_table.length = BE32_TO_CPU(fw_desc_table.length);

	for(i = 0; i < (int)ARRAY_COUNT(fw_desc_entry); i++) {
		fw_desc_entry[i].version =
			BE32_TO_CPU(fw_desc_entry[i].version);
		fw_desc_entry[i].target_addr =
			BE32_TO_CPU(fw_desc_entry[i].target_addr);
		fw_desc_entry[i].offset = BE32_TO_CPU(fw_desc_entry[i].offset);
		fw_desc_entry[i].length = BE32_TO_CPU(fw_desc_entry[i].length);
		fw_desc_entry[i].paddings = BE32_TO_CPU(fw_desc_entry[i].paddings);
		fw_desc_entry[i].checksum = BE32_TO_CPU(fw_desc_entry[i].checksum);
	}

	return run_kernel_from_flash(0x9ec00000, flash_size,
			fw_desc_entry, ARRAY_COUNT(fw_desc_entry));
#endif

	ret = rtk_plat_read_fw_image_from_SPI();

	return ret;
}


//#define DEBUG_SKIP_BOOT_ALL
//#define DEBUG_SKIP_BOOT_LINUX
//#define DEBUG_SKIP_BOOT_AV

#if (defined(CONFIG_RTD1195) || defined(CONFIG_RTD1295)) && defined(NAS_ENABLE)
extern int rtk_plat_boot_prep_nas_partition(void);
#endif

/* Calls bootm with the parameters given */
static int rtk_call_bootm(void)
{
	char *bootm_argv[] = { "bootm", NULL, "-", NULL, NULL };
	int ret = 0;
	int j;
	int argc=4;


	if ((bootm_argv[1] = getenv("kernel_loadaddr")) == NULL) {
		bootm_argv[1] =(char*) CONFIG_KERNEL_LOADADDR;
	}

	if ((bootm_argv[3] = getenv("fdt_loadaddr")) == NULL) {
		bootm_argv[3] =(char*) CONFIG_FDT_LOADADDR;
	}

	/*
	 * - do the work -
	 * exec subcommands of do_bootm to init the images
	 * data structure
	 */
	debug("bootm_argv ={ ");
	for (j = 0; j < argc; j++)
			debug("%s,",bootm_argv[j]);
	debug("}\n");

#ifdef CONFIG_SECOND_BOOTCODE_SUPPORT && CONFIG_RTD1295
#if (defined(CONFIG_RTD1195) || defined(CONFIG_RTD1295)) && defined(NAS_ENABLE)
	rtk_plat_boot_prep_nas_partition();
#endif
	run_command_list("b2ndbc", -1, 0);
#else
	ret = do_bootm(find_cmd("do_bootm"), 0, argc,bootm_argv);
#endif


	if (ret) {
		printf("ERROR do_bootm failed!\n");
		return -1;
	}

	return 1;
}

int rtk_plat_set_fw(void)
{
	int ret = RTK_PLAT_ERR_OK;
	char cmd[16];
	int magic = SWAPEND32(0x16803001);
	int offset = SWAPEND32(MIPS_SHARED_MEMORY_ENTRY_ADDR);

	printf("Start Boot Setup ... ");

	/* reset some shared memory */
	reset_shared_memory();

#ifdef DEBUG_SKIP_BOOT_ALL // Skip by CK
	printf("(CK skip)\n");
	return RTK_PLAT_ERR_PARSE_FW_DESC;
#else
	printf("\n");
#endif
	if (boot_from_usb != BOOT_FROM_USB_DISABLE) // workaround path that read fw img from usb
	{			
		ret = rtk_plat_read_fw_image_from_USB(0);
	}
	else
	{
		/* parse fw_desc_table, and read all data from flash to ram except kernel image */
		if (boot_flash_type == BOOT_EMMC)
		{
			/* For eMMC */
			ret = rtk_plat_prepare_fw_image_from_eMMC();
		}
		else if (boot_flash_type == BOOT_SATA)
		{ 
			/* For SATA */
			ret = rtk_plat_prepare_fw_image_from_SATA();
		}
		else if (boot_flash_type == BOOT_NAND)
		{
			/* For NAND */
			ret = rtk_plat_prepare_fw_image_from_NAND();
#ifdef NAS_ENABLE
			if(ret != RTK_PLAT_ERR_OK){
				nas_rescue = 1;
				boot_mode = BOOT_RESCUE_MODE;
				ret = rtk_plat_prepare_fw_image_from_NAND();
			}
#endif
		}
		else
		{
#ifdef CONFIG_BOOT_FROM_SATA
			ret = rtk_plat_prepare_fw_image_from_SATA();
#else			
			/* For SPI */
			ret = rtk_plat_prepare_fw_image_from_SPI();
#ifdef CONFIG_BOOT_FROM_USB
			if(ret == RTK_PLAT_ERR_OK)			
				ret = rtk_plat_read_fw_image_from_USB(0);
#endif /* CONFIG_BOOT_FROM_USB */

#endif /* CONFIG_BOOT_FROM_SATA */
		}
	}

#if CONFIG_ANDROID_RECOVERY
    /* factory save ---------work space----------------*/
    //gen recovery signature(update.zip from backup partition).
    if((ret == RTK_PLAT_ERR_OK) && (boot_mode == BOOT_GOLD_MODE))
    {
        printf("------------recovery write start--------------\n");
        
        /* write in emmc */
        bootloader_message *boot=(bootloader_message *)BACKUP_DESCRIPTION_RECOVERY_ADDR;
        memset(boot, 0, sizeof(bootloader_message));
        memset(boot->command, '\0', sizeof(boot->command));
        memset(boot->recovery, '\0', sizeof(boot->recovery));
        sprintf(boot->command, "boot-recovery");
        sprintf(boot->recovery, "recovery\n--update_package=BACKUP:update.zip\n--locale=en_GB");

#ifdef CONFIG_SYS_FACTORY
    	ret = factory_write(RECOVERY_FILE_IN_FACTORY, (char *)boot, CONFIG_RECOVERY_SIZE);
    	if (ret != 0) 
        { 
            // failed case
    		printf("[ENV] write_recovery failed\n");
    	}
    	else
		    factory_save();
#else
	    printf("[ENV][WARN] CONFIG_SYS_FACTORY is not defined.\n");
#endif
        printf("------------recovery write end--------------\n");
        ret = RTK_PLAT_ERR_OK;
    }
#endif
#ifndef DEBUG_SKIP_BOOT_AV // mark for boot linux kernel only
	if (boot_from_flash == BOOT_FROM_FLASH_NORMAL_MODE)
	{
		if (ret == RTK_PLAT_ERR_OK)
		{
			run_command("go a", 0);
		}
	}
	else
	{
		printf("[Skip A] boot manual mode\n");
	}
#endif

	return ret;
}

//all standard boot_cmd entry.
int rtk_plat_do_boot_linux(void)
{

	rtk_call_bootm();

	/* Reached here means jump to kernel entry flow failed */

	return RTK_PLAT_ERR_BOOT;

}
/*
 ************************************************************************
 *
 * This is the final part before booting Linux in realtek platform:
 * we need to move audio/video firmware and stream files
 * from flash to ram. We will also decompress or decrypt image files,
 * if necessary, which depends on the information from flash writer.
 *
 ************************************************************************
 */
int  rtk_plat_boot_handler(void)
{
	int ret = RTK_PLAT_ERR_OK;

	/* copy audio/video firmware and stream files from flash to ram */
	ret = rtk_plat_set_fw();
	if (ret == RTK_PLAT_ERR_OK)
	{
#ifndef DEBUG_SKIP_BOOT_LINUX
		if (boot_from_flash == BOOT_FROM_FLASH_NORMAL_MODE)
		{
			/* go Linux */
#ifdef CONFIG_REALTEK_WATCHDOG
			WATCHDOG_KICK();
#else
			WATCHDOG_DISABLE();
#endif

			EXECUTE_CUSTOMIZE_FUNC(1); // insert execute customer callback at here

			ret = rtk_plat_do_boot_linux ();
		}
		else
		{
			printf("[Skip K] boot manual mode (execute \"go all\")\n");
		}
#endif
	}

	return ret;
}

#ifdef CONFIG_MODULE_TEST
void rtk_plat_do_bootr_after_mt()
{
	int ret = RTK_PLAT_ERR_OK;

	/* reset boot flags */
	boot_from_flash = BOOT_FROM_FLASH_NORMAL_MODE;
	boot_from_usb = BOOT_FROM_USB_DISABLE;

	WATCHDOG_KICK();
	ret = rtk_plat_boot_handler();
	return;
}
#endif

int rtk_plat_do_bootr(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	int ret = RTK_PLAT_ERR_OK;
	/* reset boot flags */
	boot_from_flash = BOOT_FROM_FLASH_NORMAL_MODE;
	boot_from_usb = BOOT_FROM_USB_DISABLE;

	/* parse option */
	if (argc == 1)
	{
		boot_from_usb = BOOT_FROM_USB_DISABLE;
	}
	else if (argc == 2 && argv[1][0] == 'u')
	{
		if (argv[1][1] == 'z')
		{
			boot_from_usb = BOOT_FROM_USB_COMPRESSED;
		}
		else if (argv[1][1] == '\0')
		{
			boot_from_usb = BOOT_FROM_USB_UNCOMPRESSED;
		}
		else
		{
			return CMD_RET_USAGE;
		}
	}
	else if (argc == 2 && argv[1][0] == 'm')
	{
		boot_from_flash = BOOT_FROM_FLASH_MANUAL_MODE;
	}
	else
	{
		return CMD_RET_USAGE;
	}

	WATCHDOG_KICK();
	ret = rtk_plat_boot_handler();
#ifdef CONFIG_RESCUE_FROM_USB
	if (ret != RTK_PLAT_ERR_OK) {
		ret = boot_rescue_from_usb();
    }
#endif /* CONFIG_RESCUE_FROM_USB */

//adam 0729 start
#ifdef CONFIG_RESCUE_FROM_DHCP
//add the boot dhcp function when rescue from usb fail	
	if (ret != RTK_PLAT_ERR_OK) {
		ret = boot_rescue_from_dhcp();
	}
//adam 0729 end	
#endif
	
	return CMD_RET_SUCCESS;
}

U_BOOT_CMD(
	bootr, 2, 0,	rtk_plat_do_bootr,
	"boot realtek platform",
	"[u/uz]\n"
	"\tu   - boot from usb\n"
	"\tuz  - boot from usb (use lzma image)\n"
	"\tm   - read fw from flash but boot manually (go all)\n"
);
#endif