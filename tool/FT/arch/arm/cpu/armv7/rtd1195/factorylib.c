#include <common.h>
#include <exports.h>
#include <asm/arch/factorylib.h>
#include <asm/arch/system.h>
#include <fw_info.h>
#include <tar.h>
#include <nand.h>

#define ENABLE_FACTORY_CONSOLE_MODE
//#define ENABLE_FACTORY_DEBUG

#define FAC_PRINTF(fmt, args...)	printf(fmt, ##args)

#ifdef	ENABLE_FACTORY_DEBUG
#define FAC_DEBUG(fmt, args...)		printf(fmt, ##args)
#else
#define FAC_DEBUG(fmt, args...)
#endif

#ifndef CONFIG_FACTORY_START
#define CONFIG_FACTORY_START	0x1800000	/* For eMMC */
#endif
#ifndef CONFIG_FACTORY_SIZE
#define CONFIG_FACTORY_SIZE		0x800000	/* For eMMC */
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int factory_dirty = 0;
static uchar *factory_buffer = NULL;
static uchar *factory_buffer2 = NULL;
static int factory_tarsize = 0;
static int factory_current_pp = 0;
static int factory_seq_num = 0;

extern BOOT_FLASH_T boot_flash_type;
extern unsigned int tar_read_print_info;
extern unsigned char tar_read_print_prefix[32];

////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int factory_check_sanity_from_SPI(uchar *buffer, int length)
{
	int ret = 0;

#ifndef CONFIG_SYS_RTK_SPI_FLASH
	FAC_DEBUG("[FAC][WARN] CONFIG_SYS_RTK_SPI_FLASH is undefined\n");
#endif

	return ret;
}

static loff_t factory_get_start_address(void)
{
#ifdef CONFIG_SYS_RTK_NAND_FLASH
	struct mtd_info *mtd = &nand_info[nand_curr_device];
	int uboot_512KB = 0x80000;
	int factory_8MB = 0x800000 ;
	int reservedSize;
	 
	reservedSize = 6* mtd->erasesize;  //NF profile + BBT + Hw_setting*4
	reservedSize += (1*4)* mtd->erasesize; //Hw_setting*4
	reservedSize += rtd_size_aligned(uboot_512KB ,mtd->erasesize)*4;
	reservedSize += rtd_size_aligned(factory_8MB ,mtd->erasesize);
	
	// add extra 20% space for safety.	
	reservedSize = rtd_size_aligned(reservedSize*1.2 ,mtd->erasesize);
			
	return (reservedSize -factory_8MB);	
#endif
	return 0;	
}

static int factory_check_sanity_from_NAND(uchar *buffer, int length)
{
#ifdef CONFIG_SYS_RTK_NAND_FLASH
		int dev = nand_curr_device;
		nand_info_t *nand =&nand_info[dev];		//nand_info[0];
		struct nand_chip *this = (struct nand_chip *) nand->priv;
		
		unsigned long long from;
		unsigned int retlen;
		unsigned int num_temp,num_temp1;
		
		uint factory_header_bytes = 512;
		uint blk_start, blk_cnt = 0;
		//int n = 0;
		int ret = 0;
		posix_header *p_start = NULL;
		posix_header *p_end = NULL;
		char factory_header[] = FACTORY_HEADER_FILE_NAME;
		uint pp_ok = 0;
		unsigned int pp_seqnum[2];
		unsigned int pp_tarsize[2];
		int i = 0;
		void *buf_contain_a_header;
		loff_t	read_addr;
	
		if (buffer == NULL) {
			FAC_PRINTF("[FAC][ERR] factory buffer is NULL\n");
			return -1;
		}

		/* reset factory data in ddr */
		memset(buffer, 0, length);
	
		p_start = (posix_header *)malloc(nand->oobblock);		// 1 page
		if (p_start == NULL) {
			FAC_PRINTF("[FAC][ERR] p_start malloc(%d) failed\n", nand->oobblock);
			return -1;
		}
	
		memset(p_start, 0, nand->oobblock);
	
		buf_contain_a_header = (posix_header *)malloc(nand->oobblock * 2);
		if (buf_contain_a_header == NULL) {
			FAC_PRINTF("[FAC][ERR] buf_contain_a_header malloc(%d) failed\n", nand->oobblock * 2);
			free(p_start);
			return -1;
		}
	
		memset(buf_contain_a_header, 0, nand->oobblock * 2);
		// page alignment.
		
		// calculate start address.		
#ifdef CONFIG_PROTECTED_AREA_OLD_LAYOUT	
        read_addr = (nand->oobblock)*512*31- CONFIG_FACTORY_SIZE;	
#else		
		read_addr = factory_get_start_address();
#endif		
		//printn(read_addr,16);
			
		for (i = 0;i < 2;i++)
		{
			/* Read factory header */
			from = read_addr + i * (CONFIG_FACTORY_SIZE / 2);
			nand->read(nand, from, nand->oobblock, &retlen, (unsigned char *)p_start);             
			
			if (retlen != nand->oobblock)
			{
			/* Read error */
			FAC_PRINTF("[FAC][ERR] Get factory header from NAND failed\n");
			ret = -1;
			}
			else
			{
			/* Read success */
			FAC_DEBUG("[FAC] Get factory header from NAND\n");
			}


#ifdef ENABLE_FACTORY_DEBUG
			FAC_DEBUG("[FAC] ******** CHECK FACTORY HEADER [%d] ********\n", i);
	
			if (!ret) {
				FAC_DEBUG("[FAC] -- PASS: read nand\n");
			}
			else {
				FAC_DEBUG("[FAC] -- FAIL: read nand\n");
				continue;
			}

			if (!strcmp(p_start->rtk_signature, "RTK")) {
				FAC_DEBUG("[FAC] -- PASS: rtk signature\n");
			}
			else {
				FAC_DEBUG("[FAC] -- FAIL: rtk signature\n");
				continue;
			}
	
			if (!strcmp(p_start, factory_header)) {
				FAC_DEBUG("[FAC] -- PASS: factory header\n");
			}
			else {
				FAC_DEBUG("[FAC] -- FAIL: factory header\n");
				continue;
			}
	
			if (tar_check_header(p_start) == 0) {
				FAC_DEBUG("[FAC] -- PASS: tar header\n");
			}
			else {
				FAC_DEBUG("[FAC] -- FAIL: tar header\n");
				continue;
			}
	
			if (p_start->rtk_tarsize >= 256) {
				FAC_DEBUG("[FAC] -- PASS: tar size >= 256\n");
			}
			else {
				FAC_DEBUG("[FAC] -- FAIL: tar size < 256\n");
				continue;
			}
	
			if (!strcmp(p_start->rtk_signature, "RTK")) {
				FAC_DEBUG("[FAC] -- PASS: rtk signature\n");
			}
			else {
				FAC_DEBUG("[FAC] -- FAIL: rtk signature\n");
				continue;
			}
	
			if (p_start->rtk_tarsize < (CONFIG_FACTORY_SIZE / 2 - sizeof(posix_header))) {
				FAC_DEBUG("[FAC] -- PASS: tar size 0x%08x\n", p_start->rtk_tarsize);
			}
			else {
				FAC_DEBUG("[FAC] -- FAIL: tar size 0x%08x > 0x%08x\n", p_start->rtk_tarsize, CONFIG_FACTORY_SIZE/2 - sizeof(posix_header));
				continue;
			}
	
			FAC_DEBUG("[FAC] ******** CHECK FACTORY HEADER [%d] ALL PASS\n", i);
			FAC_DEBUG("[FAC] Need to check the end header\n");
#endif
			/* check header */
			if (!ret && !strcmp((const char *)p_start, factory_header) && (tar_check_header((char *)p_start) == 0) && (p_start->rtk_tarsize >= 256)
					&& !strcmp(p_start->rtk_signature, "RTK") && (p_start->rtk_tarsize < (CONFIG_FACTORY_SIZE / 2 - sizeof(posix_header)))) {
	
				pp_seqnum[i] = p_start->rtk_seqnum;
				pp_tarsize[i] = p_start->rtk_tarsize;
	
				//from = (CONFIG_FACTORY_START + p_start->rtk_tarsize + i * CONFIG_FACTORY_SIZE / 2) ;
				//printf("p_start->rtk_tarsize = %x\n",p_start->rtk_tarsize);
				num_temp = p_start->rtk_tarsize /nand->oobblock;
				num_temp1 = p_start->rtk_tarsize % nand->oobblock;
				
				from = (read_addr + num_temp*nand->oobblock+ i * CONFIG_FACTORY_SIZE / 2) ;
				
				nand->read(nand, from, nand->oobblock*2, &retlen,(unsigned char *)buf_contain_a_header);
				if (retlen != 2*nand->oobblock)
				{
					/* Read error */
					FAC_PRINTF("[FAC][ERR] Get factory tail from nand failed\n");
					ret = -1;
				}else
				{
					/* Read success */
					FAC_DEBUG("[FAC] Get factory tail [%d] from nand\n", i);
				}
				p_end = (posix_header*)(((unsigned int) buf_contain_a_header) + (p_start->rtk_tarsize % nand->oobblock));
	
#if 0 //def ENABLE_FACTORY_DEBUG
				FAC_DEBUG("[FAC] **dump p_start at %x\n", p_start);
				tar_dump_posix_header(p_start);
	
				FAC_DEBUG("[FAC] **dump p_end at %x\n", p_end);
				tar_dump_posix_header(p_end);
#endif
	
				if (!memcmp(p_end, p_start, sizeof(posix_header))) {
					FAC_DEBUG("[FAC] pp %d ok\n", i);
					pp_ok |= (1 << i);
				}
			}
		}
	
		free(p_start);
		free(buf_contain_a_header);
	
		FAC_DEBUG("[FAC] result: pp_ok = 0x%x\n", pp_ok);
		switch (pp_ok) {
			case 1:
				factory_current_pp = 0;
				break;
			case 2:
				factory_current_pp = 1;
				break;
			case 3:
				if (pp_seqnum[1] > pp_seqnum[0]) {
					if ((pp_seqnum[1] - pp_seqnum[0]) > 0xFFFFFFF0) {
						factory_current_pp = 0;
					}
					else {
						factory_current_pp = 1;
					}
				}
				else {
					factory_current_pp = 0;
				}
				break;
			default:
			case 0:
				p_start = (posix_header *)buffer;
				tar_build_header((char *)p_start, FACTORY_HEADER_FILE_NAME, 0, '5');
				p_start->rtk_signature[0] = 'R';
				p_start->rtk_signature[1] = 'T';
				p_start->rtk_signature[2] = 'K';
				p_start->rtk_signature[3] = 0;
				p_start->rtk_tarsize = sizeof(posix_header);
				p_start->rtk_seqnum = factory_seq_num;
				tar_fill_checksum((char *)p_start);
				tar_check_header((char *)p_start);
				FAC_DEBUG("[FAC] pp:%d, seq:0x%x\n", factory_current_pp, factory_seq_num);
				FAC_PRINTF("[FAC] No factory data in NAND\n");
				return sizeof(posix_header);
	
		}
	
		from = (read_addr + factory_current_pp * CONFIG_FACTORY_SIZE / 2) ;
		num_temp1 = ((pp_tarsize[factory_current_pp] + nand->oobblock-1) /nand->oobblock) * nand->oobblock;
		nand->read(nand, from, num_temp1, &retlen,(unsigned char *)buffer);
		if (retlen != num_temp1)
		{
			/* Read error */
			FAC_PRINTF("[FAC][ERR] Get factory  from nand failed\n");
			ret = -1;
		}else
		{
			/* Read success */
			FAC_DEBUG("[FAC] Get factory  from nand ok\n");
		}

		factory_seq_num = pp_seqnum[factory_current_pp];
	
		FAC_PRINTF("Factory: seq:0x%x, blk:0x%x(pp:%d), size:0x%x (to 0x%x)\n",
			factory_seq_num, blk_start, factory_current_pp, pp_tarsize[factory_current_pp], (unsigned int)buffer);
	
		return pp_tarsize[factory_current_pp];
	
#else /* !CONFIG_SYS_RTK_NAND_FLASH */
	
		FAC_DEBUG("[FAC][WARN] CONFIG_SYS_RTK_NAND_FLASH is undefined\n");
		return 0;
	
#endif

	//return ret;
}


static int factory_check_sanity_from_NAND_old(uchar *buffer, int length)
{
	int ret = 0;
	
#ifdef CONFIG_SYS_RTK_NAND_FLASH

	uint factory_header_bytes = 512; // sizeof(posix_header)
	uint blk_start;
	posix_header *p_start = NULL;
	posix_header *p_end = NULL;
	char factory_header[] = FACTORY_HEADER_FILE_NAME;
	uint pp_ok = 0;
	unsigned int pp_seqnum, pp_tarsize;
	void *buf_contain_a_header;
	size_t retlen;
	loff_t	read_addr;
	uint	read_len;
	struct mtd_info *mtd = &nand_info[nand_curr_device];

	#if 0
		// test code.
		unsigned char *data;

		printk("[%s] entry\n", __FUNCTION__);
		printk("oobblock(0x%x), oobsize(0x%x), eccsize(0x%x) \n",
			mtd->oobblock, mtd->oobsize, mtd->eccsize);
		
		data = (posix_header *)malloc(mtd->oobblock);
		//oob = (posix_header *)malloc(mtd->oobsize);

		ret = mtd->read_ecc(mtd, 0*mtd->erasesize, mtd->oobblock, &retlen, data, NULL, NULL);
		if (ret == 0) {
			printk("retlen = 0x%x \n", retlen);
			rtk_hexdump("data: ", data, mtd->oobblock);
		}

		free(data);

		return 0;
	#endif

 	if (buffer == NULL) {
		FAC_PRINTF("[FAC][ERR] factory buffer is NULL\n");
		return -1;
 	}

	/* reset factory data in ddr */
	memset(buffer, 0, length);

	p_start = (posix_header *)malloc(mtd->oobblock);
	buf_contain_a_header = (posix_header *)malloc(CONFIG_FACTORY_SIZE);

	// page alignment.
	read_len = ((length>>mtd->writesize_shift) + 1) << mtd->writesize_shift;
	
	// calculate start address.
	if(mtd->erasesize== 0x40000)
		read_addr = 0x1B00000;	// 31M - 4M
	else if (mtd->erasesize == 0x100000)
		read_addr = 0x3600000;	// 62M - 8M
	else
		read_addr = 0x7400000; // 124M - 8M

	//blk_start = CONFIG_FACTORY_START_BLK;
	ret = mtd->read_ecc(mtd, read_addr, read_len, &retlen, p_start, NULL, NULL);

	if (ret)
	{
		/* Read error */
		FAC_PRINTF("[FAC][ERR] Get factory header from NAND failed\n");
		ret = -1;
	}
	else
	{
		/* Read success */
		FAC_DEBUG("[FAC] Get factory header from NAND\n");
	}
	
#ifdef ENABLE_FACTORY_DEBUG
	FAC_DEBUG("[FAC] ******** CHECK FACTORY HEADER ********\n");

	if (!strcmp(p_start, factory_header)) {
		FAC_DEBUG("[FAC] -- PASS: factory header\n");
	}
	else {
		FAC_DEBUG("[FAC] -- FAIL: factory header\n");
		ret = -1;
	}

	if (tar_check_header(p_start) == 0) {
		FAC_DEBUG("[FAC] -- PASS: tar header\n");
	}
	else {
		FAC_DEBUG("[FAC] -- FAIL: tar header\n");
		ret = -1;
	}

	if (p_start->rtk_tarsize >= 256) {
		FAC_DEBUG("[FAC] -- PASS: tar size >= 256\n");
	}
	else {
		FAC_DEBUG("[FAC] -- FAIL: tar size < 256\n");
		ret = -1;
	}

	if (!strcmp(p_start->rtk_signature, "RTK")) {
		FAC_DEBUG("[FAC] -- PASS: rtk signature\n");
	}
	else {
		FAC_DEBUG("[FAC] -- FAIL: rtk signature\n");
		ret = -1;
	}

	if (p_start->rtk_tarsize < (CONFIG_FACTORY_SIZE - sizeof(posix_header))) {
		FAC_DEBUG("[FAC] -- PASS: tar size 0x%08x\n", p_start->rtk_tarsize);
	}
	else {
		FAC_DEBUG("[FAC] -- FAIL: tar size 0x%08x > 0x%08x\n", p_start->rtk_tarsize, CONFIG_FACTORY_SIZE - sizeof(posix_header));
		ret = -1;
	}

	if (!ret) {
		FAC_DEBUG("[FAC] ******** CHECK FACTORY HEADER ALL PASS\n");
		FAC_DEBUG("[FAC] Need to check the end header\n");
	}
#endif

	if (!ret && !strcmp((const char *)p_start, factory_header) && (tar_check_header((char *)p_start) == 0) && (p_start->rtk_tarsize >= 256)
			&& !strcmp(p_start->rtk_signature, "RTK") && (p_start->rtk_tarsize < (CONFIG_FACTORY_SIZE - sizeof(posix_header)))) {

		pp_seqnum = p_start->rtk_seqnum;
		pp_tarsize = p_start->rtk_tarsize;

		// page alignment.
		read_len = ((pp_tarsize>>mtd->writesize_shift) + 1) << mtd->writesize_shift;
		
		//ret = mtd->read_ecc(mtd, read_addr, p_start->rtk_tarsize, &retlen, buf_contain_a_header, NULL, NULL);
		ret = mtd->read_ecc(mtd, read_addr, read_len, &retlen, buf_contain_a_header, NULL, NULL);
		p_end = (posix_header*)(((unsigned int) buf_contain_a_header) + (p_start->rtk_tarsize));

		if (!memcmp(p_end, p_start, sizeof(posix_header))) {
			pp_ok = 1;
		}
	}

	// reset return value to 0.
	ret = 0;
	
	if (pp_ok) {
		if (length >= p_start->rtk_tarsize) {
			memcpy(buffer, buf_contain_a_header, p_start->rtk_tarsize);
			ret = p_start->rtk_tarsize;
		}
	}

	free(p_start);
	free(buf_contain_a_header);

#else
	FAC_DEBUG("[FAC][WARN] CONFIG_SYS_RTK_NAND_FLASH is undef\n");
#endif

	return ret;
}

static int factory_check_sanity_from_eMMC(uchar *buffer, int length)
{
#ifdef CONFIG_SYS_RTK_EMMC_FLASH

	uint factory_header_bytes = 512;
	uint blk_start, blk_cnt = 0;
	int n = 0;
	int ret = 0;
	posix_header *p_start = NULL;
	posix_header *p_end = NULL;
	char factory_header[] = FACTORY_HEADER_FILE_NAME;
	uint pp_ok = 0;
	unsigned int pp_seqnum[2], pp_tarsize[2];
	int i = 0;
	void *buf_contain_a_header;

 	if (buffer == NULL) {
		FAC_PRINTF("[FAC][ERR] factory buffer is NULL\n");
		return -1;
 	}

	/* reset factory data in ddr */
	memset(buffer, 0, length);

	p_start = (posix_header *)malloc(factory_header_bytes);
	buf_contain_a_header = (posix_header *)malloc(factory_header_bytes * 2);

	for (i = 0;i < 2;i++)
	{
		/* Read factory header */
		blk_start = (CONFIG_FACTORY_START + i * CONFIG_FACTORY_SIZE / 2) / EMMC_BLOCK_SIZE;
		blk_cnt = factory_header_bytes / EMMC_BLOCK_SIZE;
		n = rtk_eMMC_read(blk_start, factory_header_bytes, (unsigned int *)p_start);
		if (n != blk_cnt)
		{
			/* Read error */
			FAC_PRINTF("[FAC][ERR] Get factory header from eMMC failed\n");
			ret = -1;
		}
		else
		{
			/* Read success */
			FAC_DEBUG("[FAC] Get factory header [%d] from eMMC\n", i);
		}

#ifdef ENABLE_FACTORY_DEBUG
		FAC_DEBUG("[FAC] ******** CHECK FACTORY HEADER [%d] ********\n", i);

		if (!ret) {
			FAC_DEBUG("[FAC] -- PASS: read emmc\n");
		}
		else {
			FAC_DEBUG("[FAC] -- FAIL: read emmc\n");
			continue;
		}

		if (!strcmp(p_start, factory_header)) {
			FAC_DEBUG("[FAC] -- PASS: factory header\n");
		}
		else {
			FAC_DEBUG("[FAC] -- FAIL: factory header\n");
			continue;
		}

		if (tar_check_header(p_start) == 0) {
			FAC_DEBUG("[FAC] -- PASS: tar header\n");
		}
		else {
			FAC_DEBUG("[FAC] -- FAIL: tar header\n");
			continue;
		}

		if (p_start->rtk_tarsize >= 256) {
			FAC_DEBUG("[FAC] -- PASS: tar size >= 256\n");
		}
		else {
			FAC_DEBUG("[FAC] -- FAIL: tar size < 256\n");
			continue;
		}

		if (!strcmp(p_start->rtk_signature, "RTK")) {
			FAC_DEBUG("[FAC] -- PASS: rtk signature\n");
		}
		else {
			FAC_DEBUG("[FAC] -- FAIL: rtk signature\n");
			continue;
		}

		if (p_start->rtk_tarsize < (CONFIG_FACTORY_SIZE / 2 - sizeof(posix_header))) {
			FAC_DEBUG("[FAC] -- PASS: tar size 0x%08x\n", p_start->rtk_tarsize);
		}
		else {
			FAC_DEBUG("[FAC] -- FAIL: tar size 0x%08x > 0x%08x\n", p_start->rtk_tarsize, CONFIG_FACTORY_SIZE/2 - sizeof(posix_header));
			continue;
		}

		FAC_DEBUG("[FAC] ******** CHECK FACTORY HEADER [%d] ALL PASS\n", i);
		FAC_DEBUG("[FAC] Need to check the end header\n");
#endif

		if (!ret && !strcmp((const char *)p_start, factory_header) && (tar_check_header((char *)p_start) == 0) && (p_start->rtk_tarsize >= 256)
				&& !strcmp(p_start->rtk_signature, "RTK") && (p_start->rtk_tarsize < (CONFIG_FACTORY_SIZE / 2 - sizeof(posix_header)))) {

			pp_seqnum[i] = p_start->rtk_seqnum;
			pp_tarsize[i] = p_start->rtk_tarsize;

			blk_start = (CONFIG_FACTORY_START + p_start->rtk_tarsize + i * CONFIG_FACTORY_SIZE / 2) / EMMC_BLOCK_SIZE;
			n = rtk_eMMC_read(blk_start, EMMC_BLOCK_SIZE * 2, (unsigned int *)buf_contain_a_header);

			p_end = (posix_header*)(((unsigned int) buf_contain_a_header) + (p_start->rtk_tarsize % EMMC_BLOCK_SIZE));

#ifdef ENABLE_FACTORY_DEBUG
			FAC_DEBUG("[FAC] **dump p_start at %x\n", p_start);
			tar_dump_posix_header(p_start);

			FAC_DEBUG("[FAC] **dump p_end at %x\n", p_end);
			tar_dump_posix_header(p_end);
#endif

			if (!memcmp(p_end, p_start, sizeof(posix_header))) {
				FAC_DEBUG("[FAC] pp %d ok\n", i);
				pp_ok |= (1 << i);
			}
		}
	}

	free(p_start);
	free(buf_contain_a_header);

	FAC_DEBUG("[FAC] result: pp_ok = 0x%x\n", pp_ok);
	switch (pp_ok) {
		case 1:
			factory_current_pp = 0;
			break;
		case 2:
			factory_current_pp = 1;
			break;
		case 3:
			if (pp_seqnum[1] > pp_seqnum[0]) {
				if ((pp_seqnum[1] - pp_seqnum[0]) > 0xFFFFFFF0) {
					factory_current_pp = 0;
				}
				else {
					factory_current_pp = 1;
				}
			}
			else {
				factory_current_pp = 0;
			}
			break;
		default:
		case 0:
			p_start = (posix_header *)buffer;
			tar_build_header((char *)p_start, FACTORY_HEADER_FILE_NAME, 0, '5');
			p_start->rtk_signature[0] = 'R';
			p_start->rtk_signature[1] = 'T';
			p_start->rtk_signature[2] = 'K';
			p_start->rtk_signature[3] = 0;
			p_start->rtk_tarsize = sizeof(posix_header);
			p_start->rtk_seqnum = factory_seq_num;
			tar_fill_checksum((char *)p_start);
			tar_check_header((char *)p_start);
			FAC_DEBUG("[FAC] pp:%d seq#:0x%x\n", factory_current_pp, factory_seq_num);
			FAC_PRINTF("[FAC] No factory data in eMMC\n");
			return sizeof(posix_header);

	}

	blk_start = (CONFIG_FACTORY_START + factory_current_pp * CONFIG_FACTORY_SIZE / 2) / EMMC_BLOCK_SIZE;
	n = rtk_eMMC_read(blk_start, pp_tarsize[factory_current_pp], (unsigned int *)buffer);

	factory_seq_num = pp_seqnum[factory_current_pp];

	FAC_PRINTF("Factory: pp:%d, seq#:0x%x, size:0x%x\n",
		factory_current_pp, factory_seq_num, pp_tarsize[factory_current_pp]);

	return pp_tarsize[factory_current_pp];

#else /* !CONFIG_SYS_RTK_EMMC_FLASH */

	FAC_DEBUG("[FAC][WARN] CONFIG_SYS_RTK_EMMC_FLASH is undefined\n");
	return 0;

#endif
}

static int factory_get_from_SPI(uchar *buffer)
{
	int ret = 0;

	ret = factory_check_sanity_from_SPI(buffer, CONFIG_FACTORY_SIZE/2);

	return ret;
}

static int factory_get_from_NAND(uchar *buffer)
{
	int ret = 0;

	ret = factory_check_sanity_from_NAND(buffer, CONFIG_FACTORY_SIZE/2);

	return ret;
}

static int factory_get_from_eMMC(uchar *buffer)
{
	int ret = 0;

	ret = factory_check_sanity_from_eMMC(buffer, CONFIG_FACTORY_SIZE/2);

	return ret;
}

static int factory_save_to_SPI(uchar* buffer, int len)
{
	return 0;
}


static int factory_save_to_NAND(uchar* buffer, int len)
{
#ifdef CONFIG_SYS_RTK_NAND_FLASH
		int dev = nand_curr_device;
		nand_info_t *nand =&nand_info[dev];		//nand_info[0];
		struct nand_chip *this = (struct nand_chip *) nand->priv;
		struct erase_info *instr;
		int erase_ret=0;
		
		unsigned long long to;
		unsigned int factory_block;
		u_char *oob_buf;		//oob size
		unsigned int retlen;
		unsigned int page_num=0;
		
		posix_header *pp_start;
		int next_pp;
#ifdef CONFIG_SYS_FACTORY_PROTECT_ALL
		unsigned short next_seqnum;
#else
		unsigned int next_seqnum;
#endif
		uint blk_start, blk_cnt, n;
		uint total_len;
		loff_t	read_addr;
		
		read_addr = factory_get_start_address();
	
		if (buffer == NULL) {
			return -1;
		}

		oob_buf = (u_char *)malloc(nand->oobsize);
		if(oob_buf == NULL){
			printf("[FAC][ERR] factory_save_to_NAND: allocate oob_buf failed!!!\n");
			return -1;
		}
		
		if (factory_current_pp < 0) {
			next_pp = 0;
			next_seqnum = 0;
		}
		else {
			next_pp = (factory_current_pp + 1) & 0x01;
			next_seqnum = factory_seq_num + 1;
		}
	
		/* fill the first header as RTK header */
		pp_start = (posix_header *)buffer;
		pp_start->rtk_signature[0] = 'R';
		pp_start->rtk_signature[1] = 'T';
		pp_start->rtk_signature[2] = 'K';
		pp_start->rtk_signature[3] = 0;
		pp_start->rtk_tarsize = (unsigned int)len;
#ifdef CONFIG_SYS_FACTORY_PROTECT_ALL
		pp_start->rtk_seqnum = next_seqnum;
		/* rtk_checksum does not involve the start header */
		pp_start->rtk_chksum = factory_rtk_checksum((uchar *)buffer + sizeof(posix_header), len - sizeof(posix_header));
#else
		pp_start->rtk_seqnum = next_seqnum;
#endif
		tar_fill_checksum((char *)pp_start);
	
		/* copy this RTK header to the end of tar file for data check */
		memcpy((void *)(((unsigned int) pp_start) + pp_start->rtk_tarsize), pp_start, sizeof(posix_header));
	
		/* the last block will be reserved to save serial no , and magic no */
		/* can't exceed 2M size - (1 block size)  */
		if (len > (CONFIG_FACTORY_SIZE/2 -nand->erasesize) ) {
			FAC_DEBUG("[FAC][ERR] factory_save_to_NAND: too big\n");
			return 1;
		}	


		//nand->reload_bbt(nand);		//reload bbt
		
		total_len =  ((len + sizeof(posix_header) + nand->oobblock-1) / nand->oobblock) * nand->oobblock; 
		oob_buf[0] = 0x82;	//block tag--> NAND_BLOCK_FACTORY_SETTING
		
		
		
		to = (read_addr + next_pp * (CONFIG_FACTORY_SIZE/2) );

		instr = (struct erase_info *)malloc(sizeof(struct erase_info));
		if(instr == NULL){
			
			printf("[FAC][ERR] factory_save_to_NAND: allocate erase_info failed!!!\n");
			return -1;
			
		}
		memset(instr, 0x00, sizeof(struct erase_info));
		instr->mtd = nand;
		instr->addr = to;
		instr->len = total_len;
		erase_ret = nand->erase(nand, instr);
		
		if (erase_ret != 0) {
			printf("\n[FAC][ERR] factory_save_to_NAND: MTD Erase failure: %d\n",erase_ret);
			return -1;;
		}else{
			free(instr);
		}
		
		n = nand->write_ecc(nand, to, total_len, &retlen, (u_char *)buffer, (u_char *)oob_buf, NULL);
	
		if(retlen == total_len){
			/* Write success */
			//printf("\n[%s][%d]retlen = %d, total_len=%d ", __FUNCTION__,__LINE__,retlen,total_len);
			FAC_PRINTF("\n[FAC] Save to nand  OK\n");

		}else{
			/* Write error */
			//printf("\n[%s][%d]retlen = %llu, total_len=%d ", __FUNCTION__,__LINE__,retlen,total_len);
			FAC_PRINTF("\n[FAC][ERR] Save to nand FAILED\n");
			return 1;
		}
		
		/* remove the RTK header at the end of tar file to prevent side effect */
		memset((void *)(((unsigned int) pp_start) + pp_start->rtk_tarsize), 0, sizeof(posix_header));
	
		factory_current_pp = next_pp;
		factory_seq_num = next_seqnum;
	
#endif

	return 0;
}



static int factory_save_to_NAND_old(uchar* buffer, int len)
{
#ifdef CONFIG_SYS_RTK_NAND_FLASH

	posix_header *pp_start;
	unsigned int next_seqnum = 0;
	uint blk_start;
	uint total_len;
	int rc;
	size_t retlen;
	uchar *write_buf = NULL;
	uint write_len = 0;
	loff_t	write_addr;
	struct erase_info instr;
	struct mtd_info *mtd = &nand_info[nand_curr_device];

	if (buffer == NULL) {
		return -1;
	}

	/* fill the first header as RTK header */
	pp_start = (posix_header *)buffer;
	pp_start->rtk_signature[0] = 'R';
	pp_start->rtk_signature[1] = 'T';
	pp_start->rtk_signature[2] = 'K';
	pp_start->rtk_signature[3] = 0;
	pp_start->rtk_tarsize = (unsigned int)len;
	pp_start->rtk_seqnum = next_seqnum;
	tar_fill_checksum((char *)pp_start);

	/* copy this RTK header to the end of tar file for data check */
	memcpy((void *)(((unsigned int) pp_start) + pp_start->rtk_tarsize), pp_start, sizeof(posix_header));
	total_len = len + sizeof(posix_header);

	/* can't exceed 2M size */
	if (total_len > CONFIG_FACTORY_SIZE ) {
		FAC_DEBUG("[FAC][ERR] factory_save_to_NAND: too big\n");
		return 1;
	}

	// page alignment.
	write_len = ((total_len>>mtd->writesize_shift) + 1) << mtd->writesize_shift;
	write_buf = (uchar *)malloc(write_len);

	if (!write_buf) {
		FAC_PRINTF("[FAC][ERR] allocate memory for page alignment fail.\n");
		return -1;
	}

	memset(write_buf, 0xFF, write_len);
	memcpy(write_buf, buffer, total_len);

	// calculate start address.
	if(mtd->erasesize== 0x40000)
		write_addr = 0x1B00000;	// 31M - 4M
	else if (mtd->erasesize == 0x100000)
		write_addr = 0x3600000;	// 62M - 8M
	else
		write_addr = 0x7400000; // 124M - 8M
		
	//printk("[%s]total_len:%d, write_len:%d\n", __FUNCTION__, total_len, write_len);

	// erase first.
	instr.addr = write_addr;
	instr.len = write_len;
	mtd->erase(mtd, &instr);
	
	//blk_start = CONFIG_FACTORY_START_BLK;

	//write it.
	rc = mtd->write_ecc(mtd, write_addr, write_len, &retlen, write_buf, NULL, NULL);

	free(write_buf);
	write_buf = NULL;
	
	if (rc)
	{
		/* Write error */
		FAC_PRINTF("[FAC][ERR] Save to NAND FAILED\n");
		return 1;
	}
	else
	{
		/* Write success */
		FAC_PRINTF("[FAC] Save to NAND  (blk#:0x%x, buf:0x%08x, len:0x%x)\n",
			blk_start, (uint)buffer, total_len);
	}

	/* remove the RTK header at the end of tar file to prevent side effect */
	memset((void *)(((unsigned int) pp_start) + pp_start->rtk_tarsize), 0, sizeof(posix_header));

#endif	// CONFIG_SYS_RTK_NAND_FLASH

	return 0;
}

static int factory_save_to_eMMC(uchar* buffer, int len)
{
#ifdef CONFIG_SYS_RTK_EMMC_FLASH

	posix_header *pp_start;
	int next_pp;
	unsigned int next_seqnum;
	uint blk_start, blk_cnt, n;
	uint total_len;

 	if (buffer == NULL) {
		return -1;
 	}

	if (factory_current_pp < 0) {
		next_pp = 0;
		next_seqnum = 0;
	}
	else {
		next_pp = (factory_current_pp + 1) & 0x01;
		next_seqnum = factory_seq_num + 1;
	}

	/* fill the first header as RTK header */
	pp_start = (posix_header *)buffer;
	pp_start->rtk_signature[0] = 'R';
	pp_start->rtk_signature[1] = 'T';
	pp_start->rtk_signature[2] = 'K';
	pp_start->rtk_signature[3] = 0;
	pp_start->rtk_tarsize = (unsigned int)len;
	pp_start->rtk_seqnum = next_seqnum;
	tar_fill_checksum((char *)pp_start);

	/* copy this RTK header to the end of tar file for data check */
	memcpy((void *)(((unsigned int) pp_start) + pp_start->rtk_tarsize), pp_start, sizeof(posix_header));

	/* the last block will be reserved to save serial no , and magic no */
	/* can't exceed 2M size - (1 block size)  */
	if (len > (CONFIG_FACTORY_SIZE / 2 - EMMC_BLOCK_SIZE) ) {
		FAC_DEBUG("[FAC][ERR] factory_save_to_eMMC: too big\n");
		return 1;
	}

	total_len = len + sizeof(posix_header);

	blk_start = (CONFIG_FACTORY_START + next_pp * CONFIG_FACTORY_SIZE / 2) / EMMC_BLOCK_SIZE;
	blk_cnt = ALIGN(total_len , EMMC_BLOCK_SIZE) / EMMC_BLOCK_SIZE;
	n = rtk_eMMC_write(blk_start, total_len, (uint *)buffer);
	if (n != blk_cnt)
	{
		/* Write error */
		FAC_PRINTF("[FAC][ERR] Save to eMMC FAILED\n");
		return 1;
	}
	else
	{
		/* Write success */
		FAC_PRINTF("[FAC] Save to eMMC (blk#:0x%x, buf:0x%08x, len:0x%x)\n",
			blk_start, (uint)buffer, total_len);
		FAC_PRINTF("[FAC] Save to eMMC (seq#:0x%x, pp:%d)\n",
			next_seqnum, next_pp);
	}

	/* remove the RTK header at the end of tar file to prevent side effect */
	memset((void *)(((unsigned int) pp_start) + pp_start->rtk_tarsize), 0, sizeof(posix_header));

	factory_current_pp = next_pp;
	factory_seq_num = next_seqnum;

#endif

	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

int factory_dump_info(void)
{

	FAC_PRINTF("****** dump factory info ******\n");
	FAC_PRINTF("boot_flash_type    = ");
	switch(boot_flash_type){
		case BOOT_NOR_SERIAL:
			FAC_PRINTF("NOR\n");
			break;

		case BOOT_NAND:
			FAC_PRINTF("NAND\n");
			break;

		case BOOT_EMMC:
			FAC_PRINTF("MMC\n");
			break;

		default:
			FAC_PRINTF("UNKNOWN\n");
			break;
	}

	FAC_PRINTF("factory_buffer     = 0x%08x\n", (uint)factory_buffer);
	FAC_PRINTF("factory_buffer2    = 0x%08x\n", (uint)factory_buffer2);
	FAC_PRINTF("factory_tarsize    = 0x%08x\n", factory_tarsize);
	FAC_PRINTF("factory_current_pp = 0x%08x\n", factory_current_pp);
	FAC_PRINTF("factory_seq_num    = 0x%08x\n", factory_seq_num);

	return 0;
}

int factory_dump_list(void)
{
	char *dst_addr;
	uint dst_length;

	tar_read_print_info = 1;

	memset(tar_read_print_prefix, 0, sizeof(tar_read_print_prefix));

	strcpy((char *)tar_read_print_prefix, FACTORY_HEADER_FILE_NAME);

	tar_read("DUMMY_NAME_FOR_DUMP", (char *)FACTORY_DATA_ADDR, CONFIG_FACTORY_SIZE/2, &dst_addr, &dst_length);

	tar_read_print_info = 0;

	return 0;
}

int factory_reset(void)
{
	int i = 0;
	posix_header *p_start = NULL;

 	if (factory_buffer == NULL) {
		FAC_PRINTF("[FAC] factory_reset: factory_buffer is NULL\n");
		return -1;
 	}

	/* reset sequence number */
	factory_seq_num = 0;

	/* reset tar size */
	factory_tarsize = sizeof(posix_header);

	memset(factory_buffer, 0, CONFIG_FACTORY_SIZE / 2);

	/* build RTK header */
	p_start = (posix_header *)factory_buffer;
	tar_build_header((char *)p_start, FACTORY_HEADER_FILE_NAME, 0, '5');
	p_start->rtk_signature[0] = 'R';
	p_start->rtk_signature[1] = 'T';
	p_start->rtk_signature[2] = 'K';
	p_start->rtk_signature[3] = 0;
	p_start->rtk_tarsize = sizeof(posix_header);
	p_start->rtk_seqnum = 0;
	tar_fill_checksum((char *)p_start);
	tar_check_header((char *)p_start);

	// save to pp factory data
	for (i = 0;i < 2;i++)
	{
		factory_dirty = 1;

		factory_save();
	}
	return 0;
}

int factory_delete(char *path)
{
 	if (factory_buffer == NULL) {
		FAC_PRINTF("[FAC] factory_delete: factory_buffer is NULL\n");
		return -1;
 	}

	memset(factory_buffer2, 0, CONFIG_FACTORY_SIZE / 2);
	factory_tarsize = tar_add_or_delete((char *)factory_buffer, path, 0, 0, (char *)factory_buffer2, CONFIG_FACTORY_SIZE / 2, 0);
	factory_dirty = 1;

	return 0;
}

int factory_read_by_index(int index, char *buffer, int *length, char *name)
{
 	if (factory_buffer == NULL) {
		FAC_PRINTF("[FAC] factory_read_by_index: factory_buffer is NULL\n");
		return -1;
 	}

	return tar_read_by_index(index, (char *)factory_buffer, buffer, length, name);
}

/*
 * Return Value:
 *    0: success
 *    1: tar read failed
 *   -1: factory buffer error
 */
int factory_read(char *path, char**buffer, int *length)
{
 	if (factory_buffer == NULL) {
		FAC_PRINTF("[FAC] factory_read: factory_buffer is NULL\n");
		return -1;
 	}

	return tar_read(path, (char *)factory_buffer, CONFIG_FACTORY_SIZE/2, buffer, (uint *)length) == 0;
}

int factory_write(char *path, char *buffer, int length)
{
	int length_512 = ((length + 511)/512) * 512;

 	if (factory_buffer == NULL) {
		FAC_PRINTF("[FAC] factory_write: factory_buffer is NULL\n");
		return -1;
 	}

	if (length_512 + factory_tarsize + 512 > CONFIG_FACTORY_SIZE/2) {
		FAC_PRINTF("[FAC] factory_write: too big\n");
		return -1;
	}

	memset(factory_buffer2, 0 , CONFIG_FACTORY_SIZE/2);

	if ((factory_tarsize = tar_add_or_delete((char *)factory_buffer, path, buffer, length, (char *)factory_buffer2, CONFIG_FACTORY_SIZE/2, 1)) == 0)  {
		FAC_PRINTF("[FAC] factory_write: tar_add_or_delete fail\n");
		return -1;
	}
	FAC_DEBUG("factory_tarsize = 0x%x\n", factory_tarsize);

	factory_dirty = 1;

	return 0;
}

int factory_save(void)
{
	int ret = 0;

	FAC_PRINTF("[FAC] factory_save: ");

 	if (factory_buffer == NULL) {
		FAC_PRINTF("FAILED (factory_buffer is NULL)\n");
		return -1;
 	}

	if (factory_dirty && factory_tarsize > 0) {

		switch(boot_flash_type){
			case BOOT_NOR_SERIAL:
				FAC_PRINTF("NOR\n");
				ret = factory_save_to_SPI(factory_buffer, factory_tarsize);
				break;

			case BOOT_NAND:
				FAC_PRINTF("NAND\n");
				ret = factory_save_to_NAND(factory_buffer, factory_tarsize);
				break;

			case BOOT_EMMC:
				FAC_PRINTF("MMC\n");
				ret = factory_save_to_eMMC(factory_buffer, factory_tarsize);
				break;

			default:
				FAC_PRINTF("UNKNOWN\n");
				ret = -1;
				break;
		}
	}
	else {
		FAC_PRINTF("no change\n");
		FAC_DEBUG("[FAC] factory_dirty is %d\n", factory_dirty);
	}

	factory_dirty = 0;

	return 0;
}

int factory_init(void)
{
	int ret = 0;

	factory_buffer = (uchar *)FACTORY_DATA_ADDR;
	factory_buffer2 = (uchar *)FACTORY_DATA_ADDR + CONFIG_FACTORY_SIZE / 2;

	switch(boot_flash_type){
		case BOOT_NOR_SERIAL:
			FAC_PRINTF("NOR\n");
			factory_tarsize = factory_get_from_SPI(factory_buffer);
			break;

		case BOOT_NAND:
			FAC_PRINTF("NAND\n");
			FAC_DEBUG("[NAND] factory_buffer  = 0x%x\n", factory_buffer);
			FAC_DEBUG("[NAND] factory_buffer2 = 0x%x\n", factory_buffer2);
			factory_tarsize = factory_get_from_NAND(factory_buffer);
			FAC_DEBUG("[NAND] factory_tarsize = 0x%x\n", factory_tarsize);
			break;

		case BOOT_EMMC:
			FAC_PRINTF("MMC\n");
			FAC_DEBUG("[FAC] factory_buffer  = 0x%x\n", factory_buffer);
			FAC_DEBUG("[FAC] factory_buffer2 = 0x%x\n", factory_buffer2);
			factory_tarsize = factory_get_from_eMMC(factory_buffer);
			FAC_DEBUG("[FAC] factory_tarsize = 0x%x\n", factory_tarsize);
			break;

		default:
			FAC_PRINTF("UNKNOWN\n");
			ret = -1;
			break;
	}

	return 0;
}

#ifdef ENABLE_FACTORY_CONSOLE_MODE
int do_factory(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	char *buffer;
	unsigned long dst_buffer;//for rtice tool factory read
	int length;
	int rc;

	if (argc < 2) {
		return CMD_RET_USAGE;
	}
	else {
		if (strcmp(argv[1], "save") == 0) {
			factory_save();
		}
		else if (strcmp(argv[1], "reset") == 0) {
			factory_reset();
		}
		else if (strcmp(argv[1], "info") == 0) {
			factory_dump_info();
		}
		else if (strcmp(argv[1], "list") == 0) {
			factory_dump_list();
		}
		else if (strcmp(argv[1], "delete") == 0) {
			factory_delete(argv[2]);
		}
		else if (strcmp(argv[1], "read") == 0) {
			rc = factory_read(argv[2], &buffer, &length);

			if (rc)
				FAC_PRINTF("%s: file not found\n", argv[2]);
			else
				FAC_PRINTF("%s: %d bytes at 0x%08x\n", argv[2], length, (uint)buffer);

			if (argc == 4) {
				dst_buffer = simple_strtoul(argv[3], NULL, 16);
				memcpy((void *)dst_buffer, (void *)buffer, length);
				FAC_PRINTF("src[0x%08x] dst[0x%08x]\n", (uint)buffer, (uint)dst_buffer);
			}
		}
		else if (strcmp(argv[1], "write") == 0) {

			buffer = (char *)simple_strtoul(argv[3], NULL, 16);
			length = (int)simple_strtoul(argv[4], NULL, 16);

			factory_write(argv[2], buffer, length);
		}
		else {
			return CMD_RET_USAGE;
		}
	}

	return 0;
}


U_BOOT_CMD(
	factory,	5,	1,	do_factory,
	"FACTORY sub system",
	"read path\n"
	"factory write path addr length\n"
	"factory delete path\n"
	"factory save\n"
	"factory reset\n"
	"factory info\n"
	"factory list"
);
#endif

