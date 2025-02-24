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
#include <rbus/sb2_reg.h>
#include <rbus/md_reg.h>
#include <asm/arch/system.h>
#include <asm/arch/extern_param.h>
#include <asm/arch/fw_info.h>
#include <fdt.h>
#include <rtkspi.h>
#include "../examples/flash_writer_u/include/flash/flash_spi_list.h"


unsigned int spi_flash_id_idx;
s_device_type * pspi_flash_type;
unsigned int spi_flash_min_erase_size;
unsigned int spi_flash_max_erase_size;

static void spi_switch_read_mode(void)
{
    sync();
    rtd_outl(SB2_SFC_OPCODE, 0x00000003); //switch flash to read mode
    rtd_outl(SB2_SFC_CTL, 0x00000018); //command cycle
    sync();
}

static void rtkspi_hexdump( const char * str, unsigned int start_address, unsigned int length )
{
    unsigned int i, j, rows, count;
    volatile unsigned char tmp;
    printf("======================================================\n");
    printf("%s(base=0x%08x)\n", str, start_address);
    count = 0;
    rows = (length+((1<<4)-1)) >> 4;
    for( i = 0; ( i < rows ) && (count < length); i++ ) {
        printf("%03x :", i<<4 );
        for( j = 0; ( j < 16 ) && (count < length); j++ ) {
            tmp = rtd_inb(start_address);
            printf(" %02x",  tmp );
            count++;
            start_address++;
        }
        printf("\n");
    }
}

static unsigned int rtkspi_swap_endian(unsigned int input)
{
    unsigned int output;
    output = 0;
    output |= (input & 0xFF000000)>>24;
    output |= (input & 0x00FF0000)>>8;
    output |= (input & 0x0000FF00)<<8;
    output |= (input & 0x000000FF)<<24;
    return output;
}

static unsigned int rtkspi_get_min_erase_size( s_device_type * _pspi_flash_type )
{
	unsigned int _min_erase_blk_size;

	_min_erase_blk_size = 0;

	if( _pspi_flash_type->sec_256k_en == 1 )
	{
		_min_erase_blk_size = (256UL<<10);
	}
	if( _pspi_flash_type->sec_64k_en == 1 )
	{
		_min_erase_blk_size = (64UL<<10);
	}
	if( _pspi_flash_type->sec_32k_en == 1 )
	{
		_min_erase_blk_size = (32UL<<10);
	}
	if( _pspi_flash_type->sec_4k_en == 1 )
	{
		_min_erase_blk_size = (4UL<<10);
	}

	if( _min_erase_blk_size ) {
		return _min_erase_blk_size;
	}

	return 0; // flash_wp or not support erase
}

static unsigned int rtkspi_get_max_erase_size( s_device_type * _pspi_flash_type )
{
	unsigned int _max_erase_blk_size;

	_max_erase_blk_size = 0;

	if( _pspi_flash_type->sec_256k_en == 1 )
	{
		_max_erase_blk_size = (256UL<<10);
	}
	else if( _pspi_flash_type->sec_64k_en == 1 )
	{
		_max_erase_blk_size = (64UL<<10);
	}
	else if( _pspi_flash_type->sec_32k_en == 1 )
	{
		_max_erase_blk_size = (32UL<<10);
	}
	else if( _pspi_flash_type->sec_4k_en == 1 )
	{
		_max_erase_blk_size = (4UL<<10);
	}

	if( _max_erase_blk_size ) {
		return _max_erase_blk_size;
	}

	return 0; // flash_wp or not support erase
}

int rtkspi_identify( void )
{
    unsigned int id;
    unsigned int idx;
    unsigned int temp_id;

    // init global variable
    spi_flash_id_idx = 0;
    pspi_flash_type = NULL;
    spi_flash_min_erase_size = 0;
    spi_flash_max_erase_size = 0;

    // configure spi flash controller register
    rtd_outl(SB2_SFC_POS_LATCH,0x00000001);   //set serial flash controller latch data at rising edge

    //remove this, due to we already set this register at hw-setting
    //rtd_outl(0xb801a808,0x0101000f);   //lowering frequency, setup freq divided no

    rtd_outl(SB2_SFC_CE,0x00071307);   //setup control edge

    // read Manufacture & device ID
    rtd_outl(SB2_SFC_OPCODE,0x0000009f);
    rtd_outl(SB2_SFC_CTL,0x00000010);
    sync();

    temp_id = rtd_inl(SPI_RBUS_BASE_ADDR);
    id = rtkspi_swap_endian(temp_id);
    id >>= 8;

    printf("nor flash id [0x%08x]\n", id);

    // find the match flash brand
    for (idx = 0; idx < DEV_SIZE_S; idx++)
    {
        if ( s_device[idx].id == id )
        {
            //special case: the same id have two mode, check ext-id
            if (id == SPANSION_128Mbit)
            {
                /* read extended device ID */
                rtd_outl(SB2_SFC_OPCODE,0x0000009f);
                rtd_outl(SB2_SFC_CTL,0x00000013);
                sync();

                temp_id = rtd_inl(SPI_RBUS_BASE_ADDR);
                id = rtkspi_swap_endian(temp_id);
                id >>= 16;
                printf("\textension id [0x%x]\n", id);
                continue;
            }

            pspi_flash_type = &s_device[idx];
            spi_flash_id_idx = (idx | SPI_FLASH_ID_FOUND);
            spi_flash_min_erase_size = rtkspi_get_min_erase_size(pspi_flash_type);
            spi_flash_max_erase_size = rtkspi_get_max_erase_size(pspi_flash_type);

            // show flash info
            printf("sector 256k en: %d\n", pspi_flash_type->sec_256k_en);
            printf("sector  64k en: %d\n", pspi_flash_type->sec_64k_en);
            printf("sector  32k en: %d\n", pspi_flash_type->sec_32k_en);
            printf("sector   4k en: %d\n", pspi_flash_type->sec_4k_en);
            printf("page_program  : %d\n", pspi_flash_type->page_program);
            printf("max capacity  : 0x%08x\n", pspi_flash_type->size);
            printf("spi type name : %s\n", pspi_flash_type->string);

            return idx;
        }
    }

    printf("ID not match try CMD 90h...\n");

    //device not found, down freq and try again
    if (idx == DEV_SIZE_S)
    {
        rtd_outl(SB2_SFC_OPCODE,0x00000090);  //read id
        rtd_outl(SB2_SFC_CTL,0x00000010);  //issue command
        sync();
        id = rtd_inl(SPI_RBUS_BASE_ADDR);
        id >>= 16;

        for (idx = 0; idx < DEV_SIZE_S; idx++)
        {
            if ( s_device[idx].id == id )
            {
                //special case: the same id have two mode, check ext-id
                if (id == SPANSION_128Mbit)
                {
                    /* read extended device ID */
                    rtd_outl(SB2_SFC_OPCODE,0x00000090);
                    rtd_outl(SB2_SFC_CTL,0x0000001b);
                    sync();

                    temp_id = rtd_inl(SPI_RBUS_BASE_ADDR);
                    id = rtkspi_swap_endian(temp_id);
                    id >>= 16;
                    continue;
                }

                pspi_flash_type = &s_device[idx];
                spi_flash_id_idx = (idx | SPI_FLASH_ID_FOUND);
                spi_flash_min_erase_size = rtkspi_get_min_erase_size(pspi_flash_type);

                // show flash info
                printf("sector 256k en: %d\n", pspi_flash_type->sec_256k_en);
                printf("sector  64k en: %d\n", pspi_flash_type->sec_64k_en);
                printf("sector  32k en: %d\n", pspi_flash_type->sec_32k_en);
                printf("sector   4k en: %d\n", pspi_flash_type->sec_4k_en);
                printf("page_program  : %d\n", pspi_flash_type->page_program);
                printf("max capacity  : 0x%08x\n", pspi_flash_type->size);
                printf("spi type name : %s\n", pspi_flash_type->string);

                return idx;
            }
        }
    }

    printf("!!!! No ID match !!!!\n");

    return -1;
}

void rtkspi_init_regs( void )
{
    unsigned char tmp;

    // need to init again ( ROM code had set up this ? )
    // configure serial flash controller
    rtd_outl(SB2_SFC_CE,0x00071307);   // setup control edge
	mdelay(100);//printf("****** %s %d\n", __FUNCTION__, __LINE__);
    rtd_outl(SB2_SFC_WP,0x00000000);    // disable hardware potection
    // enable write status register
    rtd_outl(SB2_SFC_OPCODE,0x00000050);
    rtd_outl(SB2_SFC_CTL,0x00000000);
    sync();

    tmp = rtd_inb(SPI_RBUS_BASE_ADDR);
    rtd_outb(SPI_RBUS_BASE_ADDR, 0x0);
    // write status register , no memory protection
    rtd_outl(SB2_SFC_OPCODE,0x00000001);
    rtd_outl(SB2_SFC_CTL,0x00000010);
    rtd_outb(SPI_RBUS_BASE_ADDR, 0x0);
    sync();
}

void rtkspi_init( void )
{
    rtkspi_identify();
    rtkspi_init_regs();
    spi_switch_read_mode();
}

void rtkspi_read32( unsigned int target_address, unsigned int source_address, unsigned int byte_length )
{
    volatile unsigned int * piTarge;
    unsigned int word_length;

	//printf("*** %s %d, tar 0x%08x, src 0x%08x, len 0x%08x\n", __FUNCTION__, __LINE__, target_address, source_address, byte_length);

    spi_switch_read_mode();

    piTarge = (volatile unsigned int *)target_address;
    word_length = (byte_length)>>2;

    // flush data
    flush_cache(target_address, byte_length );

    while( word_length-- ) {
        *piTarge++ = rtd_inl(source_address);
        source_address += 4;
    }
}

void rtkspi_read32_progress( unsigned int target_address, unsigned int source_address, unsigned int byte_length )
{
    volatile unsigned int * piTarge;
    unsigned int word_length;

	//printf("*** %s %d, tar 0x%08x, src 0x%08x, len 0x%08x\n", __FUNCTION__, __LINE__, target_address, source_address, byte_length);

    spi_switch_read_mode();

    piTarge = (volatile unsigned int *)target_address;
    word_length = (byte_length+3)>>2;

    // flush data
    flush_cache(target_address, byte_length );

#if 0
    while( word_length-- ) {
        *piTarge++ = rtd_inl(source_address);
        if( !(word_length & 0x0001FFFF) ) {
        	printf(".");
        }
        source_address += 4;
    }
#else
	// MD mode
	rtd_outl(MD_FDMA_CTRL1, 0xA);								// clear go bit
	rtd_outl(MD_FDMA_DDR_SADDR, target_address);
	rtd_outl(MD_FDMA_FL_SADDR, source_address);
	rtd_outl(MD_FDMA_CTRL2, (0x2C000000 | (word_length<<2)));	
	rtd_outl(MD_FDMA_CTRL1, 0x3);								// enable go bit
	while( ( rtd_inl(MD_FDMA_CTRL1) & 1 ) ) {
		mdelay(100);
		printf(".");
	}
#endif
    if(byte_length) {
    	printf("\n");
    }
}

void rtkspi_read32_md( unsigned int target_address, unsigned int source_address, unsigned int byte_length )
{
    volatile unsigned int * piTarge;
    unsigned int word_length;

	printf("*** %s %d, tar 0x%08x, src 0x%08x, len 0x%08x\n", __FUNCTION__, __LINE__, target_address, source_address, byte_length);

    spi_switch_read_mode();

    piTarge = (volatile unsigned int *)target_address;
    word_length = (byte_length+3)>>2;

    // flush data
    flush_cache(target_address, byte_length );

    // MD mode
	rtd_outl(MD_FDMA_CTRL1, 0xA);								// clear go bit
	rtd_outl(MD_FDMA_DDR_SADDR, target_address);
	rtd_outl(MD_FDMA_FL_SADDR, source_address);
	rtd_outl(MD_FDMA_CTRL2, (0x2C000000 | (word_length<<2)));	
	rtd_outl(MD_FDMA_CTRL1, 0x3);								// enable go bit
	while( ( rtd_inl(MD_FDMA_CTRL1) & 1 ) ) {
		;
	}
}

void rtkspi_write8( unsigned int target_address, unsigned int source_address, unsigned int byte_length )
{
    volatile unsigned char * pcSourece;
    unsigned int dot_print;

    pcSourece = (volatile unsigned char *)source_address;
    dot_print = 0;

    // flush data
    flush_cache(target_address, byte_length );

    //add by angus
    rtd_outl(SB2_SFC_EN_WR,     0x00000106);
    rtd_outl(SB2_SFC_WAIT_WR,   0x00000105);
    rtd_outl(SB2_SFC_CE,        0x00071307);

    //issue write command
    rtd_outl(SB2_SFC_OPCODE,    0x00000002);
    rtd_outl(SB2_SFC_CTL,       0x00000018);
    sync();

    mdelay(2); // must do this or rbus will be hanged

    while(byte_length--)
    {
        if( !(byte_length & (1024UL-1)) ) {
            printf(".");
            dot_print = 1;
        }
        rtd_outb(target_address++ , *pcSourece++);
    }

    if( dot_print ) {
        printf("\n");
    }

    spi_switch_read_mode();

    rtd_inb(SPI_RBUS_BASE_ADDR);    // workaground for last byte not be written
}

int rtkspi_erase( unsigned int spi_offset_address, unsigned int byte_length )
{
	volatile unsigned char tmp_sts;
    unsigned int start_address;
    unsigned int end_address;
    unsigned int curr_address;
    unsigned int tmp_cnt;
    unsigned int erase_size;

    if( !spi_flash_min_erase_size ) {
    	printf("*** unknown SPI flash erase size, DO NOTHING ***\n");
    	return;
    }

    start_address = spi_offset_address;
    end_address   = spi_offset_address + byte_length;

    //printf("*** start addr : 0x%08x\n", start_address);
    //printf("*** end addr : 0x%08x\n", end_address);

    // set aligment
    start_address &= ~(spi_flash_min_erase_size-1);

    end_address   += (spi_flash_min_erase_size-1);
    end_address   &= ~(spi_flash_min_erase_size-1);

    printf("min erase size : 0x%08x\n", spi_flash_min_erase_size);
    printf("*** adjust start addr : 0x%08x\n", start_address);
    printf("*** adjust end addr : 0x%08x\n", end_address);

    //disable auto-prog
	rtd_outl(SB2_SFC_EN_WR,    0x00000006);
	rtd_outl(SB2_SFC_WAIT_WR,    0x00000005);
    sync();

	curr_address = start_address;

	while( curr_address < end_address )
    {
        // addr align max erase size
        if (((curr_address & (spi_flash_max_erase_size - 1)) == 0)  &&  
            ((curr_address + spi_flash_max_erase_size) <= end_address)) {
            erase_size = spi_flash_max_erase_size;
        }
        else {
            erase_size = spi_flash_min_erase_size;
        }
    
        printf("e");

        // write enable
        rtd_outl(SB2_SFC_OPCODE,0x00000006);
        mdelay(1); // work around for GD25Q80C_08Mbit
        rtd_outl(SB2_SFC_CTL,0x00000000);
        sync();

        tmp_sts = rtd_inb(curr_address);

		do {
			if( erase_size == (256UL<<10) )
            {
                rtd_outl(SB2_SFC_OPCODE,0x000000d8);
                rtd_outl(SB2_SFC_CTL,0x00000008);
                sync();
                tmp_sts = rtd_inb(curr_address);
                break;
            }
			else if( erase_size == (64UL<<10) )
            {
                rtd_outl(SB2_SFC_OPCODE,0x000000d8);
            	rtd_outl(SB2_SFC_CTL,0x00000008);
                sync();
            	tmp_sts = rtd_inb(curr_address);
                break;
            }
			else if( erase_size == (32UL<<10) )
            {
            	rtd_outl(SB2_SFC_OPCODE,0x00000052);
                rtd_outl(SB2_SFC_CTL,0x00000008);
                sync();
                tmp_sts = rtd_inb(curr_address);
                break;
            }
			else if( erase_size == (4UL<<10) )
            {
            	if (pspi_flash_type->id==PMC_4Mbit) {
                    rtd_outl(SB2_SFC_OPCODE,0x000000d7);
                }
                else {
                    rtd_outl(SB2_SFC_OPCODE,0x00000020);
                }
                rtd_outl(SB2_SFC_CTL,0x00000008);
                sync();
                tmp_sts = rtd_inb(curr_address);
                break;
            }

		    printf("*** erase size(0x%08x) not support\n", erase_size);
			//enable auto-prog
			rtd_outl(SB2_SFC_EN_WR,    0x00000106);
        	rtd_outl(SB2_SFC_WAIT_WR,    0x00000105);
            sync();
            return -1;
		}
		while(0);

        // read status registers until write operation completed
        tmp_cnt = 0;
        do
        {
            if( !(tmp_cnt & 0x1FF) ) {
            	tmp_cnt = 0;
            	printf("c");
            	mdelay(100);
            }
            tmp_cnt++;
            rtd_outl(SB2_SFC_OPCODE,0x00000005);
            rtd_outl(SB2_SFC_CTL,0x00000010);
            sync();
            tmp_sts = rtd_inb(curr_address);
        } while(tmp_sts&0x1);

        curr_address += erase_size;
    }

    printf("\n");

	//enable auto-prog
	rtd_outl(SB2_SFC_EN_WR,    0x00000106);
    rtd_outl(SB2_SFC_WAIT_WR,    0x00000105);
    sync();

    spi_switch_read_mode();

    return 0;
}

/*
 *   Below definition are defined in config file
 *   #define CONFIG_DTS_BASE                             0x000F0000
 *   #define CONFIG_DTS_SIZE                             0x00010000 *
 *
 */
#ifdef CONFIG_DTB_IN_SPI_NOR
unsigned int rtkspi_load_DT_for_kernel( unsigned int _target_fdt_address )
{
	unsigned int _iSPI_base_addr;
	unsigned char _tmp_str[16];
	struct fdt_header * _pfdt;

	_iSPI_base_addr = SPI_RBUS_BASE_ADDR + CONFIG_DTS_BASE;

	if( _target_fdt_address == 0 ) {
		_target_fdt_address = CONFIG_FDT_LOADADDR;
	}

	memset(_tmp_str, 0, sizeof(_tmp_str));
	sprintf(_tmp_str, "%x", _target_fdt_address);
	setenv("fdt_loadaddr", _tmp_str);

	rtkspi_read32( _target_fdt_address, _iSPI_base_addr, CONFIG_DTS_SIZE>>1);

	_pfdt = (struct fdt_header *)_target_fdt_address;

	if( _pfdt->magic == rtkspi_swap_endian(FDT_MAGIC) ) {
		return rtkspi_swap_endian(_pfdt->totalsize);
	}
	else {
		printf("\n[Warning] It seemd no DTS(kernel) data in SPI flash\n\n");
	}

	return 0;
}

unsigned int rtkspi_load_DT_for_rescure_android( unsigned int _target_fdt_address )
{
	unsigned int _iSPI_base_addr;
	unsigned char _tmp_str[16];
	struct fdt_header * _pfdt;

	_iSPI_base_addr = SPI_RBUS_BASE_ADDR + CONFIG_DTS_BASE + (CONFIG_DTS_SIZE>>1);

	if( _target_fdt_address == 0 ) {
		_target_fdt_address = CONFIG_FDT_LOADADDR;
	}

	memset(_tmp_str, 0, sizeof(_tmp_str));
	sprintf(_tmp_str, "%x", _target_fdt_address);
	setenv("fdt_loadaddr", _tmp_str);

	rtkspi_read32( _target_fdt_address, _iSPI_base_addr, CONFIG_DTS_SIZE>>1);

	_pfdt = (struct fdt_header *)_target_fdt_address;

	if( _pfdt->magic == rtkspi_swap_endian(FDT_MAGIC) ) {
		return rtkspi_swap_endian(_pfdt->totalsize);
	}
	else {
		printf("\n[Warning] It seemd no DTS(rescure) data in SPI flash\n\n");
	}

	return 0;
}
#endif

void rtkspi_fwtable_create( void )
{
#if 0
	unsigned int _iSPI_base_addr;
    unsigned int _iDataByteSize;
    unsigned int 	     _ifw_desc_table_base;
	fw_desc_table_v1_t   *_p_fw_desc_table_v1;
	part_desc_entry_v1_t *_p_part_entry;
	fw_desc_entry_v1_t   *_p_fw_entry;	

	// erase block 0x0010_0000 +64KB
	_iSPI_base_addr = SPI_RBUS_BASE_ADDR + 0x00100000;
	_iDataByteSize  = 64 << 10;
	rtkspi_erase( _iSPI_base_addr, _iDataByteSize );

	// initial data
	_ifw_desc_table_base = FIRMWARE_DESCRIPTION_TABLE_ADDR; // 0x0640_0000
	memset( (void*)_ifw_desc_table_base, 0, 512);
	
	// init main descriptor
	//printf("****** %s %d, %s , len %d\n", __FILE__, __LINE__, FIRMWARE_DESCRIPTION_TABLE_SIGNATURE, sizeof(FIRMWARE_DESCRIPTION_TABLE_SIGNATURE));
	//printf("****** %s %d, fw_desc_table_v1_t size %d\n", __FILE__, __LINE__, sizeof(fw_desc_table_v1_t));
	//printf("****** %s %d, part_desc_entry_v1_t size %d\n", __FILE__, __LINE__, sizeof(part_desc_entry_v1_t));
	//printf("****** %s %d, fw_desc_entry_v1_t size %d\n", __FILE__, __LINE__, sizeof(fw_desc_entry_v1_t));
	_p_fw_desc_table_v1 = (fw_desc_table_v1_t*)_ifw_desc_table_base;
	memcpy( _p_fw_desc_table_v1->signature, FIRMWARE_DESCRIPTION_TABLE_SIGNATURE, 8);
	_p_fw_desc_table_v1->checksum      = 0xDEADBEEF;
	_p_fw_desc_table_v1->version       = 0x01;
	_p_fw_desc_table_v1->paddings      = 512;
	_p_fw_desc_table_v1->part_list_len = sizeof(part_desc_entry_v1_t) * 3; // 2 dummy
	_p_fw_desc_table_v1->fw_list_len   = sizeof(fw_desc_entry_v1_t) * 5; // kernel x 1, DTB x 2, rootfs x 1, bluecore x 1
	
	// init partition descriptor
	// reserved for advanced featre
	_p_part_entry = (part_desc_entry_v1_t*) (_ifw_desc_table_base+sizeof(fw_desc_table_v1_t));
	_p_part_entry[0].type = FS_TYPE_UNKOWN;
	_p_part_entry[1].type = FS_TYPE_UNKOWN;
	_p_part_entry[2].type = FS_TYPE_UNKOWN;
	
	// init fw descriptor
	_p_fw_entry = (fw_desc_entry_v1_t*) (_ifw_desc_table_base+sizeof(fw_desc_table_v1_t)+_p_fw_desc_table_v1->part_list_len);
	
	_p_fw_entry[0].type        = FW_TYPE_KERNEL; // 2
	_p_fw_entry[0].version     = 0;
	_p_fw_entry[0].target_addr = CONFIG_KERNEL_LOADADDR;
	_p_fw_entry[0].offset      = CONFIG_KERNEL_BASE;
	_p_fw_entry[0].length      = 4317520;//4056528;
	_p_fw_entry[0].paddings    = (_p_fw_entry[0].length+32768-1) & ~(32768UL-1);
	_p_fw_entry[0].checksum    = 0xDEADBEEF;

	_p_fw_entry[1].type        = FW_TYPE_RESCUE_DT; // 3
	_p_fw_entry[1].version     = 0;
	_p_fw_entry[1].target_addr = CONFIG_FDT_LOADADDR;
	_p_fw_entry[1].offset      = CONFIG_DTB_BASE + (CONFIG_DTB_SIZE>>1);
	_p_fw_entry[1].length      = 26065;
	_p_fw_entry[1].paddings    = (_p_fw_entry[1].length+32768-1) & ~(32768UL-1);
	_p_fw_entry[1].checksum    = 0xDEADBEEF;
	
	_p_fw_entry[2].type        = FW_TYPE_KERNEL_DT; // 4
	_p_fw_entry[2].version     = 0;
	_p_fw_entry[2].target_addr = CONFIG_FDT_LOADADDR;
	_p_fw_entry[2].offset      = CONFIG_DTB_BASE;
	_p_fw_entry[2].length      = 23731;
	_p_fw_entry[2].paddings    = (_p_fw_entry[2].length+32768-1) & ~(32768UL-1);
	_p_fw_entry[2].checksum    = 0xDEADBEEF;
	
	_p_fw_entry[3].type        = FW_TYPE_RESCUE_ROOTFS; // 5
	_p_fw_entry[3].version     = 0;
	_p_fw_entry[3].target_addr = CONFIG_ROOTFS_LOADADDR;
	_p_fw_entry[3].offset      = 0;
	_p_fw_entry[3].length      = 0;
	_p_fw_entry[3].paddings    = 0;
	_p_fw_entry[3].checksum    = 0xDEADBEEF;

	_p_fw_entry[4].type        = FW_TYPE_AUDIO; // 7
	_p_fw_entry[4].version     = 0;
	_p_fw_entry[4].target_addr = MIPS_AUDIO_FW_ENTRY_ADDR;
	_p_fw_entry[4].offset      = CONFIG_AFW_BASE;
	_p_fw_entry[4].length      = 1009936;
	_p_fw_entry[4].paddings    = (_p_fw_entry[4].length+32768-1) & ~(32768UL-1);
	_p_fw_entry[4].checksum    = 0xDEADBEEF;

	// update checksum of main descriptor
	_p_fw_desc_table_v1->checksum = get_checksum((uchar*)_ifw_desc_table_base +
												 offsetof(fw_desc_table_v1_t, version),
												 sizeof(fw_desc_table_v1_t) -
												 offsetof(fw_desc_table_v1_t, version) +
												 _p_fw_desc_table_v1->part_list_len +
												 _p_fw_desc_table_v1->fw_list_len);
	
	// dump memory
	rtk_hexdump("fw table : ", (void*)_ifw_desc_table_base, 512);

	// write fwtable
	rtkspi_write8( _iSPI_base_addr, _ifw_desc_table_base, 512 );
#endif	
}

void rtkspi_fwtable_parser( void )
{
#if 0
	unsigned int _iSPI_base_addr;
    unsigned int _iDataByteSize;
    unsigned int _ifw_desc_table_base;
	//fw_desc_table_v1_t   *_p_fw_desc_table_v1;
	//part_desc_entry_v1_t *_p_part_entry;
	//fw_desc_entry_v1_t   *_p_fw_entry;	

	// read
	_iSPI_base_addr = SPI_RBUS_BASE_ADDR + 0x00100000;
	_iDataByteSize  = 512;
	_ifw_desc_table_base = FIRMWARE_DESCRIPTION_TABLE_ADDR; // 0x0640_0000
	rtkspi_read32( _ifw_desc_table_base, _iSPI_base_addr, _iDataByteSize );
	rtk_hexdump("fw table : ", (void*)_ifw_desc_table_base, 512);
#endif
}

int do_rtkspi(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
    int cmd;
    unsigned int _iSPI_base_addr;
    unsigned int _iDDR_base_addr;
    unsigned int _iDataByteSize;

    cmd = -1;

    // parse command
    if( argc >= 2 ) {
        if( strncmp( argv[1], "init", 4 ) == 0 && argc == 2 ) {
            cmd = 0;
        }
        if( strncmp( argv[1], "read", 4 ) == 0 && argc == 5 ) {
            cmd = 1;
        }
        if( strncmp( argv[1], "write", 5 ) == 0 && argc == 5 ) {
            cmd = 2;
        }
        if( strncmp( argv[1], "erase", 5 ) == 0 && argc == 4 ) {
            cmd = 3;
        }
        if( strncmp( argv[1], "load", 4 ) == 0 && argc >= 4 ) {
        	if( strncmp( argv[2], "dtb", 3 ) == 0 ) {
        		if( strncmp( argv[3], "kernel", 6 ) == 0 ) {
        			cmd = 4;
        		}
        		if( strncmp( argv[3], "rescure", 7 ) == 0 ) {
        			cmd = 5;
        		}
        	}
        }
        if( strncmp( argv[1], "fwtable", 7 ) == 0 && argc == 3 ) {
            if( strncmp( argv[2], "create", 6 ) == 0 ) {
            	cmd = 6;
        	}
        	if( strncmp( argv[2], "parser", 6 ) == 0 ) {
            	cmd = 7;
        	}
        }
        if( strncmp( argv[1], "debug", 5 ) == 0 ) {
            rtkspi_read32_md( 0x03000000, 0xb8250000, 0x0041e150 );
            return 0;
        }
    }

    if( cmd < 0 ) {
        printf("Error: command %s error\n", argv[1]);
        return -1;
    }

    // parse SPIflash info

    //
    do {
        _iSPI_base_addr = 0;
        _iDDR_base_addr = 0;
        _iDataByteSize  = 0;

        if( cmd == 0 ) {
            break;
        }
        else if( cmd == 1 || cmd == 2 ) { // read/write
            _iSPI_base_addr = simple_strtoul(argv[2], NULL, 16);
            _iDDR_base_addr = simple_strtoul(argv[3], NULL, 16);
            _iDataByteSize = simple_strtoul(argv[4], NULL, 16);

			if( _iDDR_base_addr < 0x01400000 ) {
            	printf("Error: the target DDR address must be larger than 0x01400000\n");
            	return -1;
        	}
        }
        else if( cmd == 3 ) { // erase
            _iSPI_base_addr = simple_strtoul(argv[2], NULL, 16);
            _iDataByteSize = simple_strtoul(argv[3], NULL, 16);
        }
        else if( cmd == 4 || cmd == 5 ) {
            if( argc > 4 ) {
            	_iDDR_base_addr = simple_strtoul(argv[4], NULL, 16);
            }
            break;
        }
        else if( cmd == 6 || cmd == 7 ) { // create/parser fwtable
            break;
        }

        // sanity check for cmd 1/2/3
        if( _iDataByteSize == 0 ) {
            printf("Warning: please input data size \n");
            return -1;
        }

        if( _iDataByteSize > 0x00800000 ) {
            printf("Error: no support SPI size larger than 8MB\n");
            return -1;
        }

        if( _iDataByteSize & 0x3 ) {
            printf("Error: data size is not 4-byte alignment\n");
            return -1;
        }
#if 0        
        if( cmd == 2 || cmd == 3 ) {
        	if( _iSPI_base_addr < 0x00100000) {
				printf("Warning! input address is less than 0x00100000!\n");
				return 0;
	        }
	    }
#endif
        _iSPI_base_addr += SPI_RBUS_BASE_ADDR;
#if 1
        printf("\n");
        //printf("SPI start addr(offset)= 0x%08x\n",_iSPI_base_addr);
        printf("SPI start addr(remap) = 0x%08x\n",_iSPI_base_addr);
        if( cmd == 1 ) {
            printf("DDR start addr        = 0x%08x\n",_iDDR_base_addr);
            printf("reading byte size     = 0x%08x\n",_iDataByteSize);
        }
        else if( cmd == 2 ) {
            printf("DDR start addr        = 0x%08x\n",_iDDR_base_addr);
            printf("writing byte size     = 0x%08x\n",_iDataByteSize);
        }
        else if( cmd == 3 ) {
            // to fit available erase block size
            printf("erasing byte size     = 0x%08x\n",_iDataByteSize);
        }
        else if( cmd == 4 || cmd == 5 ) {
            printf("DDR start addr        = 0x%08x\n",_iDDR_base_addr);
            printf("reading byte size     = 0x%08x\n",_iDataByteSize);
        }
#endif
    }
    while(0);

    do {
        if( cmd == 0 ) {
            rtkspi_init();
        }
        if( cmd == 1 ) {
            rtkspi_read32( _iDDR_base_addr, _iSPI_base_addr, _iDataByteSize );
        }
        if( cmd == 2 ) {
            rtkspi_write8( _iSPI_base_addr, _iDDR_base_addr, _iDataByteSize );
        }
        if( cmd == 3 ) {
            rtkspi_erase( _iSPI_base_addr, _iDataByteSize );
        }
#ifdef CONFIG_DTB_IN_SPI_NOR
        if( cmd == 4 ) {
            rtkspi_load_DT_for_kernel(_iDDR_base_addr);
        }
        if( cmd == 5 ) {
            rtkspi_load_DT_for_rescure_android(_iDDR_base_addr);
        }
#endif
        if( cmd == 6 ) {
            rtkspi_fwtable_create();
        }
        if( cmd == 7 ) {
			rtkspi_fwtable_parser();
        }
    }
    while(0);

    return 0;
}

U_BOOT_CMD(
    rtkspi, 5, 0,   do_rtkspi,
    "spi flash utility",
    "\n(1) rtkspi read spi_start_address ddr_start_address data_size\n"
    "(2) rtkspi write spi_start_address ddr_start_address data_size\n"
    "(3) rtkspi erase spi_start_address erase_size\n"
    "(4) rtkspi load dtb kernel\n"
    "(5) rtkspi load dtb rescure\n"
    "(6) rtkspi fwtable create\n"
    "(7) rtkspi fwtable parser\n"
    "*** all arguments in byte unit ***************\n"
    "rtkspi init\n"
    "rtkspi read 0x00000000 0x01500000 0x00100000\n"
    "rtkspi write 0x00000000 0x01500000 0x00100000\n"
    "rtkspi erase 0x00000000 0x00100000\n"
    "rtkspi load dtb kernel [DDR_addr]\n"
    "rtkspi load dtb rescure [DDR_addr]\n"
    "rtkspi fwtable create\n"
    "rtkspi fwtable parser\n"
    "      - SPI start address\n"
    "      - DDR start address ( suggest large than 0x01500000 )\n"
    "      - data bytes ( should 4-byte alignment )\n"
    "      - [DDDR_addr]optional address\n"
);
