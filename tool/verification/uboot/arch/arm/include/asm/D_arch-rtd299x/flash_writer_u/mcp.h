/************************************************************************
 *
 *  mcp.h
 *
 *  Public header file for CP module
 *
 ************************************************************************/

#ifndef __MCP_H__
#define __MCP_H__

//#include <common.h>
//#include <exports.h>
//#include <linux/types.h>
//#include "sysdefs.h"
#include <asm/arch/system.h>

/************************************************************************
 *  Memory usage
 ************************************************************************/
#define SECURE_IMAGE2HASH_BUF		(UBOOT_SECURE_MCP_MEMORY_ADDR)
#define SECURE_SIGN2HASH_BUF		(UBOOT_SECURE_MCP_MEMORY_ADDR + 0x200)
#define SECURE_SIGN2HASH_TEMP_BUF   (UBOOT_SECURE_MCP_MEMORY_ADDR + 0x800)
#define SECURE_MAX_ALLOC_SIZE		(UBOOT_SECURE_MCP_MEMORY_SIZE)	// (32UL << 20)
#define SECURE_MALLOC_BASE 			SECURE_SIGN2HASH_TEMP_BUF

/************************************************************************
 *  Definition
 ************************************************************************/
#define  DEFAULT_KEY_PTR			NULL // Kh_key_default

#define  CP_REG_BASE				0xb8015000

#define  CP_OTP_LOAD				(CP_REG_BASE + 0x19c)

#if 0
	//for KCPU & ACPU
	/* MCP General Registers */
#define  K_MCP_CTRL					(CP_REG_BASE + 0x900)
#define  K_MCP_STATUS				(CP_REG_BASE + 0x904)
#define  K_MCP_EN					(CP_REG_BASE + 0x908)

	/* MCP Ring-Buffer Registers */
#define  K_MCP_BASE					(CP_REG_BASE + 0x90c)
#define  K_MCP_LIMIT				(CP_REG_BASE + 0x910)
#define  K_MCP_RDPTR				(CP_REG_BASE + 0x914)
#define  K_MCP_WRPTR				(CP_REG_BASE + 0x918)
#define  K_MCP_DES_COUNT			(CP_REG_BASE + 0x934)
#define  K_MCP_DES_COMPARE			(CP_REG_BASE + 0x938)

	/* MCP Ini_Key Registers */
#define  K_MCP_DES_INI_KEY			(CP_REG_BASE + 0x91C)
#define  K_MCP_AES_INI_KEY			(CP_REG_BASE + 0x924)
#else
	//for SCPU
	/* MCP General Registers */
#define  K_MCP_CTRL					(CP_REG_BASE + 0x100)
#define  K_MCP_STATUS				(CP_REG_BASE + 0x104)
#define  K_MCP_EN					(CP_REG_BASE + 0x108)

	/* MCP Ring-Buffer Registers */
#define  K_MCP_BASE					(CP_REG_BASE + 0x10c)
#define  K_MCP_LIMIT				(CP_REG_BASE + 0x110)
#define  K_MCP_RDPTR				(CP_REG_BASE + 0x114)
#define  K_MCP_WRPTR				(CP_REG_BASE + 0x118)
#define  K_MCP_DES_COUNT			(CP_REG_BASE + 0x134)
#define  K_MCP_DES_COMPARE			(CP_REG_BASE + 0x138)

	/* MCP Ini_Key Registers */
#define  K_MCP_DES_INI_KEY			(CP_REG_BASE + 0x11C)
#define  K_MCP_AES_INI_KEY			(CP_REG_BASE + 0x124)

#endif
#define UBOOT_DDR_OFFSET        	0xA0000000  //for RTD299X

#define CP_DESCRIPTOR_ADDR			(0xa000ff00 - UBOOT_DDR_OFFSET)	/* CP descriptor address */
#define CP_DSCPT_POOL_BASE_ADDR		(0xa0010000 - UBOOT_DDR_OFFSET)	/* CP descriptor pool base address */
#define CP_DSCPT_POOL_SIZE			0x800							/* CP descriptor pool size */
#define CP_DSCPT_POOL_MAX_ADDR		(CP_DSCPT_POOL_BASE_ADDR + CP_DSCPT_POOL_SIZE)


typedef struct mcp_descriptor
{
    unsigned int mode;
    unsigned int key[6];
    unsigned int ini_key[4];
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned int length;
} t_mcp_descriptor ;

/* 128 bit of AES_H initial vector(h0) */
#define AES_H_IV_0		            0x2dc2df39
#define AES_H_IV_1		            0x420321d0
#define AES_H_IV_2		            0xcef1fe23
#define AES_H_IV_3		            0x74029d95

/* 160 bit SHA1 initial vector */
#ifndef SHA1_IV_0
    #define SHA1_IV_0		        0x67452301
    #define SHA1_IV_1		        0xEFCDAB89
    #define SHA1_IV_2		        0x98BADCFE
    #define SHA1_IV_3		        0x10325476
    #define SHA1_IV_4		        0xC3D2E1F0
#endif

#define SHA1_SIZE					20

/* 256 bit SHA256 initial vector */
#define SHA256_H0					0x6A09E667
#define SHA256_H1					0xBB67AE85
#define SHA256_H2					0x3C6EF372
#define SHA256_H3					0xA54FF53A
#define SHA256_H4					0x510E527F
#define SHA256_H5					0x9B05688C
#define SHA256_H6					0x1F83D9AB
#define SHA256_H7					0x5BE0CD19


#define SHA256_SIZE					32


#define SECURE_KH_KEY_STR 			"abcdef1213572468a1b2c3d49090babe"
#define SECURE_KH_KEY0 				0xabcdef12
#define SECURE_KH_KEY1 				0x13572468
#define SECURE_KH_KEY2 				0xa1b2c3d4
#define SECURE_KH_KEY3 				0x9090babe

#define RSA_SIGNATURE_LENGTH		256

#define PHYS(addr)              	((uint)(addr))

//#define MCP_DEBUG
/************************************************************************
 *  Public functions
 ************************************************************************/
int AES_CBC_decrypt(unsigned char * src_addr, unsigned int length, unsigned char * dst_addr, unsigned int key[4]);
int AES_CBC_encrypt(unsigned char * src_addr, unsigned int length, unsigned char * dst_addr, unsigned int key[4]);
int AES_ECB_decrypt(unsigned char * src_addr, unsigned int length, unsigned char * dst_addr, unsigned int key[4]);
int AES_ECB_encrypt(unsigned char * src_addr, unsigned int length, unsigned char * dst_addr, unsigned int key[4]);
int AES_hash_one(unsigned char * src_addr, unsigned int length, unsigned char * dst_addr);
int AES_hash(unsigned char * src_addr, unsigned int length, unsigned char * dst_addr, unsigned int block_size);
int SHA1_hash(unsigned char * src_addr, unsigned int length, unsigned char * dst_addr, unsigned int iv[5]);
int SHA256_hash(unsigned char * src_addr, unsigned int length, unsigned char *dst_addr, unsigned int iv[8]);
int Verify_SHA256_hash( unsigned char * src_addr, unsigned int length, unsigned char * ref_sha256, unsigned int do_recovery );
void rtk_hexdump( const char * str, unsigned char * pcBuf, unsigned int length );
void reverse_signature( unsigned char * pSignature );

#endif // __MCP_H__
