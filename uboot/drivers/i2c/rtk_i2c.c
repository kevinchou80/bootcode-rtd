#include <common.h>
#include "rtk_i2c-lib.h"

#ifdef CONFIG_I2C_MULTI_BUS

static unsigned int current_bus = 0;

int i2c_set_bus_num(unsigned int bus)
{    
	if ((bus < 0) || (bus >= I2C_GetBusCount())) 
    {
		printf("Bad bus: %d\n", bus);
		return -1;
	}        	
	current_bus = bus;	
	return 0;
}

unsigned int i2c_get_bus_num(void)
{
	return current_bus;
}
#endif


/* ------------------------------------------------------------------------ */
/* API Functions                                                            */
/* ------------------------------------------------------------------------ */
void i2c_init(int speed, int slaveaddr)
{
    I2C_Init();
    
#ifdef CONFIG_I2C_MULTI_BUS
	current_bus = 0;	
#endif	
}


/*
 * i2c_probe: - Test if a chip answers for a given i2c address
 *
 * @chip:	address of the chip which is searched for
 * @return:	0 if a chip was found, -1 otherwhise
 */
int i2c_probe(uchar chip)
{
	return 0;
}

/*
 * i2c_read: - Read multiple bytes from an i2c device
 *
 * The higher level routines take into account that this function is only
 * called with len < page length of the device (see configuration file)
 *
 * @chip:	address of the chip which is to be read
 * @addr:	i2c data address within the chip
 * @alen:	length of the i2c data address (1..2 bytes)
 * @buffer:	where to write the data
 * @len:	how much byte do we want to read
 * @return:	0 in case of success
 */
int i2c_read(uchar chip, uint addr, int alen, uchar *buffer, int len)
{    
    unsigned char tmp[10];
    tmp[0] = addr;
    return (alen==1) ? I2C_Read_EX(current_bus, chip, alen, tmp, len, buffer, 0) : -1;   
}

/*
 * i2c_write: -  Write multiple bytes to an i2c device
 *
 * The higher level routines take into account that this function is only
 * called with len < page length of the device (see configuration file)
 *
 * @chip:	address of the chip which is to be written
 * @addr:	i2c data address within the chip
 * @alen:	length of the i2c data address (1..2 bytes)
 * @buffer:	where to find the data to be written
 * @len:	how much byte do we want to read
 * @return:	0 in case of success
 */
int i2c_write(uchar chip, uint addr, int alen, uchar *buffer, int len)
{
    unsigned char tmp[256];
    if (len + alen > 256)
        return -1;
    tmp[0] = addr;
    //memcpy(tmp, addr, alen);
    memcpy(tmp[alen], buffer, len);            

	return (alen==1) ? I2C_Write_EX(current_bus, chip, alen + len, tmp, NO_READ) : -1;   
}
