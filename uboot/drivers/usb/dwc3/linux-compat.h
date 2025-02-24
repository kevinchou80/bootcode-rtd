/**
 * linux-compat.h - DesignWare USB3 Linux Compatibiltiy Adapter  Header
 *
 * Copyright (C) 2015 Texas Instruments Incorporated - http://www.ti.com
 *
 * Authors: Kishon Vijay Abraham I <kishon@ti.com>
 *
 * SPDX-License-Identifier:	GPL-2.0
 *
 */

#ifndef __DWC3_LINUX_COMPAT__
#define __DWC3_LINUX_COMPAT__

#include <linux/compat.h>

#define pr_debug(format)                debug(format)
#define WARN(val, format, arg...)	debug(format, ##arg)
#define dev_WARN(dev, format, arg...)	debug(format, ##arg)
#define WARN_ON_ONCE(val)		debug("Error %d\n", val)
#define dev_err(dev, fmt, args...)		\
	printf(fmt, ##args)
#define dev_dbg(dev, fmt, args...)		\
	debug(fmt, ##args)
#define dev_vdbg(dev, fmt, args...)		\
	debug(fmt, ##args)
#define dev_info(dev, fmt, args...)		\
	printf(fmt, ##args)


#define BUILD_BUG_ON_NOT_POWER_OF_2(n)

#define IRQ_NONE 0
#define IRQ_HANDLED 1
#define IRQ_WAKE_THREAD 2

typedef int spinlock_t;
typedef int irqreturn_t;
typedef unsigned long resource_size_t;

static inline size_t strlcat(char *dest, const char *src, size_t n)
{
	strcat(dest, src);
	return strlen(dest) + strlen(src);
}

static inline void *devm_kzalloc(struct device *dev, unsigned int size,
				 unsigned int flags)
{
	return kzalloc(size, flags);
}

static inline void *kmalloc_array(size_t n, size_t size, gfp_t flags)
{
	return kzalloc(n * size, flags);
}
#endif
