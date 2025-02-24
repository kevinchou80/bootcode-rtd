#include <common.h>

#ifdef CONFIG_NONCACHE_ALLOCATION
static unsigned int mem_noncache_start; 
static unsigned int mem_noncache_end; 
static unsigned int mem_noncache_current;

void *malloc_noncache(unsigned int size) {
	unsigned int allocated;
	if (mem_noncache_current + size > mem_noncache_end) {
		printf("Memory is not enough!\n");
		printf("Available memory %d, but request %d bytes\n", mem_noncache_end-mem_noncache_current, size);
		return (void *)0;	
	}

	if (size%4) {
		size -= (size%4);
		size += 4;
	}
	allocated = mem_noncache_current;
	mem_noncache_current += size;

	return (void *)allocated;
}

void mem_malloc_noncache_init(unsigned int start, unsigned int size) {
	mem_noncache_current = mem_noncache_start = start;
	mem_noncache_end = start + size;
}
#endif	//CONFIG_NONCACHE_ALLOCATION
