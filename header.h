#include <stdlib.h>
typedef unsigned long addr_t;

#define SUCCESS 0
#define FAILURE 1
#define BIT32 0
#define BIT64 1

// 2MB Page Size
#define PS_2MB 0x200000ULL 
#define GET_BIT(reg, bit) (!!(reg & (1ULL<<bit)))
#define PAGE_SIZE(entry)        GET_BIT(entry, 7)


typedef struct {
	int 	bits;
	FILE 	*fd;
	FILE 	*dump;
	addr_t 	kpgd;
	int		pageSize;

	// Page Table info
	addr_t pte_location;
	addr_t pte_value;
	addr_t pgd_location;
	addr_t pgd_value;
	addr_t pdpte_location;
	addr_t pdpte_value;
	addr_t pml4e_location;
	addr_t pml4e_value;
} arch_t;


typedef struct page_info {
	addr_t pte_location;
	addr_t pte_value;
	addr_t pgd_location;
	addr_t pgd_value;
	addr_t pdpte_location;
	addr_t pdpte_value;
	addr_t pml4e_location;
	addr_t pml4e_value;
} page_info_t;

