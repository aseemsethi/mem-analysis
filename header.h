typedef unsigned long addr_t;

#define SUCCESS 0
#define FAILURE 1
#define BIT32 0
#define BIT64 1

typedef struct {
	int bits;
	FILE *fd;
	FILE *dump;
	addr_t kpgd;

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

