#include <stdio.h>
#include "header.h"

/*
 * Following definitions are from:
 * http://lxr.free-electrons.com/source/arch/x86/include/asm/pgtable_64.h#L23
 *
  extern pud_t level3_kernel_pgt[512];
  extern pud_t level3_ident_pgt[512];
  extern pmd_t level2_kernel_pgt[512];
  extern pmd_t level2_fixmap_pgt[512];
  extern pmd_t level2_ident_pgt[512];
  extern pte_t level1_fixmap_pgt[512];
  extern pgd_t init_level4_pgt[];
  #define swapper_pg_dir init_level4_pgt
 */

arch_t arch;

// Right shit 0xFFFFFFFFFFFFFFFF by (63-b) and then zero out (a) LSB bits
#define BIT_MASK(a, b) (((unsigned long long) -1 >> (63 - (b))) & ~((1ULL << (a)) - 1))

addr_t get_pml4_index (addr_t vaddr) {
    return (vaddr & BIT_MASK(39,47)) >> 36;
}

/*
 * Level 0 is PML4E(Page-Map Level-4 Offset)
 * Level 1 is PDPE(Page-Directory- Pointer Offset)
 * Level 2 is PDP(Page-Directory Offset) 
 * Level 3 is PTE (Page Table Offset)
 */
int 
get_pml4e (addr_t va, addr_t kpgd, addr_t *pml4e_address, addr_t *pml4e_value) {
	addr_t			paddr, tmp, va_temp;
	addr_t			*buff;
	buff = malloc(4);

    *pml4e_value = 0;
	// Basically, location = Mask 12 LSB of KPGD  + 9 MSB of vaddr (offset)
	*pml4e_address = (kpgd & BIT_MASK(12,51)) | get_pml4_index(va);
	// Read 4 bytes from *pml4e_address. This is the pml4e_value
	// This read is just be reading phy mem
	// read_32_pa(*pgd_location, &value);
	paddr = *pml4e_address;
	tmp = NULL;
    if (tmp != fseek(arch.dump, paddr, SEEK_SET)) {
		printf("fseek returned %ld, vs %ld\n", tmp, paddr);
		perror("\n Error in get_pgd seek");
		return FAILURE;
    }
	if (8 != fread(buff, 1, 8, arch.dump)) {
		perror("\n Error in get_pgd read");
		return FAILURE;
	}
	*pml4e_value = *buff;
	printf("PGD Location:0x%.16x, Value:0x%.16x\n",
			*pml4e_address, *pml4e_value);
	return SUCCESS;
}

/*           PGD     PUD     PMD     PTE  -> PAGE
 * i386	    22-31	 	 	12-21
 * i386pae  30-31	21-29	12-20
 * x86-64	39-46	30-38	21-29	12-20
 * Taken from v2p_ia32e in libvmi arch/amd64.c
 */
int pagetable_lookup (addr_t kpgd, addr_t va, addr_t *phys_addr) {
	page_info_t	*page;
	addr_t		paddr;
	int			ret;

	printf("pagetable_lookup for va: 0x%.16x\n", va);
	ret = get_pml4e(va, kpgd, &arch.pml4e_location, &arch.pml4e_value);
	if (ret == FAILURE) return ret;
	/*
    get_pte(va, arch.pgd_value, &arch.pte_location, &arch.pte_value);
    paddr = get_paddr(va, &arch.pte_value);
	*phys_addr = paddr;
	printf("pagetable_lookup for va: 0x%.16x, is 0x%.16x\n", va, paddr);
	*/
}

int loadPTValues () {
	addr_t va_init_level4_pgt, va_phys_startup_64, va_startup_64;
	addr_t boundary, va_swapper_pg_dir, paddr;
	addr_t phys_addr;
	int ret;

	ret = get_symbol_row("swapper_pg_dir", &va_swapper_pg_dir);
	if (ret == FAILURE) {
		printf("This is a 64bit m/c\n");
		arch.bits = BIT64;
		ret = get_symbol_row("init_level4_pgt", &va_init_level4_pgt);
	} else {
		printf("This is a 32bit m/c\n");
		arch.bits = BIT32;
	}
	// phys_startup = 0x1000000, which is 16 Megs
	ret = get_symbol_row("phys_startup_64", &va_phys_startup_64);
	// virt_start = 0x81000000 = 2 Gigs
	ret = get_symbol_row("startup_64", &va_startup_64);
	boundary = va_startup_64 - va_phys_startup_64;
	arch.kpgd = va_init_level4_pgt - boundary;
	printf("boundary = 0x%x, kpgd = 0x%x\n", boundary, arch.kpgd);
	// Sanity check - convert VA to PA using Page Tables
	// Physical address for va_startup_64 should equal va_phys_startup_64
	ret = pagetable_lookup(arch.kpgd, va_startup_64, &phys_addr);
	if (ret == FAILURE) return ret;
}

main(int argc, char **argv) {
	addr_t va;
	int ret;

	if (argc != 2) {
		printf("Enter symbol to get Virtual Address for\n");
	}

	arch.fd = NULL;
	arch.dump = fopen("./dump1g", "r");
	if (arch.dump == NULL) {
		perror("Cannot open dump file");
		return;
	}
	ret = get_symbol_row(argv[1], &va);
	loadPTValues();
}