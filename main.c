#include <stdio.h>
#include "header.h"

// If CR0.PG = 1, CR4.PAE = 1, and IA32_EFER.LME = 1, IA-32e paging is used.

arch_t arch;


// Right shit 0xFFFFFFFFFFFFFFFF by (63-b) and then zero out (a) LSB bits
#define BIT_MASK(a, b) (((unsigned long long) -1 >> (63 - (b))) & ~((1ULL << (a)) - 1))

// L0 Page Map Level 4 Table Offset (PML4) (39-47)
addr_t get_pml4_index (addr_t vaddr) { 
	return (vaddr & BIT_MASK(39,47)) >> 36; }

// L1 Page Directory Pointer Offset (30-38)
addr_t get_pdpt_index_ia32e (addr_t vaddr) {
    return (vaddr & BIT_MASK(30,38)) >> 27; }

// L2 Page Directory Offset (21-29)
addr_t get_pd_index_ia32e (addr_t vaddr) {
    return (vaddr & BIT_MASK(21,29)) >> 18; }

// L3 Page Table Offset (12-20)
addr_t get_pt_index_ia32e (addr_t vaddr) {
    return (vaddr & BIT_MASK(12,20)) >> 9; }


int memRead (addr_t *address, addr_t *value) {
	addr_t			va_temp;
	addr_t			*buff;
	int 			ret;

	buff = malloc(8);
	printf("memRead Mem Dump at Phys Address:%x\n", *address);
    ret = fseek(arch.dump, *address, SEEK_SET);
    if (ret != 0) {
		perror("\n Error in get_pgd seek");
		return FAILURE;
    }
	if (8 != fread(buff, 1, 8, arch.dump)) {
		perror("\n Error in get_pgd read");
		return FAILURE;
	}
	*value = *buff;
}

int get_pml4e_ia32e (addr_t va, addr_t kpgd, 
				addr_t *pml4e_address, addr_t *pml4e_value) {

    *pml4e_value = 0;
	// Basically, location = Mask 12 LSB of KPGD  + 9 MSB of vaddr (offset)
	*pml4e_address = (kpgd & BIT_MASK(12,51)) | get_pml4_index(va);
	// Read 8 bytes from *pml4e_address. This is the pml4e_value
	// This read is by reading phy mem, vmi_read_64_pa(), which eventutally
	// calls vm_read() with the CR3 value set to 0, so that the main mem, which
	// is file in our case, is read directly as physical mem.
	memRead(pml4e_address, pml4e_value);
	printf("PML4E Address:0x%.16x, Value:0x%.16x\n",
			*pml4e_address, *pml4e_value);
	return SUCCESS;
}

int get_pdpte_ia32e (addr_t vaddr, addr_t pml4e,
					addr_t *pdpte_address, addr_t *pdpte_value) {
    *pdpte_value = 0;
    *pdpte_address = (pml4e & BIT_MASK(12,51))|get_pdpt_index_ia32e(vaddr);
	memRead(pdpte_address, pdpte_value);
	printf("PDPTE Address:0x%.16x, Value:0x%.16x\n",
			*pdpte_address, *pdpte_value);
    return SUCCESS;
}

int get_pde_ia32e (addr_t vaddr, addr_t pdpte,
						addr_t *pde_address, addr_t *pde_value)
{
    *pde_value = 0;
    *pde_address = (pdpte & BIT_MASK(12,51)) | get_pd_index_ia32e(vaddr);
	memRead(pde_address, pde_value);
	printf("PDE Address:0x%.16x, Value:0x%.16x\n",
			*pde_address, *pde_value);
    return SUCCESS;
}

int get_pte_ia32e (addr_t vaddr, addr_t pde,
						addr_t *pte_address, addr_t *pte_value)
{
    *pte_value = 0;
    *pte_address = (pde & BIT_MASK(12,51)) | get_pt_index_ia32e(vaddr);
	memRead(pte_address, pte_value);
	printf("PTE Address:0x%.16x, Value:0x%.16x\n",
			*pte_address, *pte_value);
    return SUCCESS;
}

addr_t get_paddr_ia32e (addr_t vaddr, addr_t pte) {
    return (pte & BIT_MASK(12,51)) | (vaddr & BIT_MASK(0,11)); }



/*           PGD     PUD     PMD     PTE  -> PAGE
 * i386	    22-31	 	 	12-21
 * i386pae  30-31	21-29	12-20
 *
 * x86-64 (our example)
 * Sign Extend Page Offset (63-48),
 * L0 Page Map Level 4 Table Offset (PML4) (39-47)
 * L1 Page Directory Pointer Offset (30-38)
 * L2 Page Directory Offset (21-29) 
 * --- If 4 MB page size is set, next 2 entries are offset into 4 MB page
 * L3 Page Table Offset (12-20)
 * Page Offset (0-11)
 *
 * Code Taken from v2p_ia32e in libvmi arch/amd64.c
 */
int pagetable_lookup (addr_t kpgd, addr_t va, addr_t *phys_addr) {
	page_info_t	*page;
	addr_t		paddr;
	int			ret;

	// TBD: Checking for ENTRY_PRESENT is not being done to keep the code 
	// clearer. 
	printf("pagetable_lookup for va: 0x%.16x\n", va);
	ret = get_pml4e_ia32e   (va, kpgd, 
							&arch.pml4e_location, &arch.pml4e_value);
	if (ret == FAILURE) return ret;
    ret = get_pdpte_ia32e   (va, arch.pml4e_value,
							&arch.pdpte_location, &arch.pdpte_value);
	if (ret == FAILURE) return ret;
	ret = get_pde_ia32e     (va, arch.pdpte_value,
							&arch.pgd_location, &arch.pgd_value);
	if (ret == FAILURE) return ret;
	// Check the PAGE_SIZE using 7th bit in pgd_value. If this is set to 2MB
	// then we have 21 bits of page offset.
	// Page Directory 7th bit is used to check the page size
    if (PAGE_SIZE(arch.pgd_value)) { // pde maps a 2MB page
		printf("Pages are 2MB in size\n");
		arch.pageSize = PS_2MB;
		paddr = (arch.pgd_value & BIT_MASK(21,51)) |
				(va & BIT_MASK(0,20));
		goto done;
	}
	ret = get_pte_ia32e     (va, arch.pgd_value,
							&arch.pte_location, &arch.pte_value);
	if (ret == FAILURE) return ret;
    paddr = get_paddr_ia32e (va, arch.pte_value);
done:
	*phys_addr = paddr;
	printf("Physical Address:0x%.16x\n", paddr);
}

int loadProcesses() {
	addr_t va_init_task;
	addr_t va;
    addr_t list_head = 0, next_list_entry = 0;
    addr_t current_process = 0, pid_offset;
	addr_t phys_addr;
	unsigned long pid = 0;
	int ret = 0, counter = 0;
/*
 * init_task or swapper process is not shown in "ps" listing, but can be
 * got by searching for init_task in the task list.
 */
	printf("Load processes from task_struct\n");
	ret = get_symbol_row("init_task", &va_init_task);
	list_head = va_init_task + arch.tasks_offset;
    next_list_entry = list_head;

	do {
		current_process = next_list_entry - arch.tasks_offset;
		printf("-------------------------------------------------\n");
		printf("Current Process VA :0x%x\n", current_process);
		pid_offset = current_process+arch.pid_offset;
		// We need to get Phys Mem for this VA
		// Since kpgd is set, we go thru the Page Tables, and not 
		// boundary mapping.
		ret = pagetable_lookup(arch.kpgd, pid_offset, &phys_addr);
		memRead(&phys_addr, &pid);
		//printf("Process VA Address:0x%x, PID VA Offset: %x\n",
		//	current_process, pid_offset);
		printf("Phys Address: %x, PID: %x\n", phys_addr, pid);
		// To loop again, look at the contents of next_list_entry.
		// At this point the VA of the next next_list_entry in linked-list
		// will be found.
		printf("--------------------------------------------------\n");
		printf("VA of next_list_entry .......: %x, ", next_list_entry);
		ret = pagetable_lookup(arch.kpgd, next_list_entry, &va);
		printf(".......is: %x\n", va);
		memRead(&va, &next_list_entry);
	} while (counter++ < 1);

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

/*
 * TBD: Use the jsmn parser
 */
readConfig() {

	arch.tasks_offset = 0x448;  // offset of tasks in task_struct in sched.h
	arch.pid_offset = 0x4a8;  // offset of PID
}

/*
 * Invoke as ./mem <dump file> pagetables
 */
main(int argc, char **argv) {
	addr_t va;
	int ret;

	if (argc != 3) {
		printf("Enter memory dump file and command\n");
		return;
	}

	arch.fd = NULL;
	arch.dump = fopen(argv[1], "r");
	if (arch.dump == NULL) {
		perror("Cannot open dump file");
		return;
	}
	printf("Mem Dump file opened: %x\n", arch.dump);
	readConfig();

	if (strcmp("pagetables", argv[2]) == 0) {
		loadPTValues();
	} else if (strcmp("processes", argv[2]) == 0) {
		loadPTValues();
		loadProcesses();	
	} else {
		printf("..Invalid Command: %s\n", argv[2]);
		printf("Valid Commands: ");
		printf("pagetables, processes\n");
	}
}
