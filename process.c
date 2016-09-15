#include <stdio.h>
#include "header.h"
#include "log.h"

extern arch_t arch;
int loadProcesses() {
	addr_t va_init_task;
	addr_t va;
    addr_t list_head = 0, next_list_entry = 0;
    addr_t current_process = 0, pid_offset, name_offset;
	addr_t phys_addr;
	unsigned long pid = 0;
	int ret = 0, counter = 0;
/*
 * init_task or swapper process is not shown in "ps" listing, but can be
 * got by searching for init_task in the task list.
 */
	log_info(stdout, "Load processes from task_struct");
	ret = get_symbol_row("init_task", &va_init_task);
	list_head = va_init_task + arch.tasks_offset;
    next_list_entry = list_head;

	do {
		char* procname = malloc(100); // for Process Name read via strRead

		current_process = next_list_entry - arch.tasks_offset;
		log_debug(stdout, "Current Process VA :0x%x", current_process);
		pid_offset = current_process+arch.pid_offset;
		// We need to get Phys Mem for this VA
		// Since kpgd is set, we go thru the Page Tables, and not 
		// boundary mapping.
		ret = pagetable_lookup(arch.kpgd, pid_offset, &phys_addr);
		memRead(&phys_addr, &pid);
		//log_debug(stdout, "Process VA Address:0x%x, PID VA Offset: %x",
		//	current_process, pid_offset);

		// Now get the Process Name
		name_offset = current_process + arch.name_offset;
		ret = pagetable_lookup(arch.kpgd, name_offset, &phys_addr);
        ret = strRead(&phys_addr, procname);

		// Output
		log_info(stdout, "  [%d] Virt: %x, Phys: %x, PID: %d, Name: %s",
				counter, current_process, phys_addr, pid, procname);

		// To loop again, look at the contents of next_list_entry.
		// At this point the VA of the next next_list_entry in linked-list
		// will be found.
		log_debug(stdout, "--------------------------------------------------");
		ret = pagetable_lookup(arch.kpgd, next_list_entry, &va);
		memRead(&va, &next_list_entry);
		log_debug(stdout, "VA of next_list_entry .......: %x, ", next_list_entry);
	} while (next_list_entry != list_head);

}
