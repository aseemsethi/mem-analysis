#include <stdio.h>
#include "header.h"

extern arch_t arch;

/*
 * Taken from get_symbol_row in libvmi
 */
int get_symbol_row(char* symbol, addr_t* val) {
    int ret = FAILURE;
	int index=0;
    int position = 2;
	addr_t va;
    char *row = malloc(200);
	FILE *f;
	int pos;

	if (arch.fd == NULL) {
		arch.fd = fopen("/boot/System.map-2.6.32-431.el6.x86_64", "r");
		printf("\n FD for System.map file = %d", arch.fd);
	}
	f = arch.fd;
    pos = fseek(arch.fd, 0, SEEK_SET);

    while (fgets(row, 200, f) != NULL) {
		index++;
        char *token = NULL;

        /* find the correct token to check */
        int curpos = 0;
        int position_copy = position;

        while (position_copy > 0 && curpos < 200) {
            if (isspace(row[curpos])) {
                while (isspace(row[curpos])) {
                    row[curpos] = '\0';
                    ++curpos;
                }
                --position_copy;
                continue;
            }
            ++curpos;
        }
        if (position_copy == 0) {
            token = row + curpos;
            while (curpos < 200) {
                if (isspace(row[curpos])) {
                    row[curpos] = '\0';
                }
                ++curpos;
            }
        }
        else {  /* some went wrong in the loop above */
            goto error_exit;
        }

        /* check the token */
        if (strncmp(token, symbol, 200) == 0) {
			va = (addr_t) strtoull(row, NULL, 16);
			*val = va;
			printf("Token: %s, addr: 0x%x, at line:%d\n", symbol, va, index);
            ret = SUCCESS;
            break;
        }
    }

error_exit:
    if (ret == FAILURE) {
		printf("FAILED...to retrive symbol for %s\n", symbol);
        memset(row, 0, 200);
    }
    return ret;
}

