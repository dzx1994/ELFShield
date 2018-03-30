#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>

#define PAGESIZE 4096

char buffer[PAGESIZE*4];
char outfile[512];

int main(int argc, char **argv){
	int fd1, fd2;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	unsigned i;
	unsigned loader_filesz = 0, so_filesz = 0;
	struct stat f_stat;
	void *base;
	int load2 = 0;
	unsigned load2_offset = 0;
	if(argc < 3){
		printf("Notic input file\n");
		return -1;
	}
	fd1 = open(argv[1], O_RDWR);
        printf("fd1 is  %d\n", fd1);
	if(fd1 == -1){
		printf("cannot open loader %s\n", argv[1]);
		return -1;
	}
	fd2 = open(argv[2], O_RDWR);
        printf("fd2 is %d\n", fd2);
	if(fd2 == -1){
		printf("open so %s failed\n", argv[2]);
		goto _error;
	}
        if(fstat(fd1, &f_stat) < 0){
	printf("get so filze failed\n");
	goto _error;
	}
	read(fd1, buffer, PAGESIZE);
        printf("ehdr is 0x%x\n", buffer);
	ehdr = (Elf32_Ehdr*)buffer;
	phdr = (Elf32_Phdr*)(buffer + ehdr->e_phoff);
        printf("phdr is 0x%x\n", phdr);
	for (i = 0; i < ehdr->e_phnum; ++i){
		if(phdr[i].p_type == PT_LOAD){
			loader_filesz = phdr[i].p_filesz + phdr[i].p_offset;
			if(load2){
				load2_offset = (unsigned)&phdr[i] - (unsigned)ehdr;
			}else{
				load2 = 1;
			}
		}
	}
	printf("loader size = 0x%x\n", loader_filesz);
	if(fstat(fd2, &f_stat) < 0){
		printf("get so filze failed\n");
		goto _error;
	}
	printf("so size = 0x%x\n", f_stat.st_size);
	base = mmap(NULL, loader_filesz + f_stat.st_size, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        printf("base is 0x%x\n", base);
	if(base == (void*)-1){
		printf("get space failed\n");
		goto _error;
	}
	if(mmap(base, loader_filesz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd1, 0) == (void*)-1){
		printf("mmap loader failed\n");
		goto _done;
	}
	read(fd2, base + loader_filesz, f_stat.st_size);
	ehdr = (Elf32_Ehdr*)(base);
	ehdr->e_shoff = loader_filesz + 0x1000;
	phdr = (Elf32_Phdr*)(base + load2_offset);
	phdr->p_memsz += f_stat.st_size;
	phdr->p_filesz += f_stat.st_size;
	do{
		int fdw;
		char name[300];
		char *p_name;
		sprintf(name, "%s", argv[2]);
		p_name = strstr(name, "mo");
		if(p_name != NULL){
			*p_name = 's';
		}
		fdw = open(name, O_WRONLY | O_CREAT | O_EXCL);
		if(fdw == -1){
			printf("write file %s failed\n", name);
			goto _done;
		}
		write(fdw, base, loader_filesz + f_stat.st_size);
		close(fdw);
	}while(0);
_done:
	munmap(base, loader_filesz + f_stat.st_size);
_error:
	close(fd2);
	close(fd1);
	return 0;
}
