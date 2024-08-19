#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

struct elf64_file_hdr
{
  unsigned char	e_ident[16];	/* Magic number and other info */
  unsigned short	e_type;			/* Object file type */
  unsigned short	e_machine;		/* Architecture */
  unsigned int	e_version;		/* Object file version */
  unsigned long	e_entry;		/* Entry point virtual address */
  unsigned long	e_phoff;		/* Program header table file offset */
  unsigned long	e_shoff;		/* Section header table file offset */
  unsigned int	e_flags;		/* Processor-specific flags */
  unsigned short	e_ehsize;		/* ELF header size in bytes */
  unsigned short	e_phentsize;		/* Program header table entry size */
  unsigned short	e_phnum;		/* Program header table entry count */  
  unsigned short	e_shentsize;		/* Section header table entry size */
  unsigned short	e_shnum;		/* Section header table entry count */
  unsigned short	e_shstrndx;		/* Section header string table index */
};

struct elf64_section_hdr
{
  unsigned int	sh_name;		/* Section name (string tbl index) */
  unsigned int	sh_type;		/* Section type +4*/ 
  unsigned long	sh_flags;		/* Section flags +8*/
  unsigned long	sh_addr;		/* Section virtual addr at execution +16*/
  unsigned long	sh_offset;		/* Section file offset +24*/
  unsigned long	sh_size;		/* Section size in bytes */
  unsigned int	sh_link;		/* Link to another section */
  unsigned int	sh_info;		/* Additional section information */
  unsigned long	sh_addralign;		/* Section alignment */
  unsigned long sh_entsize;		/* Entry size if section holds table */
};

struct elf64_program_seg_hdr
{
  unsigned int	p_type;			/* Segment type */
  unsigned int	p_flags;		/* Segment flags */
  unsigned long	p_offset;		/* Segment file offset */
  unsigned long	p_vaddr;		/* Segment virtual address */
  unsigned long	p_paddr;		/* Segment physical address */
  unsigned long	p_filesz;		/* Segment size in file */
  unsigned long	p_memsz;		/* Segment size in memory */
  unsigned long	p_align;		/* Segment alignment */
};

/* values for p_type (segment type).  */

#define	PT_NULL		0		/* Program header table entry unused */
#define PT_LOAD		1		/* Loadable program segment */
#define PT_DYNAMIC	2		/* Dynamic linking information */
#define PT_INTERP	3		/* Program interpreter */
#define PT_NOTE		4		/* Auxiliary information */
#define PT_SHLIB	5		/* Reserved */
#define PT_PHDR		6		/* Entry for header table itself */
#define PT_TLS		7		/* Thread-local storage segment */
#define	PT_NUM		8		/* Number of defined types */
#define PT_LOOS		0x60000000	/* Start of OS-specific */
#define PT_GNU_EH_FRAME	0x6474e550	/* GCC .eh_frame_hdr segment */
#define PT_GNU_STACK	0x6474e551	/* Indicates stack executability */
#define PT_GNU_RELRO	0x6474e552	/* Read-only after relocation */
#define PT_GNU_PROPERTY	0x6474e553	/* GNU property */
#define PT_LOSUNW	0x6ffffffa
#define PT_SUNWBSS	0x6ffffffa	/* Sun Specific segment */
#define PT_SUNWSTACK	0x6ffffffb	/* Stack segment */
#define PT_HISUNW	0x6fffffff
#define PT_HIOS		0x6fffffff	/* End of OS-specific */
#define PT_LOPROC	0x70000000	/* Start of processor-specific */
#define PT_HIPROC	0x7fffffff	/* End of processor-specific */

char *buf[] = {
        "NULL",
        "LOAD",
        "DYNAMIC",
        "INTERP",
        "NOTE",
        "SHLIB",
        "PHDR",
        "TLS",
        "NUM",
        "LOOS",
        "GNU_EH_FRAME",
        "GNU_STACK",
        "GNU_RELRO",
        "GNU_PROPERTY",
        "LOSUNW",
        "SUNWBSS",
        "SUNWSTACK",
        "HISUNW",
        "HIOS",
        "LOPROC",
        "HIPROC",
        "NOT_EXIST"

    };

struct elf64_file_hdr file_hdr;
struct elf64_file_hdr *pointer_file_hdr;
struct elf64_section_hdr *pointer_section_hdr;
struct elf64_program_seg_hdr *pointer_seg_hdr;
unsigned long *value64_p;
unsigned short *value16_p;
unsigned int *value32_p;
unsigned char *value8_p;

char *program_header_name_by_value(unsigned int value)
{
    switch (value)
    {
        case PT_NULL:
            return buf[0];

        case PT_LOAD:
            return buf[1];

        case PT_DYNAMIC:
            return buf[2];

        case PT_INTERP:
            return buf[3];

        case PT_NOTE:
            return buf[4];

        case PT_SHLIB:
            return buf[5];

        case PT_PHDR:
            return buf[6];

        case PT_TLS:
            return buf[7];

        case PT_NUM:
            return buf[8];

        case PT_LOOS:
            return buf[9];

        case PT_GNU_EH_FRAME:
            return buf[10];

        case PT_GNU_STACK:
            return buf[11];

        case PT_GNU_RELRO:
            return buf[12];

        case PT_GNU_PROPERTY:
            return buf[13];

        case PT_LOSUNW:
            return buf[14];

        case PT_SUNWSTACK:
            return buf[16];

        case PT_HISUNW:
            return buf[17];

        case PT_LOPROC:
            return buf[19];

        case PT_HIPROC:
            return buf[20];
        default: return buf[21];
    }
};

void section_header_parser(char *mem)
{
    struct elf64_section_hdr *pointer_section_hdr_strndx;

    unsigned long sec_head_str_table_offset = pointer_file_hdr->e_shoff + (pointer_file_hdr->e_shstrndx)*pointer_file_hdr->e_shentsize;
    
    pointer_section_hdr_strndx = (struct elf64_section_hdr*)(mem + sec_head_str_table_offset);

    for (int i = 0; i < pointer_file_hdr->e_shnum; i++){
        unsigned long section_header_offset = pointer_file_hdr->e_shoff + i*pointer_file_hdr->e_shentsize;
        pointer_section_hdr = (struct elf64_section_hdr*)(mem+section_header_offset);
        
        unsigned long section_name_file_offset = pointer_section_hdr_strndx->sh_offset + pointer_section_hdr->sh_name;

        printf("%.3d:   offset: %.5lX   section header: %s || type: %X\n", i, section_header_offset, &mem[section_name_file_offset], pointer_section_hdr->sh_type);
    } 
};

void program_header_parser(char *mem)
{
    for (int i = 0; i < pointer_file_hdr->e_phnum; i++){

        unsigned long program_header_offset = pointer_file_hdr->e_phoff + i*pointer_file_hdr->e_phentsize;
        pointer_seg_hdr = (struct elf64_program_seg_hdr*)(mem + program_header_offset);

        printf("%.3d:   offset: %.5lX   program header: %s (%X)\n", i, program_header_offset, program_header_name_by_value(pointer_seg_hdr->p_type), pointer_seg_hdr->p_type);
    }
};



int main(int argc, char *argv[]){

   

    int fd;
    struct stat elf_struct;
    int file_struct_status;
    unsigned int file_size;
    int byte_counter;

   


    if (argc < 2){
        printf("no arguments, stop\n");
        return 0;
    }

    fd = open(argv[1], O_RDONLY);
    if (fd == -1){
        printf("open err\n");
        return 0;
    }

    file_struct_status = fstat(fd, &elf_struct);
    if (file_struct_status == -1){
        close(fd);
        printf("fstat err\n");
        return 0;
    }
        
    
    file_size = elf_struct.st_size;
    printf("File size: %x\n\n\n", file_size);

    unsigned char *mem = malloc(file_size);
    if (mem == 0){
        close(fd);
        printf("malloc err\n");
        return 0;
    }

    while (byte_counter = read(fd, mem, file_size)) 
        if (byte_counter == -1){
            close(fd);
            free(mem);
            printf("read err\n");
            return 0;
        }

    pointer_file_hdr = (struct elf64_file_hdr*)mem;

    if (file_size < sizeof(struct elf64_file_hdr)){
        printf("file too small\n");
        free(mem);
        close(fd);
        return 0;
    }

    printf("==========FILE HEADER==========\n\n");

    printf("entry point: %lX\n", pointer_file_hdr->e_entry);
   
    printf("Program header table file offset: %lX\n", pointer_file_hdr->e_phoff);

    printf("Section header table file offset: %lX\n", pointer_file_hdr->e_shoff);

    printf("Program header table entry size: %X\n", pointer_file_hdr->e_phentsize);

    printf("Program header table entry count: %X\n", pointer_file_hdr->e_phnum);

    printf("Section header table entry size: %X\n", pointer_file_hdr->e_shentsize);

    printf("Section header table entry count: %X\n", pointer_file_hdr->e_shnum);

    printf("Section header string table index: %X\n", pointer_file_hdr->e_shstrndx);

    printf("\n==========SECTION HEADER==========\n\n");
    section_header_parser(mem);

    printf("\n==========PROGRAM HEADER==========\n\n");
    program_header_parser(mem);

    printf("What do you want:\n\n");
  //  printf("symbol table: 1\n");

    //symbol_table_parser_with_relocs(mem);

    free(mem);
    close(fd);


}