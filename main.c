/* sectview: Display the section layout of an ELF file
 * Copyright 2015 enferex <mattdavis9@gmail.com>
 *
 * sectview is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * sectview is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with sectview.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>


#define ERR(...) \
    do { fprintf(stderr,__VA_ARGS__); \
         fputc('\n',stderr);          \
         exit(EXIT_FAILURE);}         \
    while(0)


typedef struct _sect_t
{
    size_t size;    /* How big the section is (bytes) */
    size_t offset;  /* Where the section is located   */
    const char *name; /* Duh                            */
} sect_t;


static void usage(const char *execname)
{
    printf("Usage: %s <obj or exec>\n"
           "  <obj | exec | lib>: path to the ELF binary to examine\n",
            execname);
    exit(EXIT_SUCCESS);
}


static size_t safe_fread(void *buf, size_t sz, FILE *fp)
{
    if (fread(buf, 1, sz, fp) != sz)
    {
        if (ferror(fp))
          ERR("Error %d reading from input file", ferror(fp));
        else
          ERR("Could not read requested amount from input file");
    }

    return sz;
}


static void draw(int n_sections, const sect_t *sections)
{
    int i;

    printf("+ Offset          Bytes +\n");
    printf("+-----------------------+\n");
    for (i=1; i<n_sections; ++i) /* Skip the 0 (initial null sect) */
      printf("| %-8p %11zuB | <-- %s\n", 
              (void *)sections[i].offset, 
              sections[i].size, 
              sections[i].name);
    printf("+-----------------------+\n");
}

#if 0
static void gpic(int n_sections, const sect_t *sections)
{
    int i;
    size_t total;
    float height;
    const float max = 1024.0f;

    total = 0;
    for (i=0; i<n_sections; ++i)
      total += sections[i].size;

    printf(".PS\n");
    printf("down\n");
    for (i=0; i<n_sections; ++i)
    {
        height = ((float)sections[i].size / (float)total) * max;
        printf("box height %d \"%s\"\n", (int)height, sections[i].name);
    }
    printf(".PE\n");
}
#endif


/* 32/64 Elf structure accessor:
 * _b: Name of the structure following the Elf32 or Elf64 prefix
 * _f: Field of the structure to access
 * _s: Bit size (32 or 64)
 * _p: void * to the structure
 */
#define E(_b, _f, _s, _p) ((_s==32) ? \
    ((Elf32_##_b *) _p)->_f : ((Elf64_##_b *) _p)->_f)

#define E_SZ(_b, _s) ((_s==32) ? \
    sizeof(Elf32_##_b) : sizeof(Elf64_##_b))

                         
static void disp_sections(FILE *fp, const char *fname)
{
    int i, n_sections, bits;
    void *hdr, *shdr;
    uint64_t strtbl_idx, shent_sz;
    char *strtbl, ident[EI_NIDENT];
    sect_t *all_sects;
    Elf32_Ehdr hdr32 = {{0}};
    Elf64_Ehdr hdr64 = {{0}};

    safe_fread(ident, EI_NIDENT, fp);
    if (strncmp(ident, ELFMAG, strlen(ELFMAG)) != 0)
      ERR("This is not an ELF file");

    if (ident[EI_CLASS] == ELFCLASS32) 
    {
        hdr = (Elf32_Ehdr *)&hdr32;
        bits = 32;
    }
    else if (ident[EI_CLASS] == ELFCLASS64)
    {
        hdr = (Elf64_Ehdr *)&hdr64;
        bits = 64;
    }
    else
      ERR("Unknown binary word-size");

    /* Read the ELF header */
    rewind(fp);
    safe_fread(hdr, E_SZ(Ehdr, bits), fp);
    n_sections = E(Ehdr, e_shnum, bits, hdr);
    strtbl_idx = E(Ehdr, e_shstrndx, bits, hdr);
    shent_sz = E(Ehdr, e_shentsize, bits, hdr);

    /* A temp store for section headers (32 or 64bit agnostic) */
    if (!(shdr = malloc(shent_sz)))
      ERR("Could not allocate enough memory to parse a section header");

    /* Get the section header for the string table */
    fseek(fp, E(Ehdr, e_shoff, bits, hdr) + strtbl_idx * shent_sz, SEEK_SET);
    safe_fread(shdr, shent_sz, fp);

    /* Allocate and read the string table */
    if (!(strtbl = malloc(E(Shdr, sh_size, bits, shdr))))
      ERR("Could not allocate enough memory to store the string table");
    fseek(fp, E(Shdr, sh_offset, bits, shdr), SEEK_SET);
    safe_fread(strtbl, E(Shdr, sh_size, bits, shdr), fp);
   
    /* Array of our sections with only data we care about (internal rep) */ 
    if (!(all_sects = calloc(n_sections, sizeof(sect_t))))
      ERR("Could not allocate enough memory to store section data");

    /* For each section... */
    fseek(fp, E(Ehdr, e_shoff, bits, hdr), SEEK_SET);
    for (i=0; i<n_sections; ++i)
    {
        safe_fread(shdr, shent_sz, fp);
        all_sects[i].name   = strtbl + E(Shdr, sh_name, bits, shdr);
        all_sects[i].size   = (size_t)E(Shdr, sh_size, bits, shdr);
        all_sects[i].offset = (size_t)E(Shdr, sh_offset, bits, shdr);
    }

    draw(n_sections, all_sects);
    /* gpic(n_sections, all_sects); */

    /* Cleanup */
    free(shdr);
    free(strtbl);
    strtbl = NULL;
}


int main(int argc, char **argv)
{
    FILE *fp;
    const char *fname;

    if (argc != 2)
      usage(argv[0]);

    fname = argv[1];
    if (!(fp = fopen(fname, "r")))
      ERR("Could not open file: %s", fname);

    disp_sections(fp, fname);

    fclose(fp);
    return 0;
}
