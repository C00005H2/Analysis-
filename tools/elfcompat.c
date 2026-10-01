/*
 * elfcompat - make Ubuntu 24.04 (glibc 2.38/2.39) shared objects loadable on
 * an older glibc host, without recompiling.
 *
 * Two surgical, in-place edits:
 *
 *  1. Undefined symbols named "__isoc23_xxx" are re-pointed to the classic
 *     "xxx" entry point. The glibc 2.38 C23 variants differ only in accepting
 *     binary literals, which these libraries never rely on. No string table
 *     mutation is needed: "__isoc23_" is exactly 9 bytes, so advancing st_name
 *     by 9 yields the classic name already present in .dynstr.
 *
 *  2. Any symbol bound to a glibc version node newer than the host's
 *     (e.g. GLIBC_2.38) is made unversioned (VER_NDX_GLOBAL), and the
 *     corresponding Verneed aux entry is flagged VER_FLG_WEAK so the dynamic
 *     loader stops rejecting the object outright. Symbols such as fmod then
 *     resolve from libm via the normal global lookup.
 *
 * Usage: elfcompat <max-supported-glibc-minor> <file>...   e.g. elfcompat 36 lib.so
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>

static int glibc_minor(const char *v)
{
    unsigned maj, min;
    if (sscanf(v, "GLIBC_%u.%u", &maj, &min) != 2) return -1;
    if (maj != 2) return -1;
    return (int)min;
}

static int patch(const char *path, int maxminor)
{
    int fd = open(path, O_RDWR);
    if (fd < 0) { perror(path); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) { close(fd); return -1; }

    unsigned char *m = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) { perror("mmap"); close(fd); return -1; }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)m;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) || eh->e_ident[EI_CLASS] != ELFCLASS64) {
        munmap(m, st.st_size); close(fd); return 1;           /* not ELF64 - skip */
    }

    Elf64_Shdr *sh = (Elf64_Shdr *)(m + eh->e_shoff);
    const char *shstr = (const char *)(m + sh[eh->e_shstrndx].sh_offset);

    Elf64_Sym *dynsym = NULL; char *dynstr = NULL;
    Elf64_Half *versym = NULL; unsigned char *verneed = NULL;
    size_t nsym = 0, nverneed = 0;

    for (int i = 0; i < eh->e_shnum; i++) {
        const char *n = shstr + sh[i].sh_name;
        if (!strcmp(n, ".dynsym"))  { dynsym = (Elf64_Sym *)(m + sh[i].sh_offset);
                                      nsym = sh[i].sh_size / sizeof(Elf64_Sym); }
        else if (!strcmp(n, ".dynstr"))        dynstr  = (char *)(m + sh[i].sh_offset);
        else if (!strcmp(n, ".gnu.version"))   versym  = (Elf64_Half *)(m + sh[i].sh_offset);
        else if (!strcmp(n, ".gnu.version_r")) { verneed = m + sh[i].sh_offset;
                                                 nverneed = sh[i].sh_info; }
    }
    if (!dynsym || !dynstr) { munmap(m, st.st_size); close(fd); return 1; }

    /* Pass 1: collect version indices that the host glibc cannot provide. */
    unsigned short bad[256]; size_t nbad = 0; int weakened = 0;
    if (verneed) {
        unsigned char *vn = verneed;
        for (size_t i = 0; i < nverneed; i++) {
            Elf64_Verneed *v = (Elf64_Verneed *)vn;
            unsigned char *va = vn + v->vn_aux;
            Elf64_Vernaux *prev = NULL;
            unsigned cnt = v->vn_cnt;
            for (unsigned j = 0; j < cnt; j++) {
                Elf64_Vernaux *a = (Elf64_Vernaux *)va;
                Elf64_Word next = a->vna_next;
                int min = glibc_minor(dynstr + a->vna_name);
                if (min > maxminor && nbad < 256) {
                    bad[nbad++] = a->vna_other & 0x7fff;
                    a->vna_flags |= VER_FLG_WEAK;       /* fallback: tolerate absence */
                    weakened++;
                    /* Unlink from the aux chain so the loader never sees it.  */
                    if (v->vn_cnt > 1) {
                        if (prev)
                            prev->vna_next = next ? (Elf64_Word)(prev->vna_next + next) : 0;
                        else
                            v->vn_aux += (next ? a->vna_next : 0);
                        if (!next && prev) prev->vna_next = 0;
                        v->vn_cnt--;
                    }
                } else {
                    prev = a;
                }
                va += next;
                if (!next) break;
            }
            vn += v->vn_next;
            if (!v->vn_next) break;
        }
    }

    /* Pass 2: rewrite the affected undefined symbols. */
    int renamed = 0, unversioned = 0;
    for (size_t i = 0; i < nsym; i++) {
        if (dynsym[i].st_shndx != SHN_UNDEF) continue;
        const char *name = dynstr + dynsym[i].st_name;

        int hit = 0;
        if (versym) {
            unsigned short ix = versym[i] & 0x7fff;
            for (size_t k = 0; k < nbad; k++)
                if (ix == bad[k]) { hit = 1; break; }
        }
        if (!hit) continue;

        if (!strncmp(name, "__isoc23_", 9)) {
            dynsym[i].st_name += 9;                      /* "__isoc23_" is 9 bytes */
            renamed++;
        }
        versym[i] = 1;                                   /* VER_NDX_GLOBAL */
        unversioned++;
    }

    munmap(m, st.st_size);
    close(fd);
    if (weakened || unversioned)
        printf("  patched %-40s (weak:%d unversioned:%d renamed:%d)\n",
               path, weakened, unversioned, renamed);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s <max-glibc-minor> <file>...\n", argv[0]); return 2; }
    int maxminor = atoi(argv[1]);
    for (int i = 2; i < argc; i++) patch(argv[i], maxminor);
    return 0;
}
