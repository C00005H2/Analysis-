/* aPLib depacker matching the inline asm found at Test2.exe .boot+0x5D
 * Extracts the N aPLib streams listed at .boot+0x206 into one contiguous buffer
 * (the runtime image of the .winlice section).  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const uint8_t *src; static uint8_t tagv; static int first;
static int getbit(void){
    /* mirrors: add dl,dl / jne have / mov dl,[esi] / inc esi / adc dl,dl  (dl init 0x80) */
    int c = (tagv >> 7) & 1;            /* carry out of add dl,dl */
    uint8_t nv = (uint8_t)(tagv << 1);
    if (nv != 0) { tagv = nv; return c; }
    /* reload */
    { uint8_t b = *src++; tagv = (uint8_t)((b<<1) | c); return (b>>7)&1; }
}
static unsigned getgamma(void){ unsigned r=1; do { r=(r<<1)+getbit(); } while(getbit()); return r; }

/* returns bytes written; advances global src past the consumed stream */
static size_t depack(uint8_t *dst0, uint8_t *dst, size_t cap){
    uint8_t *d = dst; unsigned lwm = 0; unsigned r0 = 0;  /* ebx: 2 => lwm0, 1 => lwm1 */
    unsigned ebx = 2;
    tagv = 0x80;
    *d++ = *src++;                       /* first literal */
    for(;;){
        if(!getbit()){ *d++ = *src++; ebx = 2; continue; }        /* 0  -> literal */
        if(!getbit()){                                            /* 10 -> gamma pair */
            unsigned g = getgamma();
            unsigned off = g - ebx; ebx = 1;
            unsigned len;
            if(off == 0){ len = getgamma(); off = r0; }
            else { off = ((off-1)<<8) | *src++;
                   len = getgamma();
                   if(off >= 32000) len += 2;
                   else if(off >= 1280) len += 1;
                   else if(off <= 127) len += 2;
                   r0 = off; }
            if(off==0 || (size_t)(d-dst0) < off){ fprintf(stderr,"bad off %u at %zu\n",off,(size_t)(d-dst0)); return (size_t)(d-dst); }
            while(len--){ *d = *(d-off); d++; }
            continue;
        }
        if(!getbit()){                                            /* 110 -> short match */
            unsigned b = *src++;
            unsigned len = 2 + (b & 1);
            unsigned off = b >> 1;
            if(off == 0) break;                                   /* end of stream */
            r0 = off; ebx = 1;
            if((size_t)(d-dst0) < off){ fprintf(stderr,"bad soff\n"); break; }
            while(len--){ *d = *(d-off); d++; }
            continue;
        }
        {                                                         /* 111 -> 4-bit single byte */
            unsigned off = 0; int i;
            for(i=0;i<4;i++) off = (off<<1) + getbit();
            if(off){ *d = *(d-off); d++; } else *d++ = 0;
            ebx = 2;
        }
    }
    return (size_t)(d - dst);
}

int main(int argc,char**argv){
    if(argc<5){ fprintf(stderr,"usage: %s <file> <bootRawOff> <tableOff> <outsize> [out]\n",argv[0]); return 1;}
    const char*fn=argv[1];
    long bootoff=strtol(argv[2],0,0), tbl=strtol(argv[3],0,0);
    size_t outsize=strtoul(argv[4],0,0);
    const char*out = argc>5?argv[5]:"winlice.bin";
    FILE*f=fopen(fn,"rb"); if(!f){perror("open");return 1;}
    fseek(f,0,SEEK_END); long fsz=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t*buf=malloc(fsz); fread(buf,1,fsz,f); fclose(f);
    uint8_t*table = buf + bootoff + tbl;
    unsigned n = *table++;
    printf("stream count = %u (0x%x)\n", n, n);
    uint8_t *dst = calloc(outsize,1);
    size_t total=0; src = table;
    for(unsigned i=0;i<n;i++){
        const uint8_t*s0 = src;
        size_t w = depack(dst, dst+total, outsize-total);
        printf("  stream %2u: in @0x%08lx len=%-9ld out=+0x%08zx size=0x%zx\n",
               i, (long)(s0-buf-bootoff), (long)(src-s0), total, w);
        total += w;
        if(total > outsize){ printf("  OVERFLOW\n"); break; }
    }
    printf("total decompressed = 0x%zx (%zu bytes)\n", total, total);
    FILE*o=fopen(out,"wb"); fwrite(dst,1,outsize,o); fclose(o);
    printf("wrote %s (%zu)\n", out, outsize);
    return 0;
}
