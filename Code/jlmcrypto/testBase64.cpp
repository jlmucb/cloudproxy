#include <stdio.h>
#include <string.h>
#include "jlmTypes.h"

#define NBITSINBYTE 8


const char* szA= "jf7LKELNZbwta1xSMZCzAjp7WNH9cwIV5LbjLS0kSo8R0QwTSeM4itUiSmLD8RRv+Fj1e/koAcGlXsXniul//onUvt5MsxdMiS+DPnfBSf2+H4MwMvn2FRdTkOP9hwt2XlYA4B2JhSLOBK+t2vFHxrcDm0Y9RKPB5AVTw97tNrnwzYbUdR68ZDU7pHZ/UYZJ/IIkU7ibYr/Olgh+p47Tfu06SBO1ctR9S1MbPHP/2NA1kQyWsy6Do8ohZOK+XWIG36tI2nLVNATXr3mFj+7XhdGdUMzVzEyvOZE5oXAPmh8d8yfFr2lrA3nqaFJ+ePmX+X2vEXJKqUjhIMPYmz9Zr/==";
//"AAABAAE=";
//const char* szA= "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAE=";
//"pCZtfApDmtrvb2TmxDYpZCAM8V3TY/9pm7sl3zXTKWkV0RN8pNuDfz/0sMKh7z9NyiMb349YzECjIbMQxFpw5/yJTJhMx3LP0HK0CYHgL3BhCvmoiCHy5Ss8G4EKnk2EAH5O3lAWUClyN6gU/Ry9vSk3IsvsMPnfCR/XEiXewQP1fI8sxGp0xOYBXGUkwexNR/zWVGER6nfWmW4nyU4Ebtn24cAWhixR19PetILPnvdy1fndYsw0egvgHH/d1NAumZXihA3nK4ftSjIrJl3xqtNd1DBCQfaLndOb8ALiHAjD8fvPMypZg5sMaxxcI6vLrVFoGOjSjwZIihfL8kFc2Q==";

const char* szB= "0MqarK6b41IXgoBmGzfhjFtPABBvsEtw4E5pEpggOkEzx5np+GB4MnFj63T7FmlKkhoT1KrfD7HW/8pY+rqKS1lojQNZVuQcAjLtFqbByoVfJ3d5V7wJ6z9mbqGBGZtVYDqkmr29SRK1I+M+i4FHwtozDEMtYjUXickmUWb8AGxPB3ftBnIM9fDdN2kWLZFXLsSEzzt1gGP5IVIBUWq5n9+m5SIerzzwkAzB/SwQPI9Nci07B+aIvFe5I01jx/lKSGId5GNgwKDqLkLcr3JiiPTDkznNR4HOqfl/B0N1f4yl186NJeRkcPYfGNyczmMZHtJ/tlkN05I9u8MLei8MYQ==";


// -----------------------------------------------------------------------------


// pad character is '='
static const char* s_transChar= 
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const byte s_revTrans[80]= {
    62,  0,  0,  0, 63,
    52, 53, 54, 55, 56,
    57, 58, 59, 60, 61,
     0,  0,  0,  0,  0,
     0,  0,  0,  1,  2,
     3,  4,  5,  6,  7,
     8,  9, 10, 11, 12,
    13, 14, 15, 16, 17,
    18, 19, 20, 21, 22,
    23, 24, 25,  0,  0,
     0,  0,  0,  0, 26,
    27, 28, 29, 30, 31,
    32, 33, 34, 35, 36,
    37, 38, 39, 40, 41,
    42, 43, 44, 45, 46,
    47, 48, 49, 50, 51,
};


inline bool whitespace(char b)
{
    return b==' ' || b=='\t' || b=='\r' || b=='\n';
}

inline int numbytesfromBase64string(int nc)
{
    return (6*nc+NBITSINBYTE-1)/NBITSINBYTE;
}


inline int numbase64charsfrombytes(int nb)
{
    return (NBITSINBYTE*nb+5)/6;
}


inline byte b64value(char a)
{
    if(a>='A'&&a<='Z')
        return (byte) a-'A';
    if(a>='a'&&a<='z')
        return (byte) a-'a'+26;
    if(a>='0'&&a<='9')
        return (byte) a-'0'+52;
    if(a=='+')
        return 0x3e;
    if(a=='/')
        return 0x3f;
    return 0xff;  // error
}


// -----------------------------------------------------------------------------


bool AtoBase64(int inLen, const byte* pbIn, int* poutLen, char* szOut, bool fDirFwd)
//
//      Lengths are in characters
//
{
    int             numOut= ((inLen*4)+2)/3;
    int             i= 0;
    int             a, b, c, d;
    const byte*     pbC;

    // enough room?
    if(numOut>*poutLen)
        return false;

    if(fDirFwd) {
        pbC= pbIn+inLen-1;
        while(inLen>2) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC-1)>>4)&0xf);
            c= ((*(pbC-1)&0xf)<<2) | ((*(pbC-2)>>6)&0x3);
            d= (*(pbC-2)&0x3f);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= s_transChar[c];
            szOut[i++]= s_transChar[d];
            pbC-= 3;
            inLen-= 3;
        }
        // 8 bits left
        if(inLen==1) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC-1)>>4)&0xf);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= '=';
            szOut[i++]= '=';
        }
        // 16 bits left
        if(inLen==2) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC-1)>>4)&0xf);
            c= ((*(pbC-1)&0xf)<<2);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= s_transChar[c];
            szOut[i++]= '=';
        }
    }
    else {
        pbC= pbIn;
        while(inLen>2) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC+1)>>4)&0xf);
            c= ((*(pbC+1)&0xf)<<2) | ((*(pbC+2)>>6)&0x3);
            d= (*(pbC+2)&0x3f);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= s_transChar[c];
            szOut[i++]= s_transChar[d];
            pbC+= 3;
            inLen-= 3;
        }
        // 8 bits left
        if(inLen==1) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC+1)>>4)&0xf);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= '=';
            szOut[i++]= '=';
        }
        // 16 bits left
        if(inLen==2) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC+1)>>4)&0xf);
            c= ((*(pbC+1)&0xf)<<2);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= s_transChar[c];
            szOut[i++]= '=';
        }
    }
    *poutLen= i;
    szOut[i++]= 0;
    return true;
}


bool AfromBase64(int inLen, const char* szIn, int* poutLen, unsigned char* puOut, bool fDirFwd= true)
//
//      Lengths are in characters
//
{
    int             numOut= ((inLen*3)+3)/4;
    unsigned char*  puW;
    unsigned char   a,b,c,d;
    int             numLeft= inLen;

    if(inLen>2 && *(szIn+inLen-1)=='=')
        numOut--;
    if(inLen>2 && *(szIn+inLen-2)=='=')
        numOut--;
    puW= puOut+numOut-1;

    // enough room?
    if(numOut>*poutLen) {
        printf("NO ROOM %d %d\n", numOut, *poutLen);
        return false;
    }

    while(numLeft>3) {
        while(whitespace(*szIn) && numLeft>0) {
            szIn++; numLeft--;
        }
        if(*szIn<43 || *szIn>122) {
            return false;
        }
        a= s_revTrans[*szIn-43];
        szIn++; numLeft--;
        while(whitespace(*szIn) && numLeft>0) {
            szIn++; numLeft--;
        }
        if(*szIn<43 || *szIn>122) {
            return false;
        }
        b= s_revTrans[*szIn-43];
        szIn++; numLeft--;
        while(whitespace(*szIn) && numLeft>0) {
            szIn++; numLeft--;
        }
        if(*szIn=='=') {
            if(!fDirFwd) {
                *(puOut)= (a<<2) | (b>>4);
                puOut+= 1;
            }
            else {
                *(puW)= (a<<2) | (b>>4);
                puW-= 1;
            }
            numLeft-= 2;
            continue;
        }
        if(*szIn<43 || *szIn>122) {
            return false;
        }
        c= s_revTrans[*szIn-43];
        szIn++; numLeft--;
        while(whitespace(*szIn) && numLeft>0) {
            szIn++; numLeft--;
        }
        if(*szIn=='=') {
            if(!fDirFwd) {
                *(puOut)= (a<<2) | (b>>4);
                *(puOut+1)= ((b&0xf)<<4) | (c>>2);
                puOut+= 2;
            }
            else {
                *(puW)= (a<<2) | (b>>4);
                *(puW-1)= ((b&0xf)<<4) | (c>>2);
                puW-= 2;
            }
            numLeft-= 1;
            continue;
        }
        if(*szIn<43 || *szIn>122) {
            return false;
        }
        d= s_revTrans[*szIn-43];
        szIn++; numLeft--;
        if(!fDirFwd) {
            *(puOut)= (a<<2) | (b>>4);
            *(puOut+1)= ((b&0xf)<<4) | (c>>2);
            *(puOut+2)= ((c&0x3)<<6) | d;
            puOut+= 3;
        }
        else {
            *(puW)= (a<<2) | (b>>4);
            *(puW-1)= ((b&0xf)<<4) | (c>>2);
            *(puW-2)= ((c&0x3)<<6) | d;
            puW-= 3;
        }
    }

    while(whitespace(*szIn) && numLeft>0) {
        szIn++; numLeft--;
        }
    if(numLeft>0) {
        printf("fail at numLeft\n");
        return false;
    }

    *poutLen= numOut;
    return true;
}




// -----------------------------------------------------------------------------


bool toBase64(int inlen, const byte* in, int* poutlen, char* szout, bool dir=true)
{
    int     numout= numbase64charsfrombytes(inlen);
    
    if(numout>*poutlen)
        return false;

    int         n= inlen;
    int         a, b, c, d;
    const byte* pb;

    // s_transChar
    if(dir) {
        // scan from high order byte to low
        // 24 bit chunks
        pb= in+inlen-1;     // start at high order byte (eg-on little endian machine)
        while(n>2) {
            a= ((*pb)>>2)&0x3f;
            b= (((*pb)&0x3)<<4)|((*(pb-1)>>4)&0xf);
            c= (((*(pb-1))&0xf)<<2)|((*(pb-2)>>6)&0x3);
            d= (*(pb-2))&0x3f;
            *(szout++)= s_transChar[a];
            *(szout++)= s_transChar[b];
            *(szout++)= s_transChar[c];
            *(szout++)= s_transChar[d];
            n-= 3;
            pb-= 3;
        }
        // 16 bits left
        if(n==2) {
            a= ((*pb)>>2)&0x3f;
            b= (((*pb)&0x3)<<4)|((*(pb-1)>>4)&0xf);
            c= (((*(pb-1))&0xf)<<2);
            *(szout++)= s_transChar[a];
            *(szout++)= s_transChar[b];
            *(szout++)= s_transChar[c];
            *(szout++)= '=';
            n= 0;
        }
        // 8 bits left
        if(n==1) {
            a= ((*pb)>>2)&0x3f;
            b= (((*pb)&0x3)<<4)|((*(pb-1)>>4)&0xf);
            *(szout++)= s_transChar[a];
            *(szout++)= s_transChar[b];
            *(szout++)= '=';
            *(szout++)= '=';
            n= 0;
        }
    }
    else {
        // scan from low order byte to high
        // 24 bit chunks
        pb= in;
        while(n>2) {
            a= ((*pb)>>2)&0x3f;
            b= (((*pb)&0x3)<<4)|((*(pb+1)>>4)&0xf);
            c= (((*(pb+1))&0xf)<<2)|((*(pb+2)>>6)&0x3);
            d= (*(pb+2))&0x3f;
            *(szout++)= s_transChar[a];
            *(szout++)= s_transChar[b];
            *(szout++)= s_transChar[c];
            *(szout++)= s_transChar[d];
            n-= 3;
            pb+= 3;
        }
        // 16 bits left
        if(n==2) {
            a= ((*pb)>>2)&0x3f;
            b= (((*pb)&0x3)<<4)|((*(pb+1)>>4)&0xf);
            c= (((*(pb+1))&0xf)<<2);
            *(szout++)= s_transChar[a];
            *(szout++)= s_transChar[b];
            *(szout++)= s_transChar[c];
            *(szout++)= '=';
            n= 0;
        }
        // 8 bits left
        if(n==1) {
            a= ((*pb)>>2)&0x3f;
            b= (((*pb)&0x3)<<4)|((*(pb+1)>>4)&0xf);
            *(szout++)= s_transChar[a];
            *(szout++)= s_transChar[b];
            *(szout++)= '=';
            *(szout++)= '=';
            n= 0;
        }
    }
    *szout= 0;
    *poutlen= numout;
    return true;
}


bool fromBase64(int inlen, const char* szin, int* poutlen, byte* out, bool dir=true)
{
    int     numout= numbytesfromBase64string(inlen);

    if(inlen<4 || (inlen%4)!=0)
        return false;

    // does padding affect output length?
    if(*(szin+inlen-1)=='=')
        numout--;
    if(*(szin+inlen-2)=='=')
        numout--;

    if(numout>*poutlen)
        return false;

    const char* p= szin;
    byte*   pb= out;
    byte    a, b, c, d;
    if(dir) {
        pb+= numout-1;
        while(*p!='\0') {
            a= b64value(*p++);
            if(a==0xff)
                return false;
            b= b64value(*p++);
            if(b==0xff)
                return false;
            if(*(p+1)=='=') {
                *pb--= a<<2|b>>4;
                if(*p!='=') {
                    c= b64value(*p++);
                    if(c==0xff)
                        return false;
printf("a, b, c: %02x %02x %02x\n", (int)a,(int)b, (int)c);
                    *pb--= b<<4|(c>>2);  // changed from c to c>>2
                }
                break;
            }
            c= b64value(*p++);
            if(c==0xff)
                return false;
            d= b64value(*p++);
            if(d==0xff)
                return false;
printf("a, b, c, d: %02x %02x %02x %02x\n", (int)a,(int)b,(int)c,(int)d);
            *pb--= a<<2|(b>>4);
            *pb--= b<<4|(c>>2);
            *pb--= c<<6|d; 
        }
    }
    else {
        while(*p!='\0') {
            a= b64value(*p++);
            if(a==0xff)
                return false;
            b= b64value(*p++);
            if(b==0xff)
                return false;
            if(*(p+1)=='=') {
                *pb++= a<<2|b>>4;
                if(*p!='=') {
                    c= b64value(*p++);
                    if(c==0xff)
                        return false;
                    *pb++= b<<4|c>>2;
                }
                break;
            }
            c= b64value(*p++);
            if(c==0xff)
                return false;
            d= b64value(*p++);
            if(d==0xff)
                return false;
            *pb++= a<<2|(b>>4);
            *pb++= b<<4|(c>>2);
            *pb++= c<<6|d;
        }
    }

    *poutlen= numout;
    return true;
}


// -----------------------------------------------------------------------------


void PrintBytes(int n, byte* rgb)
{
    for(int j=0; j<n;j++)
        printf("%x", rgb[j]);
    printf("\n");
}


int main()
{
    byte    bytebuf[4096];
    char    buf[4096];
    byte    bytebuf2[4096];
    int     i, k, n, m;
    bool    fRet= true;

#if 1
    m= 4096;
    printf("szA: %s\n", szA);
    if(!AfromBase64(strlen(szA), szA, &m, bytebuf, true)) {
        printf("Afrombase64 fails %s\n", buf);
        return 1;
    }
    PrintBytes(m, bytebuf);
    m= 4096;
    printf("szA: %s\n", szA);
    if(!fromBase64(strlen(szA), szA, &m, bytebuf2, true)) {
        printf("frombase64 fails %s\n", buf);
        return 1;
    }
    PrintBytes(m, bytebuf2);
    if(memcmp(bytebuf, bytebuf2, m)==0)
        printf("MATCH\n");
    else
        printf("NO MATCH\n");
    m= 4096;
    printf("szB: %s\n", szB);
    if(!AfromBase64(strlen(szB), szB, &m, bytebuf, true)) {
        printf("Afrombase64 fails %s\n", buf);
        return 1;
    }
    PrintBytes(m, bytebuf);
    m= 4096;
    printf("szB: %s\n", szB);
    if(!fromBase64(strlen(szB), szB, &m, bytebuf2, true)) {
        printf("frombase64 fails %s\n", buf);
        return 1;
    }
    PrintBytes(m, bytebuf2);
    if(memcmp(bytebuf, bytebuf2, m)==0)
        printf("MATCH\n");
    else
        printf("NO MATCH\n");
#else
    for(i=0; i<80; i++) {
        bytebuf[i]= (byte)i;
        k= i+1;

        printf("\n\n%d bytes\noriginal: ", k);
        PrintBytes(k, bytebuf);
        printf("forward, old\n");
        n= 256;
        if(!AtoBase64(k, bytebuf, &n, buf, true)) {
            printf("tobase64 fails\n");
            return 1;
        }
        m= 128;
        if(!AfromBase64(strlen(buf), buf, &m, bytebuf2, true)) {
            printf("Afrombase64 fails %s\n", buf);
            return 1;
        }
        printf("Translated old: ");
        PrintBytes(m, bytebuf2);
        if(m==k && memcmp(bytebuf, bytebuf2, m)==0) {
            printf("\t %d %d, match %s\n", n, m, buf);
        }
        else {
            printf("\t %d %d, no match %s\n", n, m, buf);
            fRet= false;
        }
        printf("forward, new\n");
        n= 256;
        if(!toBase64(k, bytebuf, &n, buf, true)) {
            printf("tobase64 fails\n");
            return 1;
        }
        m= 128;
        if(!fromBase64(strlen(buf), buf, &m, bytebuf2, true)) {
            printf("frombase64 fails\n");
            return 1;
        }
        printf("Translated new: ");
        PrintBytes(m, bytebuf2);
        if(m==k && memcmp(bytebuf, bytebuf2, k)==0) {
            printf("\t %d %d, match %s\n", n, m, buf);
        }
        else {
            printf("\t %d %d, no match %s\n", n, m, buf);
            fRet= false;
        }

        printf("backward, old\n");
        n= 256;
        if(!AtoBase64(k, bytebuf, &n, buf, false)) {
            printf("tobase64 fails\n");
            return 1;
        }
        printf("Translated old: ");
        PrintBytes(m, bytebuf2);
        m= 128;
        if(!AfromBase64(strlen(buf), buf, &m, bytebuf2, false)) {
            printf("Afrombase64 fails\n");
            return 1;
        }
        if(m==k && memcmp(bytebuf, bytebuf2, k)==0) {
            printf("\t %d %d, match %s\n", n, m, buf);
        }
        else {
            printf("\t %d %d, no match %s\n", n, m, buf);
            fRet= false;
        }
        printf("backward, new\n");
        n= 256;
        if(!toBase64(k, bytebuf, &n, buf, false)) {
            printf("tobase64 fails\n");
            return 1;
        }
        m= 128;
        if(!fromBase64(strlen(buf), buf, &m, bytebuf2, false)) {
            printf("frombase64 fails\n");
            return 1;
        }
        printf("Translated new: ");
        PrintBytes(m, bytebuf2);
        if(m==k && memcmp(bytebuf, bytebuf2, k)==0) {
            printf("\t %d %d, match %s\n", n, m, buf);
        }
        else {
            printf("\t %d %d, no match %s\n", n, m, buf);
            fRet= false;
        }
    }

    if(fRet)
        printf("\nAll tests PASSED\n");
    else
        printf("\nSome tests FAILED\n");
#endif
    return 0;
}


// -----------------------------------------------------------------------------


