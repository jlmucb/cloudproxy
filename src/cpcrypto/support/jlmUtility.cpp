//
//  File: jlmUtility.cpp
//  Description: Utility classes (like lists)
//
//  Copyright (c) 2011, John Manferdelli.  All rights reserved.
//  Copyright (c) 2011, Intel Corporation. Some contributions
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//    Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the disclaimer below.
//    Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the disclaimer below in the
//      documentation and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
//  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
//  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
//  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

// ------------------------------------------------------------------------------

#include "common.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "tinyxml.h"
#include "sha256.h"
#include "keys.h"
#include "bignum.h"
#include "jlmUtility.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

// -------------------------------------------------------------------

void revmemcpy(byte* pTo, byte* pFrom, int len) {
  int i;

  for (i = 0; i < len; i++) {
    pTo[i] = pFrom[len - 1 - i];
  }
}

bool SafeStringAppend(char** pszCur, const char* szToAppend, int* piLeft) {
  if (pszCur == NULL || szToAppend == NULL) return false;
  char* szCur = *pszCur;
  int n = strlen(szToAppend);
  if (n >= *piLeft) return false;
  strcpy(szCur, szToAppend);
  *pszCur += n;
  *piLeft -= n;
  return true;
}

char* canonicalize(TiXmlNode* pNode) {
  TiXmlPrinter printer;

  pNode->Accept(&printer);
  const char* szDoc = printer.CStr();
  if (szDoc == NULL) return NULL;
  return strdup(szDoc);
}

void printIndent(const char* szItem, int indent, bool fEnd) {
  int i;

  for (i = 0; i < indent; i++) {
    fprintf(g_logFile, "  ");
  }
  if (fEnd)
    fprintf(g_logFile, "/%s\n", szItem);
  else
    fprintf(g_logFile, "%s\n", szItem);
}

void Explore(TiXmlNode* pNode, int indent) {
  while (pNode) {
    if (pNode->Type() == TiXmlNode::TINYXML_ELEMENT) {
      printIndent(((TiXmlElement*)pNode)->Value(), indent, false);
    }
    Explore(pNode->FirstChild(), indent + 1);
    if (pNode->Type() == TiXmlNode::TINYXML_ELEMENT) {
      printIndent(((TiXmlElement*)pNode)->Value(), indent, true);
    }
    pNode = pNode->NextSibling();
  }

  return;
}

TiXmlNode* Search(TiXmlNode* pNode, const char* szElementName) {
  TiXmlNode* pNode1;

  while (pNode) {
    if (pNode->Type() == TiXmlNode::TINYXML_ELEMENT) {
      if (strcmp(((TiXmlElement*)pNode)->Value(), szElementName) == 0) {
        return pNode;
      }
    }
    pNode1 = Search(pNode->FirstChild(), szElementName);
    if (pNode1 != NULL) return pNode1;
    pNode = pNode->NextSibling();
  }

  return NULL;
}

bool testCanonical(const char* szInFile, const char* szElementName) {
  TiXmlDocument doc;

  if (szInFile == NULL || szElementName == NULL) {
    fprintf(g_logFile, "Absent file or element\n");
    return false;
  }
  fprintf(g_logFile, "testCanonical(%s, %s)\n", szInFile, szElementName);
  if (!doc.LoadFile(szInFile)) {
    fprintf(g_logFile, "Cannot Load %s\n", szInFile);
    return false;
  }

  TiXmlNode* pNode = (TiXmlNode*)doc.RootElement();
  fprintf(g_logFile, "\nTree:\n");
  Explore(pNode, 0);
  fprintf(g_logFile, "\n\n");
  TiXmlNode* pNode1 = Search(pNode, szElementName);
  if (pNode1 != NULL) {
    fprintf(g_logFile, "Found %s\n\n", szElementName);
    char* szStr = canonicalize(pNode1);
    if (szStr) fprintf(g_logFile, "%s\n", szStr);
  } else {
    fprintf(g_logFile, "Can't find %s node\n", szElementName);
  }
  return true;
}

inline char toHexfromVal(byte a) {
  if (a >= 10) return (char)(a - 10 + 'a');
  return (char)(a + '0');
}

inline byte fromHextoVal(char a, char b) {
  byte x = 0;

  if (a >= 'a' && a <= 'f')
    x = (((byte)(a - 'a') + 10) & 0xf) << 4;
  else if (a >= 'A' && a <= 'F')
    x = (((byte)(a - 'A') + 10) & 0xf) << 4;
  else
    x = (((byte)(a - '0')) & 0xf) << 4;

  if (b >= 'a' && b <= 'f')
    x |= ((byte)(b - 'a') + 10) & 0xf;
  else if (b >= 'A' && b <= 'F')
    x |= ((byte)(b - 'A') + 10) & 0xf;
  else
    x |= ((byte)(b - '0')) & 0xf;

  return x;
}

int ConvertToHexString(int sizeBuf, byte* rgbBuf, int sizeOut, char* szOut) {
  byte* puIn = rgbBuf;
  char a, b;
  byte c;
  int n = 2 * sizeBuf;
  int j = n;

  //  Reverse order (most significant hex digit goes in szOut[0])
  if (n > sizeOut) return -1;
  szOut[n--] = '\0';
  for (int i = 0; i < sizeBuf; i++) {
    c = *(puIn++);
    a = (char)(c >> 4) & 0xf;
    b = (char)(c & 0xf);
    szOut[n--] = toHexfromVal(b);
    szOut[n--] = toHexfromVal(a);
  }
  return j;
}

int ConvertFromHexString(const char* szIn, int sizeOut, byte* rgbBuf) {
  char a, b;
  int j = 0;
  int n = strlen(szIn);
  int m;

  j = (n + 1) / 2;
  if (j > sizeOut) return -1;
  m = j - 1;

  if (n & 1) {  // n  is odd
    b = *(szIn++);
    rgbBuf[m--] = fromHextoVal('0', b);
  }
  while (*szIn != 0) {
    a = *(szIn++);
    b = *(szIn++);
    if (a == 0 || b == 0) break;
    rgbBuf[m--] = fromHextoVal(a, b);
  }
  return j;
}

bool Sha256Hash(int sizeIn, byte* pIn, int* piOut, byte* pOut) {
  Sha256 oHash;

  if (*piOut < SHA256_DIGESTSIZE_BYTES) return false;

  oHash.Init();
  oHash.Update(pIn, sizeIn);
  oHash.Final();
  oHash.GetDigest(pOut);

  return true;
}

bool getBlobfromFile(const char* szFile, byte* buf, int* psize) {
  if (szFile == NULL) return false;

  int iRead = open(szFile, O_RDONLY);
  if (iRead < 0) {
    return false;
  }

  int n = read(iRead, buf, *psize);
  if (n < 0) {
    close(iRead);
    return false;
  }
  *psize = n;
  close(iRead);
  return true;
}

bool saveBlobtoFile(const char* szFile, byte* buf, int size) {
  if (szFile == NULL) return false;
  int iWrite = open(szFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (iWrite < 0) return false;
  ssize_t result = write(iWrite, buf, size);
  UNUSEDVAR(result);
  close(iWrite);
  return true;
}

char* readandstoreString(const char* szFile) {
  int n;
  struct stat statBlock;
  char* szString = NULL;

  if (szFile == NULL) {
    fprintf(g_logFile, "Error: null file namse\n");
    return NULL;
  }
  int iRead = open(szFile, O_RDONLY);
  if (iRead < 0) {
    fprintf(g_logFile, "Can't open input file %s\n", szFile);
    return NULL;
  }

  if (stat(szFile, &statBlock) < 0) {
    fprintf(g_logFile, "Can't stat input file\n");
    return NULL;
  }

  int iFileSize = statBlock.st_size;
  szString = (char*)malloc(iFileSize + 1);
  if (szString == NULL) {
    fprintf(g_logFile, "Can't alloc string in readandstoreString\n");
    return NULL;
  }
  szString[iFileSize] = 0;

  n = read(iRead, szString, iFileSize);
  if (n != iFileSize) {
    fprintf(g_logFile, "File size mismatch in readandstoreString\n");
    free(szString);
    return NULL;
  }
  close(iRead);

  return szString;
}

char* gmTimetoUTCstring(tm* pt) {
  char szTimeBuf[128];

  sprintf(szTimeBuf, "%04d-%02d-%02dZ%02d:%02d.%02d", pt->tm_year + 1900,
          pt->tm_mon + 1, pt->tm_mday, pt->tm_hour, pt->tm_min, pt->tm_sec);
  return strdup(szTimeBuf);
}

bool UTCtogmTime(const char* szTime, tm* pt) {
  int year, month, day, hour, minutes, secs;

  sscanf(szTime, "%04d-%02d-%02dZ%02d:%02d.%02d", &year, &month, &day, &hour,
         &minutes, &secs);

  pt->tm_year = year - 1900;
  pt->tm_mon = month - 1;
  pt->tm_mday = day;
  pt->tm_hour = hour;
  pt->tm_min = minutes;
  pt->tm_sec = secs;
  return true;
}

char* canonicalizeXML(const char* szXML) {
  TiXmlDocument doc;

  if (!doc.Parse(szXML)) return NULL;
  TiXmlElement* pRootElement = doc.RootElement();
  if (pRootElement == NULL) return NULL;
  return canonicalize((TiXmlNode*)pRootElement);
}

// ----------------------------------------------------------------------------
