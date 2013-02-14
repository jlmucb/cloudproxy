//
//  File: canonical.cpp
//
//  Description: take xml in infile and canonicalize it to outfile
//
//  Copyright (c) 2011, Intel Corporation, incorporates contributions (c) 2007, John Manferdelli
//  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "tinyxml.h"


// ----------------------------------------------------------------------------


//  canonical -tinyxml inputfile outputfile


int main(int an, char** av)
{
    char*   szInFile= NULL;
    char*   szOutFile= NULL;
    char*   szAlgorithm= NULL;

    for(int i=0; i<an; i++) {
        if(strcmp(av[i], "-help")==0) {
            printf("\nUsage: canonical -tinyxml input-file output-file\n");
            return 0;
        }
        if(strcmp(av[i], "-tinyxml")==0) {
            if(an<(i+3)) {
                printf("Too few arguments -tinyxml input-file output-file\n");
                return 1;
            }
            szAlgorithm= av[i];
            szInFile= av[i+1];
            szOutFile= av[i+2];
            break;
        }
    }

    if(strcmp(szAlgorithm,"-tinyxml")!=0) {
        printf("Only -tinyxml supported\n");
        return 1;
    }

    if(szAlgorithm==NULL || szInFile==NULL || szOutFile==NULL) {
        printf("poorly specified files\n");
        return 1;
    }
    printf("%s %s %s\n", szAlgorithm, szInFile, szOutFile);

    TiXmlDocument* pDoc= new TiXmlDocument();
    if(pDoc==NULL) {
        printf("Cant get an Xml Document\n");
        return 1;
    }
    if(!pDoc->LoadFile(szInFile)) {
        printf("Cant load input file\n");
        return 1;
    }
    if(!pDoc->SaveFile(szOutFile)) {
        printf("Cant write output file\n");
        return 1;
    }

    return 0;
}


// ---------------------------------------------------------------------------------------



