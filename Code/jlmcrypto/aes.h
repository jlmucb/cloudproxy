//
//  File: aes.h
//  Desciption: aes object defines
//
//
// @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
// @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
// @author Paulo Barreto <paulo.barreto@terra.com.br>
//
// This code is hereby placed in the public domain.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
// OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
// BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
// OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

// Modifications subject to:
//
//  Copyright (c) 2011, John Manferdelli.  All rights reserved.
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


// ------------------------------------------------------------------------


#include <stdlib.h>  // for _lrotl and _lrotr

//  This module contains the low-level AES encryption routines.
//  Derived from public domain sources and modified for usage in the NT
//  programming environment.
//
//      Modified by John Manferdelli from a public domain version by:
//              Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
//              Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
//              Paulo Barreto <paulo.barreto@terra.com.br>
//
//  Note:  AES object can be in Enc mode or Dec mode but not both simultaneously
//


// ------------------------------------------------------------------------

#ifndef _AES_H_
#define _AES_H_

#include "jlmTypes.h"
#include "string.h"

#define  MAXKC  (256/32)
#define  MAXKB  (256/8)
#define  MAXNR  14


class aes {
private:
    int     m_Nr;                   // number of rounds (10 only for now)
    u32     m_rk[4*(MAXNR+1)+1];    // round keys
public:
    aes();
    aes(int nr);
    ~aes();

    int     KeySetupEnc(const byte key[16], int nbits);
    int     KeySetupDec(const byte key[16], int nbits);
    void    Encrypt(const byte pt[16], byte ct[16]);
    void    Decrypt(const byte ct[16], byte pt[16]);
    void    CleanKeys();
};
#endif  // _AES_H_


// ------------------------------------------------------------------------

