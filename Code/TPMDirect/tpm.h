/*
 * tpm.h: TPM-related support functions
 *
 * Copyright (c) 2006-2009, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __TPM_H__
#define __TPM_H__

#define TPM_LOCALITY_BASE             0xfed40000
#define NR_TPM_LOCALITY_PAGES         ((TPM_LOCALITY_1 - TPM_LOCALITY_0) >> \
                                       PAGE_SHIFT)

#define TPM_LOCALITY_0                TPM_LOCALITY_BASE
#define TPM_LOCALITY_1                (TPM_LOCALITY_BASE | 0x1000)
#define TPM_LOCALITY_2                (TPM_LOCALITY_BASE | 0x2000)
#define TPM_LOCALITY_3                (TPM_LOCALITY_BASE | 0x3000)
#define TPM_LOCALITY_4                (TPM_LOCALITY_BASE | 0x4000)

#define TPM_LOCALITY_BASE_N(n)        (TPM_LOCALITY_BASE | ((n) << 12))
#define TPM_NR_LOCALITIES             5

/*
 * return code:
 * The TPM has five types of return code. One indicates successful operation
 * and four indicate failure.
 * TPM_SUCCESS (00000000) indicates successful execution.
 * The failure reports are:
 *      TPM defined fatal errors (00000001 to 000003FF)
 *      vendor defined fatal errors (00000400 to 000007FF)
 *      TPM defined non-fatal errors (00000800 to 00000BFF)
 *      vendor defined non-fatal errors (00000C00 to 00000FFF).
 * Here only give definitions for a few commonly used return code.
 */
#define TPM_BASE                0x00000000
#define TPM_NON_FATAL           0x00000800
#define TPM_SUCCESS             TPM_BASE
#define TPM_BADINDEX            (TPM_BASE + 2)
#define TPM_BAD_PARAMETER       (TPM_BASE + 3)
#define TPM_DEACTIVATED         (TPM_BASE + 6)
#define TPM_DISABLED            (TPM_BASE + 7)
#define TPM_FAIL                (TPM_BASE + 9)
#define TPM_BAD_ORDINAL         (TPM_BASE + 10)
#define TPM_NOSPACE             (TPM_BASE + 17)
#define TPM_NOTRESETABLE        (TPM_BASE + 50)
#define TPM_NOTLOCAL            (TPM_BASE + 51)
#define TPM_BAD_LOCALITY        (TPM_BASE + 61)
#define TPM_READ_ONLY           (TPM_BASE + 62)
#define TPM_NOT_FULLWRITE       (TPM_BASE + 70)
#define TPM_RETRY               (TPM_BASE + TPM_NON_FATAL)

extern bool release_locality(uint32_t locality);
extern bool prepare_tpm(void);
extern bool is_tpm_ready(uint32_t locality);
extern uint32_t tpm_get_version(uint8_t *major, uint8_t *minor);

#define TPM_DIGEST_SIZE          20
typedef struct __packed {
    uint8_t     digest[TPM_DIGEST_SIZE];
} tpm_digest_t;
typedef tpm_digest_t tpm_pcr_value_t;

/*
 * specified as minimum cmd buffer size should be supported by all 1.2 TPM
 * device in the TCG_PCClientTPMSpecification_1-20_1-00_FINAL.pdf
 */
#define TPM_CMD_SIZE_MAX        768
#define TPM_RSP_SIZE_MAX        768

#define TPM_NR_PCRS             24

/*
 * tpm_pcr_read fetchs the current value of given PCR vai given locality.
 * locality     : TPM locality (0 - 4)
 * pcr          : PCR index (0 - 23)
 * out          : PCR value buffer, out parameter, should not be NULL
 * return       : TPM_SUCCESS for success, error code defined as TPM_xxx
 */
extern uint32_t tpm_pcr_read(uint32_t locality, uint32_t pcr,
                             tpm_pcr_value_t *pcr_value);

/*
 * tpm_pcr_extend extends data octets into given PCR via given locality,
 * and return the PCR value after extending if required.
 * locality     : TPM locality (0 - 4)
 * pcr          : PCR index (0 - 23)
 * in           : Hash value to be extended into PCR, should not be NULL
 * out          : Out buffer for PCR value after extending, may be NULL
 * return       : TPM_SUCCESS for success, error code defined as TPM_xxx
 */
extern uint32_t tpm_pcr_extend(uint32_t locality, uint32_t pcr,
                               const tpm_digest_t* in, tpm_pcr_value_t* out);

/* PCRs lower than 16 are not resetable */
#define TPM_PCR_RESETABLE_MIN           16

/*
 * tpm_pcr_reset resets given PCR via given locality.
 * locality     : TPM locality (0 - 4)
 * pcr          : PCR index (16 - 23)
 * return       : TPM_SUCCESS for success, error code defined as TPM_xxx
 */
extern uint32_t tpm_pcr_reset(uint32_t locality, uint32_t pcr);

#define TPM_NV_READ_VALUE_DATA_SIZE_MAX  (TPM_RSP_SIZE_MAX - 14)
typedef uint32_t tpm_nv_index_t;

/*
 * tpm_nv_read_value reads data from TPM NV ram in the given locality.
 * locality     : TPM locality (0 - 4)
 * index        : Predefined index for certain NV space
 * offset       : Start reading from offset given by this parameter.
 * data         : Out buffer for read data, should not be NULL
 * data_size    : As IN, give the size required to read, should not be NULL;
 *              : as OUT, return the size really read from TPM.
 *              : The largest nv data size can be read in a single call is
 *              : defined by TPM_NV_READ_VALUE_DATA_SIZE_MAX.
 * return       : TPM_SUCCESS for success, error code defined as TPM_xxx
 */
extern uint32_t tpm_nv_read_value(uint32_t locality, tpm_nv_index_t index,
                                  uint32_t offset, uint8_t *data,
                                  uint32_t *data_size);
#define TPM_NV_WRITE_VALUE_DATA_SIZE_MAX (TPM_CMD_SIZE_MAX - 22)

/*
 * tpm_nv_write_value writes data into TPM NV ram in the given locality.
 * locality     : TPM locality (0 - 4)
 * index        : Predefined index for certain NV space
 * offset       : Start writing from offset given by this parameter.
 * data         : Data to be written to TPM NV, should not be NULL
 * data_size    : The size of data to be written.
 *              : The largest nv data size can be written in a single call
 *              : is defined by TPM_NV_WRITE_VALUE_DATA_SIZE_MAX.
 * return       : TPM_SUCCESS for success, error code defined as TPM_xxx
 */
extern uint32_t tpm_nv_write_value(uint32_t locality, tpm_nv_index_t index,
                                   uint32_t offset, const uint8_t *data,
                                   uint32_t data_size);

typedef uint8_t tpm_locality_selection_t;
#define TPM_LOC_ZERO    0x01
#define TPM_LOC_ONE     0x02
#define TPM_LOC_TWO     0x04
#define TPM_LOC_THREE   0x08
#define TPM_LOC_FOUR    0x10
#define TPM_LOC_RSVD    0xE0

/*
 * tpm_seal seal given data (in_data[in_data_size]) to given pcrs
 * (pcr_indcs_create[pcr_nr_create]). The sealed data can only be unsealed
 * while the given pcrs (pcr_indcs_release[pcr_nr_release]) met given values
 * (pcr_values_release[pcr_nr_release]), and under one of the given release
 * locality (release_locsa).
 *
 * locality     : TPM locality (0 - 4)
 * release_locs : should be one or composition of TPM_LOC_ZERO to TPM_LOC_FOUR
 * pcr_nr_create: the number of pcrs which will be used as creation pcrs
 * pcr_indcs_create
 *              : an array of pcr indices, size is pcr_nr_create.
 * pcr_nr_release
 *              : the number of pcrs which will be used as release pcrs
 * pcr_indcs_release
 *              : an array of pcr indices, size is pcr_nr_release.
 * pcr_values_release
 *              : an array of pointers to pcr value, size is pcr_nr_release.
 * in_data_size : The size of data to be sealed.
 * in_data      : Data to be sealed, should not be NULL
 * sealed_data_size
 *              : [in] the size of prepared output buffer (sealed_data)
 *                [out] the size of sealed data blob
 * sealed_data  : [out] the buffer to receive sealed data blob. The buffer
 *                size should be large enough. For example, the sealed blob
 *                for 20-byte data will need buffer larger than 322 bytes.
 * return       : TPM_SUCCESS for success, error code defined as TPM_xxx
 *                TPM_NOSPACE for insufficient output buffer
 */
extern uint32_t tpm_seal(
                  uint32_t locality, tpm_locality_selection_t release_locs,
                  uint32_t pcr_nr_create, const uint8_t pcr_indcs_create[],
                  uint32_t pcr_nr_release, const uint8_t pcr_indcs_release[],
                  const tpm_pcr_value_t *pcr_values_release[],
                  uint32_t in_data_size, const uint8_t *in_data,
                  uint32_t *sealed_data_size, uint8_t *sealed_data);

/*
 * tpm_unseal unseal given data (sealed_data[sealed_data_size]) and return the
 * unsealed data in the given buffer (secret[*secret_size]).
 *
 * locality     : TPM locality (0 - 4)
 * sealed_data_size
 *              : the size of data to be unsealed.
 * sealed_data  : the data to be unsealed.
 * secret_size  : [in] the output buffer size.
 *                [out] the size of unsealed data
 * secret       : [out]unsealed data.
 * return       : TPM_SUCCESS for success, error code defined as TPM_xxx
 */
extern uint32_t tpm_unseal(
                  uint32_t locality,
                  uint32_t sealed_data_size, const uint8_t *sealed_data,
                  uint32_t *secret_size, uint8_t *secret);

/*
 * tpm_cmp_creation_pcrs compare the current values of specified PCRs with
 * the values of the creation PCRs in the sealed data
 *
 * return       : true if they match, false if they don't match
 */
extern bool tpm_cmp_creation_pcrs(
              uint32_t pcr_nr_create, const uint8_t pcr_indcs_create[],
              const tpm_pcr_value_t *pcr_values_create[],
              uint32_t sealed_data_size, uint8_t *sealed_data);

/*
 * tpm_get_nvindex_size use TPM_GETCAPABILITY cmd to  get the size of the NV
 * index given as index.
 *
 * return       : TPM_SUCCESS for success, error code defined as TPM_xxx
 */
extern uint32_t tpm_get_nvindex_size(uint32_t locality,
                                     tpm_nv_index_t index, uint32_t *size);

/*
 * tpm_save_state save all volatile state info into non-volatile memory.
 *
 * return       : TPM_SUCCESS for success, error code defined as TPM_xxx
 */
extern uint32_t tpm_save_state(uint32_t locality);


/*
 * tpm_get_random return TPM-generated random data.
 *
 * return       : TPM_SUCCESS for success, error code defined as TPM_xxx
 */
extern uint32_t tpm_get_random(uint32_t locality, uint8_t *random_data,
                               uint32_t *data_size);

#endif   /* __TPM_H__ */

