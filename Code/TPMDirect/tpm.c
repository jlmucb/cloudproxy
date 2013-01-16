/*
 * tpm.c: TPM-related support functions
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <printk.h>
#include <misc.h>
#include <compiler.h>
#include <processor.h>
#include <io.h>
#include <string.h>
#include <tpm.h>
#include <sha1.h>

/* un-comment to enable detailed command tracing */
//#define TPM_TRACE

/* ~5 secs are required for Infineon that requires this, so leave some extra */
#define MAX_SAVESTATE_RETRIES       60

#define TPM_TAG_RQU_COMMAND         0x00C1
#define TPM_TAG_RQU_AUTH1_COMMAND   0x00C2
#define TPM_TAG_RQU_AUTH2_COMMAND   0x00C3
#define TPM_ORD_PCR_EXTEND          0x00000014
#define TPM_ORD_PCR_READ            0x00000015
#define TPM_ORD_PCR_RESET           0x000000C8
#define TPM_ORD_NV_READ_VALUE       0x000000CF
#define TPM_ORD_NV_WRITE_VALUE      0x000000CD
#define TPM_ORD_GET_CAPABILITY      0x00000065
#define TPM_ORD_SEAL                0x00000017
#define TPM_ORD_UNSEAL              0x00000018
#define TPM_ORD_OSAP                0x0000000B
#define TPM_ORD_OIAP                0x0000000A
#define TPM_ORD_SAVE_STATE          0x00000098
#define TPM_ORD_QUOTE2              0x0000003E
#define TPM_ORD_GET_RANDOM          0x00000046

#define TPM_TAG_PCR_INFO_LONG       0x0006
#define TPM_TAG_STORED_DATA12       0x0016

/*
 * TPM registers and data structures
 *
 * register values are offsets from each locality base
 * see {read,write}_tpm_reg() for data struct format
 */

/* TPM_ACCESS_x */
#define TPM_REG_ACCESS           0x00
typedef union {
    u8 _raw[1];                      /* 1-byte reg */
    struct __packed {
        u8 tpm_establishment   : 1;  /* RO, 0=T/OS has been established before */
        u8 request_use         : 1;  /* RW, 1=locality is requesting TPM use */
        u8 pending_request     : 1;  /* RO, 1=other locality is requesting
                                        TPM usage */
        u8 seize               : 1;  /* WO, 1=seize locality */
        u8 been_seized         : 1;  /* RW, 1=locality seized while active */
        u8 active_locality     : 1;  /* RW, 1=locality is active */
        u8 reserved            : 1;
        u8 tpm_reg_valid_sts   : 1;  /* RO, 1=other bits are valid */
    };
} tpm_reg_access_t;

/* TPM_STS_x */
#define TPM_REG_STS              0x18
typedef union {
    u8 _raw[3];                  /* 3-byte reg */
    struct __packed {
        u8 reserved1       : 1;
        u8 response_retry  : 1;  /* WO, 1=re-send response */
        u8 reserved2       : 1;
        u8 expect          : 1;  /* RO, 1=more data for command expected */
        u8 data_avail      : 1;  /* RO, 0=no more data for response */
        u8 tpm_go          : 1;  /* WO, 1=execute sent command */
        u8 command_ready   : 1;  /* RW, 1=TPM ready to receive new cmd */
        u8 sts_valid       : 1;  /* RO, 1=data_avail and expect bits are valid */
        u16 burst_count    : 16; /* RO, # read/writes bytes before wait */
    };
} tpm_reg_sts_t;


/* TPM_DATA_FIFO_x */
#define TPM_REG_DATA_FIFO        0x24
typedef union {
        byte _raw[1];                      /* 1-byte reg */
} tpm_reg_data_fifo_t;

/*
 * assumes that all reg types follow above format:
 *  -packed
 *  -member named '_raw' which is array whose size is that of data to read
 */
#define read_tpm_reg(locality, reg, pdata)      \
    _read_tpm_reg(locality, reg, (pdata)->_raw, sizeof(*(pdata)))

#define write_tpm_reg(locality, reg, pdata)     \
    _write_tpm_reg(locality, reg, (pdata)->_raw, sizeof(*(pdata)))


static void _read_tpm_reg(int locality, u32 reg, u8 *_raw, size_t size)
{
    for(size_t i= 0; i<size; i++)
        _raw[i]= readb((TPM_LOCALITY_BASE_N(locality)|reg)+i);
}

static void _write_tpm_reg(int locality, u32 reg, u8 *_raw, size_t size)
{
    for(size_t i= 0; i<size; i++)
        writeb((TPM_LOCALITY_BASE_N(locality)|reg)+i, _raw[i]);
}


/*
 * the following inline function reversely copy the bytes from 'in' to
 * 'out', the byte number to copy is given in count.
 */
#define reverse_copy(out, in, count) \
    _reverse_copy((byte *)(out), (byte *)(in), count)


static inline void _reverse_copy(byte *out, byte *in, u32 count)
{
    for(u32 i= 0; i<count; i++)
        out[i]= in[count-i-1];
}

#define TPM_VALIDATE_LOCALITY_TIME_OUT  0x100


static bool tpm_validate_locality(u32 locality)
{
    u32 i;
    tpm_reg_access_t reg_acc;

    for(i= TPM_VALIDATE_LOCALITY_TIME_OUT; i>0; i--) {
        /*
         * TCG spec defines reg_acc.tpm_reg_valid_sts bit to indicate whether
         * other bits of access reg are valid.(but this bit will also be 1
         * while this locality is not available, so check seize bit too)
         * It also defines that reading reg_acc.seize should always return 0
         */
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if(reg_acc.tpm_reg_valid_sts==1 && reg_acc.seize==0)
            return true;
        cpu_relax();
    }

    if(i<=0)
        printk("TPM: tpm_validate_locality timeout\n");

    return false;
}

#define TIMEOUT_UNIT    (0x100000 / 330) /* ~1ms, 1 tpm r/w need>330ns */
#define TIMEOUT_A       750  /* 750ms */
#define TIMEOUT_B       2000 /* 2s */
#define TIMEOUT_C       750  /* 750ms */
#define TIMEOUT_D       750  /* 750ms */

typedef struct __packed {
    u32 timeout_a;
    u32 timeout_b;
    u32 timeout_c;
    u32 timeout_d;
} tpm_timeout_t;

static tpm_timeout_t g_timeout= {
    TIMEOUT_A, TIMEOUT_B,
    TIMEOUT_C, TIMEOUT_D
};


#define TPM_ACTIVE_LOCALITY_TIME_OUT    \
          (TIMEOUT_UNIT * g_timeout.timeout_a)  /* according to spec */
#define TPM_CMD_READY_TIME_OUT          \
          (TIMEOUT_UNIT * g_timeout.timeout_b)  /* according to spec */
#define TPM_CMD_WRITE_TIME_OUT          \
          (TIMEOUT_UNIT * g_timeout.timeout_d)  /* let it long enough */
#define TPM_DATA_AVAIL_TIME_OUT         \
          (TIMEOUT_UNIT * g_timeout.timeout_c)  /* let it long enough */
#define TPM_RSP_READ_TIME_OUT           \
          (TIMEOUT_UNIT * g_timeout.timeout_d)  /* let it long enough */


static u32 tpm_wait_cmd_ready(u32 locality)
{
    u32                 i;
    tpm_reg_access_t    reg_acc;
    tpm_reg_sts_t       reg_sts;

    /* ensure the contents of the ACCESS register are valid */
    read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
#ifdef TPM_TRACE
    printk("TPM: Access reg content: 0x%02x\n", (u32)reg_acc._raw[0]);
#endif
    if(reg_acc.tpm_reg_valid_sts==0) {
        printk("TPM: Access reg not valid\n");
        return TPM_FAIL;
    }

    /* request access to the TPM from locality N */
    reg_acc._raw[0]= 0;
    reg_acc.request_use= 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    i= 0;
    do {
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if(reg_acc.active_locality==1)
            break;
        else
            cpu_relax();
        i++;
    } while(i<=TPM_ACTIVE_LOCALITY_TIME_OUT);

    if(i>TPM_ACTIVE_LOCALITY_TIME_OUT) {
        printk("TPM: access reg request use timeout\n");
        return TPM_FAIL;
    }

    /* ensure the TPM is ready to accept a command */
#ifdef TPM_TRACE
    printk("TPM: wait for cmd ready ");
#endif
    i= 0;
    do {
        /* write 1 to TPM_STS_x.commandReady to let TPM enter ready state */
        memset((void *)&reg_sts, 0, sizeof(reg_sts));
        reg_sts.command_ready= 1;
        write_tpm_reg(locality, TPM_REG_STS, &reg_sts);
        cpu_relax();

        /* then see if it has */
        read_tpm_reg(locality, TPM_REG_STS, &reg_sts);
#ifdef TPM_TRACE
        printk(".");
#endif
        if(reg_sts.command_ready==1)
            break;
        else
            cpu_relax();
        i++;
    } while(i<=TPM_CMD_READY_TIME_OUT);
#ifdef TPM_TRACE
    printk("\n");
#endif

    if(i>TPM_CMD_READY_TIME_OUT) {
        printk("TPM: status reg content: %02x %02x %02x\n",
               (u32)reg_sts._raw[0],
               (u32)reg_sts._raw[1],
               (u32)reg_sts._raw[2]);
        printk("TPM: tpm timeout for command_ready\n");
        goto RelinquishControl;
    }
    return TPM_SUCCESS;

RelinquishControl:
    /* deactivate current locality */
    reg_acc._raw[0]= 0;
    reg_acc.active_locality= 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    return TPM_FAIL;
}

/*
 *   locality : TPM locality (0-3)
 *   in       : All bytes for a single TPM command, including TAG, SIZE,
 *              ORDINAL, and other arguments. All data should be in big-endian
 *              style. The in MUST NOT be NULL, containing at least 10 bytes.
 *              0   1   2   3   4   5   6   7   8   9   10  ...
 *              -------------------------------------------------------------
 *             |TAG |    SIZE     |   ORDINAL   |   arguments ...
 *              -------------------------------------------------------------
 *   in_size  : The size of the whole command contained within the in buffer.
 *              It should equal to the SIZE contained in the in buffer.
 *   out      : All bytes of the TPM response to a single command. All data
 *              within it will be in big-endian style. The out MUST not be
 *              NULL, and will return at least 10 bytes.
 *              0   1   2   3   4   5   6   7   8   9   10  ...
 *              -------------------------------------------------------------
 *             |TAG |    SIZE     | RETURN CODE |   other data ...
 *              -------------------------------------------------------------
 *   out_size : In/out paramter. As in, it is the size of the out buffer;
 *              as out, it is the size of the response within the out buffer.
 *              The out_size MUST NOT be NULL.
 *   return   : 0= success; if not 0, it equal to the RETURN CODE in out buf.
 */
#define CMD_HEAD_SIZE           10
#define RSP_HEAD_SIZE           10
#define CMD_SIZE_OFFSET         2
#define CMD_ORD_OFFSET          6
#define RSP_SIZE_OFFSET         2
#define RSP_RST_OFFSET          6

static u32 tpm_write_cmd_fifo(u32 locality, byte *in, u32 in_size, 
                              byte *out, u32 *out_size)
{
    u32                 i, rsp_size, offset, ret;
    uint16_t            row_size;
    tpm_reg_access_t    reg_acc;
    tpm_reg_sts_t       reg_sts;

    if(locality >= TPM_NR_LOCALITIES) {
        printk("TPM: Invalid locality for tpm_write_cmd_fifo()\n");
        return TPM_BAD_PARAMETER;
    }
    if(in==NULL || out==NULL || out_size==NULL) {
        printk("TPM: Invalid parameter for tpm_write_cmd_fifo()\n");
        return TPM_BAD_PARAMETER;
    }
    if(in_size<CMD_HEAD_SIZE || *out_size<RSP_HEAD_SIZE) {
        printk("TPM: in/out buf size must be larger than 10 bytes\n");
        return TPM_BAD_PARAMETER;
    }

    if(!tpm_validate_locality(locality)) {
        printk("TPM: Locality %d is not open\n", locality);
        return TPM_FAIL;
    }

    ret= tpm_wait_cmd_ready(locality);
    if(ret!=TPM_SUCCESS)
        return ret;

#ifdef TPM_TRACE
    {
        printk("TPM: cmd size= %d\nTPM: cmd content: ", in_size);
        print_hex("TPM: \t", in, in_size);
    }
#endif

    /* write the command to the TPM FIFO */
    offset= 0;
    do {
        i= 0;
        do {
            read_tpm_reg(locality, TPM_REG_STS, &reg_sts);
            /* find out how many bytes the TPM can accept in a row */
            row_size= reg_sts.burst_count;
            if(row_size>0)
                break;
            else
                cpu_relax();
            i++;
        } while(i<=TPM_CMD_WRITE_TIME_OUT);
        if(i>TPM_CMD_WRITE_TIME_OUT) {
            printk("TPM: write cmd timeout\n");
            ret= TPM_FAIL;
            goto RelinquishControl;
        }

        for(; row_size>0 && offset<in_size; row_size--, offset++)
            write_tpm_reg(locality, TPM_REG_DATA_FIFO,
                          (tpm_reg_data_fifo_t *)&in[offset]);
    } while(offset<in_size);

    /* command has been written to the TPM, it is time to execute it. */
    memset(&reg_sts, 0,  sizeof(reg_sts));
    reg_sts.tpm_go= 1;
    write_tpm_reg(locality, TPM_REG_STS, &reg_sts);

    /* check for data available */
    i= 0;
    do {
        read_tpm_reg(locality,TPM_REG_STS, &reg_sts);
        if(reg_sts.sts_valid==1 && reg_sts.data_avail==1)
            break;
        else
            cpu_relax();
        i++;
    } while(i<=TPM_DATA_AVAIL_TIME_OUT);
    if(i>TPM_DATA_AVAIL_TIME_OUT) {
        printk("TPM: wait for data available timeout\n");
        ret= TPM_FAIL;
        goto RelinquishControl;
    }

    rsp_size= 0;
    offset= 0;
    do {
        /* find out how many bytes the TPM returned in a row */
        i= 0;
        do {
            read_tpm_reg(locality, TPM_REG_STS, &reg_sts);
            row_size= reg_sts.burst_count;
            if(row_size>0)
                break;
            else
                cpu_relax();
            i++;
        } while(i<=TPM_RSP_READ_TIME_OUT);
        if(i>TPM_RSP_READ_TIME_OUT) {
            printk("TPM: read rsp timeout\n");
            ret= TPM_FAIL;
            goto RelinquishControl;
        }

        for(; row_size>0 && offset<*out_size; row_size--, offset++) {
            if(offset<*out_size)
                read_tpm_reg(locality, TPM_REG_DATA_FIFO,
                             (tpm_reg_data_fifo_t *)&out[offset]);
            else {
                /* discard the responded bytes exceeding out buf size */
                tpm_reg_data_fifo_t discard;
                read_tpm_reg(locality, TPM_REG_DATA_FIFO,
                             (tpm_reg_data_fifo_t *)&discard);
            }

            /* get outgoing data size */
            if(offset==RSP_RST_OFFSET-1) {
                reverse_copy(&rsp_size, &out[RSP_SIZE_OFFSET],
                             sizeof(rsp_size));
            }
        }
    } while(offset<RSP_RST_OFFSET ||
              (offset<rsp_size && offset<*out_size));

    *out_size= (*out_size>rsp_size) ? rsp_size : *out_size;

    /* out buffer contains the complete outgoing data, get return code */
    reverse_copy(&ret, &out[RSP_RST_OFFSET], sizeof(ret));

#ifdef TPM_TRACE
    {
        printk("TPM: response size= %d\n", *out_size);
        printk("TPM: response content: ");
        print_hex("TPM: \t", out, *out_size);
    }
#endif

    memset(&reg_sts, 0, sizeof(reg_sts));
    reg_sts.command_ready= 1;
    write_tpm_reg(locality, TPM_REG_STS, &reg_sts);

RelinquishControl:
    /* deactivate current locality */
    reg_acc._raw[0]= 0;
    reg_acc.active_locality= 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    return ret;
}

/*
 * The _tpm_submit_cmd function comes with 2 global buffers: cmd_buf & rsp_buf.
 * Before calling, caller should fill cmd arguements into cmd_buf via
 * WRAPPER_IN_BUF macro. After calling, caller should fetch result from
 * rsp_buffer via WRAPPER_OUT_BUF macro.
 * cmd_buf content:
 *  0   1   2   3   4   5   6   7   8   9   10  ...
 * -------------------------------------------------------------
 *| TAG |    SIZE     |   ORDINAL   |   arguments ...
 * -------------------------------------------------------------
 * rsp_buf content:
 *  0   1   2   3   4   5   6   7   8   9   10  ...
 * -------------------------------------------------------------
 *| TAG |    SIZE     | RETURN CODE |   other data ...
 * -------------------------------------------------------------
 *
 *   locality : TPM locality (0-4)
 *   tag      : The TPM command tag
 *   cmd      : The TPM command ordinal
 *   arg_size : Size of argument data.
 *   out_size : IN/OUT paramter. The IN is the expected size of out data;
 *              the OUT is the size of output data within out buffer.
 *              The out_size MUST NOT be NULL.
 *   return   : TPM_SUCCESS for success, for other error code, refer to the .h
 */
static byte     cmd_buf[TPM_CMD_SIZE_MAX];
static byte     rsp_buf[TPM_RSP_SIZE_MAX];
#define WRAPPER_IN_BUF          (cmd_buf+CMD_HEAD_SIZE)
#define WRAPPER_OUT_BUF         (rsp_buf+RSP_HEAD_SIZE)
#define WRAPPER_IN_MAX_SIZE     (TPM_CMD_SIZE_MAX-CMD_HEAD_SIZE)
#define WRAPPER_OUT_MAX_SIZE    (TPM_RSP_SIZE_MAX-RSP_HEAD_SIZE)

static u32 _tpm_submit_cmd(u32 locality, uint16_t tag, u32 cmd,
                               u32 arg_size, u32 *out_size)
{
    u32    ret;
    u32    cmd_size, rsp_size= 0;

    if(out_size==NULL) {
        printk("TPM: invalid param for _tpm_submit_cmd()\n");
        return TPM_BAD_PARAMETER;
    }

    /*
     * real cmd size should add 10 more bytes:
     *      2 bytes for tag
     *      4 bytes for size
     *      4 bytes for ordinal
     */
    cmd_size= CMD_HEAD_SIZE+arg_size;

    if(cmd_size>TPM_CMD_SIZE_MAX) {
        printk("TPM: cmd exceeds the max supported size.\n");
        return TPM_BAD_PARAMETER;
    }

    /* copy tag, size & ordinal into buf in a reversed byte order */
    reverse_copy(cmd_buf, &tag, sizeof(tag));
    reverse_copy(cmd_buf+CMD_SIZE_OFFSET, &cmd_size, sizeof(cmd_size));
    reverse_copy(cmd_buf+CMD_ORD_OFFSET, &cmd, sizeof(cmd));

    rsp_size= RSP_HEAD_SIZE+*out_size;
    rsp_size= (rsp_size>TPM_RSP_SIZE_MAX) ? TPM_RSP_SIZE_MAX: rsp_size;
    ret= tpm_write_cmd_fifo(locality, cmd_buf, cmd_size, rsp_buf, &rsp_size);

    /*
     * should subtract 10 bytes from real response size:
     *      2 bytes for tag
     *      4 bytes for size
     *      4 bytes for return code
     */
    rsp_size-= (rsp_size>RSP_HEAD_SIZE) ? RSP_HEAD_SIZE : rsp_size;

    if(ret!=TPM_SUCCESS)
        return ret;

    if(*out_size==0 || rsp_size==0)
        *out_size= 0;
    else
        *out_size= (rsp_size<*out_size) ? rsp_size : *out_size;

    return ret;
}

static inline u32 tpm_submit_cmd(u32 locality, u32 cmd,
                                      u32 arg_size, u32 *out_size)
{
   return  _tpm_submit_cmd(locality, TPM_TAG_RQU_COMMAND, cmd,
                           arg_size, out_size);
}

static inline u32 tpm_submit_cmd_auth1(u32 locality, u32 cmd,
                                      u32 arg_size, u32 *out_size)
{
   return  _tpm_submit_cmd(locality, TPM_TAG_RQU_AUTH1_COMMAND, cmd,
                           arg_size, out_size);
}

static inline u32 tpm_submit_cmd_auth2(u32 locality, u32 cmd,
                                      u32 arg_size, u32 *out_size)
{
   return  _tpm_submit_cmd(locality, TPM_TAG_RQU_AUTH2_COMMAND, cmd,
                           arg_size, out_size);
}

u32 tpm_pcr_read(u32 locality, u32 pcr, tpm_pcr_value_t *out)
{
    u32 ret, out_size= sizeof(*out);

    if(out==NULL)
        return TPM_BAD_PARAMETER;
    if(pcr >= TPM_NR_PCRS)
        return TPM_BAD_PARAMETER;

    /* copy pcr into buf in reversed byte order */
    reverse_copy(WRAPPER_IN_BUF, &pcr, sizeof(pcr));

    ret= tpm_submit_cmd(locality, TPM_ORD_PCR_READ, sizeof(pcr), &out_size);

#ifdef TPM_TRACE
    printk("TPM: Pcr %d Read return value= %08X\n", pcr, ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: Pcr %d Read return value= %08X\n", pcr, ret);
        return ret;
    }

    if(out_size>sizeof(*out))
        out_size= sizeof(*out);
    memcpy((void *)out, WRAPPER_OUT_BUF, out_size);

#ifdef TPM_TRACE
    {
        printk("TPM: ");
        print_hex(NULL, out->digest, out_size);
    }
#endif

    return ret;
}

u32 tpm_pcr_extend(u32 locality, u32 pcr,
                        const tpm_digest_t* in, tpm_pcr_value_t* out)
{
    u32 ret, in_size= 0, out_size;

    if(in==NULL)
        return TPM_BAD_PARAMETER;
    if(pcr >= TPM_NR_PCRS)
        return TPM_BAD_PARAMETER;
    if(out==NULL)
        out_size= 0;
    else
        out_size= sizeof(*out);

    /* copy pcr into buf in reversed byte order, then copy in data */
    reverse_copy(WRAPPER_IN_BUF, &pcr, sizeof(pcr));
    in_size+= sizeof(pcr);
    memcpy(WRAPPER_IN_BUF+in_size, (void *)in, sizeof(*in));
    in_size+= sizeof(*in);

    ret= tpm_submit_cmd(locality, TPM_ORD_PCR_EXTEND, in_size, &out_size);

#ifdef TPM_TRACE
    printk("TPM: Pcr %d extend, return value= %08X\n", pcr, ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: Pcr %d extend, return value= %08X\n", pcr, ret);
        return ret;
    }

    if(out!=NULL && out_size>0) {
       out_size= (out_size>sizeof(*out)) ? sizeof(*out) : out_size;
       memcpy((void *)out, WRAPPER_OUT_BUF, out_size);
    }

#ifdef TPM_TRACE
    {
        printk("TPM: ");
        print_hex(NULL, out->digest, out_size);
    }
#endif

    return ret;
}

typedef struct __packed {
    uint16_t    size_of_select;
    byte     pcr_select[3];
} tpm_pcr_selection_t;

u32 tpm_pcr_reset(u32 locality, u32 pcr)
{
    u32 ret, in_size, out_size= 0;
    uint16_t size_of_select;
    tpm_pcr_selection_t pcr_sel= {0,{0,}};

    if(pcr >= TPM_NR_PCRS || pcr<TPM_PCR_RESETABLE_MIN)
        return TPM_BAD_PARAMETER;

    /* the pcr_sel.pcr_select[size_of_select-1] should not be 0 */
    size_of_select= pcr / 8+1;
    reverse_copy(&pcr_sel.size_of_select, &size_of_select,
                 sizeof(size_of_select));
    pcr_sel.pcr_select[pcr / 8]= 1 << (pcr % 8);

    in_size= sizeof(pcr_sel);
    memcpy(WRAPPER_IN_BUF, (void *)&pcr_sel, in_size);

    ret= tpm_submit_cmd(locality, TPM_ORD_PCR_RESET, in_size, &out_size);

    printk("TPM: Pcr %d reset, return value= %08X\n", pcr, ret);

    return ret;
}

u32 tpm_nv_read_value(u32 locality, tpm_nv_index_t index,
                           u32 offset, byte *data,
                           u32 *data_size)
{
    u32 ret, in_size= 0, out_size;

    if(data==NULL || data_size==NULL)
        return TPM_BAD_PARAMETER;
    if(*data_size==0)
        return TPM_BAD_PARAMETER;
    if(*data_size>TPM_NV_READ_VALUE_DATA_SIZE_MAX)
        *data_size= TPM_NV_READ_VALUE_DATA_SIZE_MAX;

    /* copy the index, offset and *data_size into buf in reversed byte order */
    reverse_copy(WRAPPER_IN_BUF, &index, sizeof(index));
    in_size+= sizeof(index);
    reverse_copy(WRAPPER_IN_BUF+in_size, &offset, sizeof(offset));
    in_size+= sizeof(offset);
    reverse_copy(WRAPPER_IN_BUF+in_size, data_size, sizeof(*data_size));
    in_size+= sizeof(*data_size);

    out_size= *data_size+sizeof(*data_size);
    ret= tpm_submit_cmd(locality, TPM_ORD_NV_READ_VALUE, in_size, &out_size);

#ifdef TPM_TRACE
    printk("TPM: read nv index %08x from offset %08x, return value= %08X\n",
           index, offset, ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: read nv index %08x offset %08x, return value= %08X\n",
               index, offset, ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk("TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    if(out_size<=sizeof(*data_size)) {
        *data_size= 0;
        return ret;
    }

    out_size-= sizeof(*data_size);
    reverse_copy(data_size, WRAPPER_OUT_BUF, sizeof(*data_size));
    *data_size= (*data_size>out_size) ? out_size : *data_size;
    if(*data_size>0)
        memcpy(data, WRAPPER_OUT_BUF+sizeof(*data_size), *data_size);

    return ret;
}

u32 tpm_nv_write_value(u32 locality, tpm_nv_index_t index,
                            u32 offset, const byte *data,
                            u32 data_size)
{
    u32 ret, in_size= 0, out_size= 0;

    if(data==NULL)
        return TPM_BAD_PARAMETER;
    if(data_size==0 || data_size>TPM_NV_WRITE_VALUE_DATA_SIZE_MAX)
        return TPM_BAD_PARAMETER;

    /* copy index, offset and *data_size into buf in reversed byte order */
    reverse_copy(WRAPPER_IN_BUF, &index, sizeof(index));
    in_size+= sizeof(index);
    reverse_copy(WRAPPER_IN_BUF+in_size, &offset, sizeof(offset));
    in_size+= sizeof(offset);
    reverse_copy(WRAPPER_IN_BUF+in_size, &data_size, sizeof(data_size));
    in_size+= sizeof(data_size);
    memcpy(WRAPPER_IN_BUF+in_size, data, data_size);
    in_size+= data_size;

    ret= tpm_submit_cmd(locality, TPM_ORD_NV_WRITE_VALUE,
                         in_size, &out_size);

#ifdef TPM_TRACE
    printk("TPM: write nv %08x, offset %08x, %08x bytes, return= %08X\n",
           index, offset, data_size, ret);
#endif
    if(ret!=TPM_SUCCESS)
        printk("TPM: write nv %08x, offset %08x, %08x bytes, return= %08X\n",
               index, offset, data_size, ret);

    return ret;
}

#define TPM_CAP_VERSION_VAL 0x1A

typedef uint16_t tpm_structure_tag_t;

typedef struct __packed {
   byte  major;
   byte  minor;
   byte  rev_major;
   byte  rev_minor;
} tpm_version_t;

typedef struct __packed {
    tpm_structure_tag_t tag;
    tpm_version_t       version;
    uint16_t            specLevel;
    byte             errataRev;
    byte             tpmVendorID[4];
    uint16_t            vendorSpecificSize;
    byte             vendorSpecific[];
} tpm_cap_version_info_t;

/* get tpm module version */
u32 tpm_get_version(byte *major, byte *minor)
{
    u32 ret, in_size= 0, out_size;
    u32 cap_area= TPM_CAP_VERSION_VAL;
    u32 sub_cap_size= 0;
    u32 resp_size= 0;
    tpm_cap_version_info_t *cap_version;

    if(major==NULL || minor==NULL)
        return TPM_BAD_PARAMETER;

    reverse_copy(WRAPPER_IN_BUF, &cap_area, sizeof(cap_area));
    in_size+= sizeof(cap_area);
    reverse_copy(WRAPPER_IN_BUF+in_size, &sub_cap_size, sizeof(sub_cap_size));
    in_size+= sizeof(sub_cap_size);

    out_size= sizeof(resp_size)+sizeof(tpm_cap_version_info_t);
    ret= tpm_submit_cmd(0, TPM_ORD_GET_CAPABILITY, in_size, &out_size);

#ifdef TPM_TRACE
    printk("TPM: get version, return value= %08X\n", ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: get version, return value= %08X\n", ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk("TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    reverse_copy(&resp_size, WRAPPER_OUT_BUF, sizeof(resp_size));
    cap_version= (tpm_cap_version_info_t *)
                            (WRAPPER_OUT_BUF+sizeof(resp_size));
    *major= cap_version->version.major;
    *minor= cap_version->version.minor;

    return ret;
}

#define HMAC_BLOCK_SIZE     64
#define HMAC_OUTPUT_SIZE    20

static bool hmac(const byte key[HMAC_OUTPUT_SIZE], const byte *msg,
                 u32 len, byte md[HMAC_OUTPUT_SIZE])
{
    byte ipad[HMAC_BLOCK_SIZE], opad[HMAC_BLOCK_SIZE];
    u32 i;
    SHA_CTX ctx;

    COMPILE_TIME_ASSERT(HMAC_OUTPUT_SIZE<=HMAC_BLOCK_SIZE);

    for(i= 0; i<HMAC_BLOCK_SIZE; i++) {
        ipad[i]= 0x36;
        opad[i]= 0x5C;
    }

    for(i= 0; i<HMAC_OUTPUT_SIZE; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, ipad, HMAC_BLOCK_SIZE);
    SHA1_Update(&ctx, msg, len);
    SHA1_Final(md, &ctx);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, opad, HMAC_BLOCK_SIZE);
    SHA1_Update(&ctx, md, HMAC_OUTPUT_SIZE);
    SHA1_Final(md, &ctx);

    return true;
}

typedef uint16_t tpm_entity_type_t;
typedef u32 tpm_authhandle_t;
typedef struct __packed {
    byte     nonce[20];
} tpm_nonce_t;

#define TPM_ET_SRK              0x0004
#define TPM_KH_SRK              0x40000000

typedef u32 tpm_key_handle_t;

typedef tpm_digest_t tpm_composite_hash_t;
typedef struct __packed {
    tpm_structure_tag_t         tag;
    tpm_locality_selection_t    locality_at_creation;
    tpm_locality_selection_t    locality_at_release;
    tpm_pcr_selection_t         creation_pcr_selection;
    tpm_pcr_selection_t         release_pcr_selection;
    tpm_composite_hash_t        digest_at_creation;
    tpm_composite_hash_t        digest_at_release;
} tpm_pcr_info_long_t;

typedef byte tpm_authdata_t[20];
typedef tpm_authdata_t tpm_encauth_t;

typedef struct __packed {
    tpm_structure_tag_t    tag;
    tpm_entity_type_t      et;
    u32                    seal_info_size;
} tpm_stored_data12_header_t;

typedef struct __packed {
    tpm_stored_data12_header_t  header;
    u32                    enc_data_size;
    byte                     enc_data[];
} tpm_stored_data12_short_t;

typedef struct __packed {
    tpm_stored_data12_header_t  header;
    tpm_pcr_info_long_t         seal_info;
    u32                    enc_data_size;
    byte                     enc_data[];
} tpm_stored_data12_t;

#define UNLOAD_INTEGER(buf, offset, var) {\
    reverse_copy(buf+offset, &(var), sizeof(var));\
    offset+= sizeof(var);\
}

#define UNLOAD_BLOB(buf, offset, blob, size) {\
    memcpy(buf+offset, blob, size);\
    offset+= size;\
}

#define UNLOAD_BLOB_TYPE(buf, offset, blob) \
    UNLOAD_BLOB(buf, offset, blob, sizeof(*(blob)))

#define UNLOAD_PCR_SELECTION(buf, offset, sel) {\
    UNLOAD_INTEGER(buf, offset, (sel)->size_of_select);\
    UNLOAD_BLOB(buf, offset, (sel)->pcr_select, (sel)->size_of_select);\
}

#define UNLOAD_PCR_INFO_LONG(buf, offset, info) {\
    UNLOAD_INTEGER(buf, offset, (info)->tag);\
    UNLOAD_BLOB_TYPE(buf, offset, &(info)->locality_at_creation);\
    UNLOAD_BLOB_TYPE(buf, offset, &(info)->locality_at_release);\
    UNLOAD_PCR_SELECTION(buf, offset, &(info)->creation_pcr_selection);\
    UNLOAD_PCR_SELECTION(buf, offset, &(info)->release_pcr_selection);\
    UNLOAD_BLOB_TYPE(buf, offset, &(info)->digest_at_creation);\
    UNLOAD_BLOB_TYPE(buf, offset, &(info)->digest_at_release);\
}

#define UNLOAD_STORED_DATA12(buf, offset, hdr) {\
   UNLOAD_INTEGER(buf, offset, ((tpm_stored_data12_header_t *)(hdr))->tag);\
   UNLOAD_INTEGER(buf, offset, ((tpm_stored_data12_header_t *)(hdr))->et);\
   UNLOAD_INTEGER(buf, offset,\
                  ((tpm_stored_data12_header_t *)(hdr))->seal_info_size);\
   if(((tpm_stored_data12_header_t *)(hdr))->seal_info_size==0) {\
       UNLOAD_INTEGER(buf, offset,\
                      ((tpm_stored_data12_short_t *)hdr)->enc_data_size);\
       UNLOAD_BLOB(buf, offset,\
                   ((tpm_stored_data12_short_t *)hdr)->enc_data,\
                   ((tpm_stored_data12_short_t *)hdr)->enc_data_size);\
   }\
   else {\
       UNLOAD_PCR_INFO_LONG(buf, offset,\
                            &((tpm_stored_data12_t *)hdr)->seal_info);\
       UNLOAD_INTEGER(buf, offset,\
                      ((tpm_stored_data12_t *)hdr)->enc_data_size);\
       UNLOAD_BLOB(buf, offset,\
                   ((tpm_stored_data12_t *)hdr)->enc_data,\
                   ((tpm_stored_data12_t *)hdr)->enc_data_size);\
   }\
}

#define LOAD_INTEGER(buf, offset, var) {\
    reverse_copy(&(var), buf+offset, sizeof(var));\
    offset+= sizeof(var);\
}

#define LOAD_BLOB(buf, offset, blob, size) {\
    memcpy(blob, buf+offset, size);\
    offset+= size;\
}

#define LOAD_BLOB_TYPE(buf, offset, blob) \
    LOAD_BLOB(buf, offset, blob, sizeof(*(blob)))

#define LOAD_PCR_SELECTION(buf, offset, sel) {\
    LOAD_INTEGER(buf, offset, (sel)->size_of_select);\
    LOAD_BLOB(buf, offset, (sel)->pcr_select, (sel)->size_of_select);\
}

#define LOAD_PCR_INFO_LONG(buf, offset, info) {\
    LOAD_INTEGER(buf, offset, (info)->tag);\
    LOAD_BLOB_TYPE(buf, offset, &(info)->locality_at_creation);\
    LOAD_BLOB_TYPE(buf, offset, &(info)->locality_at_release);\
    LOAD_PCR_SELECTION(buf, offset, &(info)->creation_pcr_selection);\
    LOAD_PCR_SELECTION(buf, offset, &(info)->release_pcr_selection);\
    LOAD_BLOB_TYPE(buf, offset, &(info)->digest_at_creation);\
    LOAD_BLOB_TYPE(buf, offset, &(info)->digest_at_release);\
}

#define LOAD_STORED_DATA12(buf, offset, hdr) {\
   LOAD_INTEGER(buf, offset, ((tpm_stored_data12_header_t *)(hdr))->tag);\
   LOAD_INTEGER(buf, offset, ((tpm_stored_data12_header_t *)(hdr))->et);\
   LOAD_INTEGER(buf, offset, \
                ((tpm_stored_data12_header_t *)(hdr))->seal_info_size);\
   if(((tpm_stored_data12_header_t *)(hdr))->seal_info_size==0) {\
       LOAD_INTEGER(buf, offset,\
                    ((tpm_stored_data12_short_t *)hdr)->enc_data_size);\
       LOAD_BLOB(buf, offset,\
                 ((tpm_stored_data12_short_t *)hdr)->enc_data,\
                 ((tpm_stored_data12_short_t *)hdr)->enc_data_size);\
   }\
   else {\
       LOAD_PCR_INFO_LONG(buf, offset,\
                          &((tpm_stored_data12_t *)hdr)->seal_info);\
       LOAD_INTEGER(buf, offset,\
                    ((tpm_stored_data12_t *)hdr)->enc_data_size);\
       LOAD_BLOB(buf, offset,\
                 ((tpm_stored_data12_t *)hdr)->enc_data,\
                 ((tpm_stored_data12_t *)hdr)->enc_data_size);\
   }\
}

/*
 *  The TPM_OIAP command allows the creation of an authorization session handle and the
 *  tracking of the handle by the TPM. The TPM generates the handle and nonce. 
 *  The TPM has an internal limit as to the number of handles that may be open at one
 *  time, so the request for a new handle may fail if there is insufficient space available. 
 *  Internally the TPM will do the following:
 *      a. TPM allocates space to save handle, protocol identification, both nonces and any 
 *      other information the TPM needs to manage the session.
 *      b. TPM generates authHandle and nonceEven, returns these to caller. On each 
 *      subsequent use of the OIAP session the TPM MUST generate a new nonceEven
 *      value. When TPM_OIAP is wrapped in an encrypted transport session, no input or output
 *      parameters are encrypted.
 */
static u32 tpm_oiap(u32 locality, tpm_authhandle_t *hauth,
                         tpm_nonce_t *nonce_even)
{
    u32 ret, offset, out_size;

    if(hauth==NULL || nonce_even==NULL)
        return TPM_BAD_PARAMETER;

    offset= 0;
    out_size= sizeof(*hauth)+sizeof(*nonce_even);
    ret= tpm_submit_cmd(locality, TPM_ORD_OIAP, offset, &out_size);

#ifdef TPM_TRACE
    printk("TPM: start OIAP, return value= %08X\n", ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: start OIAP, return value= %08X\n", ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk("TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    offset= 0;
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *hauth);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, nonce_even);

    return ret;
}

/*
 *  The TPM_OSAP command creates the authorization session handle, the shared secret 
 *  and generates nonceEven and nonceEvenOSAP.
 */
static u32 tpm_osap(u32 locality, tpm_entity_type_t ent_type,
                         u32 ent_value, const tpm_nonce_t *odd_osap,
                         tpm_authhandle_t *hauth, tpm_nonce_t *nonce_even,
                         tpm_nonce_t *even_osap)
{
    u32 ret, offset, out_size;

    if(odd_osap==NULL || hauth==NULL ||
         nonce_even==NULL || even_osap==NULL)
        return TPM_BAD_PARAMETER;

    offset= 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, ent_type);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, ent_value);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, odd_osap);

    out_size= sizeof(*hauth)+sizeof(*nonce_even)+sizeof(*even_osap);
    ret= tpm_submit_cmd(locality, TPM_ORD_OSAP, offset, &out_size);

#ifdef TPM_TRACE
    printk("TPM: start OSAP, return value= %08X\n", ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: start OSAP, return value= %08X\n", ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk("TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    offset= 0;
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *hauth);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, nonce_even);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, even_osap);

    return ret;
}


static u32 _tpm_seal(u32 locality, tpm_key_handle_t hkey,
                  const tpm_encauth_t *enc_auth, u32 pcr_info_size,
                  const tpm_pcr_info_long_t *pcr_info, u32 in_data_size,
                  const byte *in_data,
                  tpm_authhandle_t hauth, const tpm_nonce_t *nonce_odd,
                  byte *cont_session, const tpm_authdata_t *pub_auth,
                  u32 *sealed_data_size, byte *sealed_data,
                  tpm_nonce_t *nonce_even, tpm_authdata_t *res_auth)
{
    u32 ret, offset, out_size;

    if(enc_auth==NULL || pcr_info==NULL || in_data==NULL ||
            nonce_odd==NULL || cont_session==NULL || pub_auth==NULL ||
            sealed_data_size==NULL || sealed_data==NULL ||
            nonce_even==NULL || res_auth==NULL) {
        printk("TPM: _tpm_seal() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset= 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hkey);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, enc_auth);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, pcr_info_size);
    UNLOAD_PCR_INFO_LONG(WRAPPER_IN_BUF, offset, pcr_info);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, in_data_size);
    UNLOAD_BLOB(WRAPPER_IN_BUF, offset, in_data, in_data_size);

    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hauth);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, nonce_odd);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, *cont_session);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, pub_auth);

    out_size= WRAPPER_OUT_MAX_SIZE;

    ret= tpm_submit_cmd_auth1(locality, TPM_ORD_SEAL, offset, &out_size);

#ifdef TPM_TRACE
    printk("TPM: seal data, return value= %08X\n", ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: seal data, return value= %08X\n", ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk("TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    if(*sealed_data_size <
        (out_size-sizeof(*nonce_even)-sizeof(*cont_session)
          -sizeof(*res_auth))) {
        printk("TPM: sealed blob is too small\n");
        return TPM_NOSPACE;
    }

    offset= 0;
    LOAD_STORED_DATA12(WRAPPER_OUT_BUF, offset, sealed_data);
    *sealed_data_size= offset;
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, nonce_even);
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *cont_session);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, res_auth);

    return ret;
}


static u32 _tpm_unseal(u32 locality, tpm_key_handle_t hkey,
                    const byte *in_data,
                    tpm_authhandle_t hauth, const tpm_nonce_t *nonce_odd,
                    byte *cont_session, const tpm_authdata_t *auth,
                    tpm_authhandle_t hauth_d, const tpm_nonce_t *nonce_odd_d,
                    byte *cont_session_d, const tpm_authdata_t *auth_d,
                    u32 *secret_size, byte *secret,
                    tpm_nonce_t *nonce_even, tpm_authdata_t *res_auth,
                    tpm_nonce_t *nonce_even_d, tpm_authdata_t *res_auth_d)
{
    u32 ret, offset, out_size;

    if(in_data==NULL || nonce_odd==NULL || cont_session==NULL ||
         auth==NULL || nonce_odd_d==NULL || cont_session_d==NULL ||
         auth_d==NULL || secret_size==NULL || secret==NULL ||
         nonce_even==NULL || res_auth==NULL || nonce_even_d==NULL ||
         res_auth_d==NULL) {
        printk("TPM: _tpm_unseal() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset= 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hkey);
    UNLOAD_STORED_DATA12(WRAPPER_IN_BUF, offset, in_data);

    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hauth);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, nonce_odd);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, *cont_session);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, auth);

    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hauth_d);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, nonce_odd_d);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, *cont_session_d);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, auth_d);

    out_size= WRAPPER_OUT_MAX_SIZE;
    ret= tpm_submit_cmd_auth2(locality, TPM_ORD_UNSEAL, offset, &out_size);

#ifdef TPM_TRACE
    printk("TPM: unseal data, return value= %08X\n", ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: unseal data, return value= %08X\n", ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk("TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    if(*secret_size <
        (out_size-sizeof(*secret_size)-sizeof(*nonce_even)
          -sizeof(*cont_session)-sizeof(*res_auth)-sizeof(*nonce_even_d)
          -sizeof(*cont_session_d)-sizeof(*res_auth_d))) {
        printk("TPM: unsealed data too small\n");
        return TPM_NOSPACE;
    }

    offset= 0;
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *secret_size);
    LOAD_BLOB(WRAPPER_OUT_BUF, offset, secret, *secret_size);

    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, nonce_even);
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *cont_session);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, res_auth);

    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, nonce_even_d);
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *cont_session_d);
    LOAD_BLOB_TYPE(WRAPPER_OUT_BUF, offset, res_auth_d);

    return ret;
}


#define XOR_BLOB_TYPE(data, pad) {\
    for(u32 i= 0; i<sizeof(*(data)); i++) \
        ((byte *)data)[i]^= ((byte *)pad)[i % sizeof(*(pad))];\
}

static const tpm_authdata_t srk_authdata =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const tpm_authdata_t blob_authdata =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};


static u32 _tpm_wrap_seal(u32 locality, const tpm_pcr_info_long_t *pcr_info,
                              u32 in_data_size, const byte *in_data,
                              u32 *sealed_data_size, byte *sealed_data)
{
    u32 ret;
    tpm_nonce_t odd_osap, even_osap, nonce_even, nonce_odd;
    tpm_authhandle_t hauth;
    tpm_authdata_t shared_secret, pub_auth, res_auth;
    tpm_encauth_t enc_auth;
    byte cont_session= false;
    tpm_key_handle_t hkey= TPM_KH_SRK;
    u32 pcr_info_size= sizeof(*pcr_info);
    u32 offset;
    u32 ordinal= TPM_ORD_SEAL;
    tpm_digest_t digest;

    /* skip generate nonce for odd_osap, just use the random value in stack */
    /* establish a osap session */
    ret= tpm_osap(locality, TPM_ET_SRK, TPM_KH_SRK, &odd_osap, &hauth,
                   &nonce_even, &even_osap);
    if(ret!=TPM_SUCCESS)
            return ret;

    /* calculate the shared secret
       shared-secret= HMAC(srk_auth, even_osap || odd_osap) */
    offset= 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &even_osap);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &odd_osap);
    hmac((byte *)&srk_authdata, WRAPPER_IN_BUF, offset,
         (byte *)&shared_secret);

    /* generate ecrypted authdata for data
       enc_auth= XOR(authdata, sha1(shared_secret || last_even_nonce)) */
    offset= 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &shared_secret);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_even);
    sha1_buffer(WRAPPER_IN_BUF, offset, (byte *)&digest);
    memcpy(&enc_auth, &blob_authdata, sizeof(blob_authdata));
    XOR_BLOB_TYPE(&enc_auth, &digest);

    /* skip generate nonce for nonce_odd, just use the random value in stack */

    /* calculate authdata */
    /* in_param_digest= sha1(1S ~ 6S) */
    offset= 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, ordinal);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &enc_auth);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, pcr_info_size);
    UNLOAD_PCR_INFO_LONG(WRAPPER_IN_BUF, offset, pcr_info);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, in_data_size);
    UNLOAD_BLOB(WRAPPER_IN_BUF, offset, in_data, in_data_size);
    sha1_buffer(WRAPPER_IN_BUF, offset, (byte *)&digest);

    /* authdata= hmac(key, in_param_digest || auth_params) */
    offset= 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &digest);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_even);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_odd);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, cont_session);
    hmac((byte *)&shared_secret, WRAPPER_IN_BUF, offset,
         (byte *)&pub_auth);

    /* call the simple seal function */
    ret= _tpm_seal(locality, hkey, (const tpm_encauth_t *)&enc_auth,
                    pcr_info_size, pcr_info, in_data_size, in_data,
                    hauth, &nonce_odd, &cont_session,
                    (const tpm_authdata_t *)&pub_auth,
                    sealed_data_size, sealed_data,
                    &nonce_even, &res_auth);

    /* skip check for res_auth */

    return ret;
}

static u32 _tpm_wrap_unseal(u32 locality, const byte *in_data,
                            u32 *secret_size, byte *secret)
{
    u32 ret;
    tpm_nonce_t odd_osap, even_osap;
    tpm_nonce_t nonce_even, nonce_odd, nonce_even_d, nonce_odd_d;
    tpm_authhandle_t hauth, hauth_d;
    tpm_authdata_t shared_secret;
    tpm_authdata_t pub_auth, res_auth, pub_auth_d, res_auth_d;
    byte cont_session= false, cont_session_d= false;
    tpm_key_handle_t hkey= TPM_KH_SRK;
    u32 offset;
    u32 ordinal= TPM_ORD_UNSEAL;
    tpm_digest_t digest;

    /* skip generate nonce for odd_osap, just use the random value in stack */

    /* establish a osap session */
    ret= tpm_osap(locality, TPM_ET_SRK, TPM_KH_SRK, &odd_osap, &hauth,
                   &nonce_even, &even_osap);
    if(ret!=TPM_SUCCESS)
            return ret;

    /* calculate the shared secret
       shared-secret= HMAC(auth, even_osap || odd_osap) */
    offset= 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &even_osap);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &odd_osap);
    hmac((byte *)&srk_authdata, WRAPPER_IN_BUF, offset,
         (byte *)&shared_secret);

    /* establish a oiap session */
    ret= tpm_oiap(locality, &hauth_d, &nonce_even_d);
    if(ret!=TPM_SUCCESS)
            return ret;

    /* skip generate nonce_odd & nonce_odd_d, just use the random values */

    /* calculate authdata */
    /* in_param_digest= sha1(1S ~ 6S) */
    offset= 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, ordinal);
    UNLOAD_STORED_DATA12(WRAPPER_IN_BUF, offset, in_data);
    sha1_buffer(WRAPPER_IN_BUF, offset, (byte *)&digest);

    /* authdata1= hmac(key, in_param_digest || auth_params1) */
    offset= 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &digest);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_even);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_odd);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, cont_session);
    hmac((byte *)&shared_secret, WRAPPER_IN_BUF, offset,
         (byte *)&pub_auth);

    /* authdata2= hmac(key, in_param_digest || auth_params2) */
    offset= 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &digest);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_even_d);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_odd_d);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, cont_session_d);
    hmac((byte *)&blob_authdata, WRAPPER_IN_BUF, offset,
         (byte *)&pub_auth_d);

    /* call the simple seal function */
    ret= _tpm_unseal(locality, hkey, in_data,
                      hauth, &nonce_odd, &cont_session,
                      (const tpm_authdata_t *)&pub_auth,
                      hauth_d, &nonce_odd_d, &cont_session_d,
                      (const tpm_authdata_t *)&pub_auth_d,
                      secret_size, secret,
                      &nonce_even, &res_auth, &nonce_even_d, &res_auth_d);

    /* skip check for res_auth */
    return ret;
}


static bool init_pcr_info(u32 locality, tpm_locality_selection_t release_locs,
                          u32 nr_create, const byte indcs_create[],
                          u32 nr_release, const byte indcs_release[],
                          const tpm_pcr_value_t *values_release[],
                          tpm_pcr_info_long_t *pcr_info)
{
    u32 offset;
    u32 i, blob_size;
    static tpm_locality_selection_t localities[TPM_NR_LOCALITIES]= {
        TPM_LOC_ZERO, TPM_LOC_ONE, TPM_LOC_TWO, TPM_LOC_THREE, TPM_LOC_FOUR
    };

    if((release_locs & TPM_LOC_RSVD)!=0)
        return TPM_BAD_PARAMETER;
    if(pcr_info==NULL)
        return TPM_BAD_PARAMETER;
    if(locality >= TPM_NR_LOCALITIES)
        return TPM_BAD_PARAMETER;
    if(indcs_create==NULL)
        nr_create= 0;
    if(indcs_release==NULL || values_release==NULL)
        nr_release= 0;
    for(i= 0; i<nr_create; i++)
        if(indcs_create[i] >= TPM_NR_PCRS)
            return TPM_BAD_PARAMETER;
    for(i= 0; i<nr_release; i++) {
        if(indcs_release[i] >= TPM_NR_PCRS || values_release[i]==NULL)
            return TPM_BAD_PARAMETER;
    }

    memset(pcr_info, 0, sizeof(*pcr_info));
    pcr_info->tag= TPM_TAG_PCR_INFO_LONG;
    pcr_info->locality_at_creation= localities[locality];
    pcr_info->locality_at_release= release_locs;
    pcr_info->creation_pcr_selection.size_of_select= 3;
    for(i= 0; i<nr_create; i++)
        pcr_info->creation_pcr_selection.pcr_select[indcs_create[i]/8]|=
            1 << (indcs_create[i] % 8);
    pcr_info->release_pcr_selection.size_of_select= 3;
    for(i= 0; i<nr_release; i++)
        pcr_info->release_pcr_selection.pcr_select[indcs_release[i]/8]|=
            1 << (indcs_release[i] % 8);

    if(nr_release>0) {
        offset= 0;
        UNLOAD_PCR_SELECTION(WRAPPER_IN_BUF, offset,
                             &pcr_info->release_pcr_selection);
        blob_size= sizeof(tpm_pcr_value_t) * nr_release;
        UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, blob_size);
        for(i= 0; i<nr_release; i++)
            UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, values_release[i]);
        sha1_buffer(WRAPPER_IN_BUF, offset,
                    (byte *)&pcr_info->digest_at_release);
    }

    return true;
}

u32 tpm_seal(u32 locality, tpm_locality_selection_t release_locs,
                  u32 pcr_nr_create, const byte pcr_indcs_create[],
                  u32 pcr_nr_release, const byte pcr_indcs_release[],
                  const tpm_pcr_value_t *pcr_values_release[],
                  u32 in_data_size, const byte *in_data,
                  u32 *sealed_data_size, byte *sealed_data)
{
    u32 ret;
    tpm_pcr_info_long_t pcr_info;

    if(locality >= TPM_NR_LOCALITIES ||
         in_data_size==0 || in_data==NULL ||
         sealed_data_size==NULL || sealed_data==NULL ||
         *sealed_data_size==0) {
        printk("TPM: tpm_seal() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    if(!init_pcr_info(locality, release_locs, pcr_nr_create,
                        pcr_indcs_create, pcr_nr_release, pcr_indcs_release,
                        pcr_values_release, &pcr_info)) {
        printk("TPM: tpm_seal() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    ret= _tpm_wrap_seal(locality, &pcr_info, in_data_size, in_data,
                         sealed_data_size, sealed_data);

    return ret;
}

static bool check_sealed_data(u32 size, const byte *data)
{
    if(size<sizeof(tpm_stored_data12_header_t))
        return false;
    if(((tpm_stored_data12_header_t *)data)->tag!=TPM_TAG_STORED_DATA12)
        return false;

    if(((tpm_stored_data12_header_t *)data)->seal_info_size==0) {
        tpm_stored_data12_short_t *data12_s;

        if(size<sizeof(*data12_s))
            return false;
        data12_s= (tpm_stored_data12_short_t *)data;
        if(size!=sizeof(*data12_s)+data12_s->enc_data_size)
            return false;
    }
    else {
        tpm_stored_data12_t *data12;

        if(size<sizeof(*data12))
            return false;
        data12= (tpm_stored_data12_t *)data;
        if(size!=sizeof(*data12)+data12->enc_data_size)
            return false;
    }

    return true;
}


u32 tpm_unseal(u32 locality, u32 sealed_data_size, const byte *sealed_data,
               u32 *secret_size, byte *secret)
{
    u32 ret;

    if(sealed_data==NULL || secret_size==NULL || secret==NULL) {
        printk("TPM: tpm_unseal() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    if(!check_sealed_data(sealed_data_size, sealed_data)) {
        printk("TPM: tpm_unseal() blob invalid\n");
        return TPM_BAD_PARAMETER;
    }

    ret= _tpm_wrap_unseal(locality, sealed_data, secret_size, secret);

    return ret;
}

static void calc_pcr_composition(u32 nr, const byte indcs[],
                                 const tpm_pcr_value_t *values[],
                                 tpm_composite_hash_t *composite)
{
    u32 i, offset, blob_size;
    tpm_pcr_selection_t sel;

    if(nr==0 || indcs==NULL || values==NULL || composite==NULL)
        return;

    sel.size_of_select= 3;
    sel.pcr_select[0]= sel.pcr_select[1]= sel.pcr_select[2]= 0;
    for(i= 0; i<nr; i++)
        sel.pcr_select[indcs[i]/8]|= 1<<(indcs[i] % 8);

    offset= 0;
    UNLOAD_PCR_SELECTION(WRAPPER_IN_BUF, offset, &sel);
    blob_size= sizeof(tpm_pcr_value_t) * nr;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, blob_size);
    for(i= 0; i<nr; i++)
        UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, values[i]);
    sha1_buffer(WRAPPER_IN_BUF, offset, (byte *)composite);
}

static tpm_composite_hash_t *get_cre_pcr_composite(byte *data)
{
    if(((tpm_stored_data12_header_t *)data)->seal_info_size==0)
        return NULL;
    else
        return &((tpm_stored_data12_t *)data)->seal_info.digest_at_creation;
}

bool tpm_cmp_creation_pcrs(u32 pcr_nr_create,
                           const byte pcr_indcs_create[],
                           const tpm_pcr_value_t *pcr_values_create[],
                           u32 sealed_data_size, byte *sealed_data)
{
    u32 i;
    tpm_composite_hash_t composite= {{0,}}, *cre_composite;

    if(pcr_indcs_create==NULL)
        pcr_nr_create= 0;
    for(i= 0; i<pcr_nr_create; i++) {
        if(pcr_indcs_create[i] >= TPM_NR_PCRS)
            return false;
    }
    if(!check_sealed_data(sealed_data_size, sealed_data)) {
        printk("TPM: Bad blob.\n");
        return false;
    }

    if(pcr_nr_create>0)
        calc_pcr_composition(pcr_nr_create, pcr_indcs_create,
                             pcr_values_create, &composite);

    cre_composite= get_cre_pcr_composite(sealed_data);
    if(cre_composite==NULL)
        return false;
    if(memcmp(&composite, cre_composite, sizeof(composite))) {
        printk("TPM: Not equal to creation composition:\n");
        print_hex(NULL, (byte *)&composite, sizeof(composite));
        print_hex(NULL, (byte *)cre_composite, sizeof(composite));
        return false;
    }

    return true;
}

typedef u32 tpm_capability_area_t;

#define TPM_CAP_NV_INDEX    0x00000011

static u32 tpm_get_capability(
                  u32 locality, tpm_capability_area_t cap_area,
                  u32 sub_cap_size, const byte *sub_cap,
                  u32 *resp_size, byte *resp)
{
    u32 ret, offset, out_size;

    if(sub_cap==NULL || resp_size==NULL || resp==NULL) {
        printk("TPM: tpm_get_capability() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset= 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, cap_area);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, sub_cap_size);
    UNLOAD_BLOB(WRAPPER_IN_BUF, offset, sub_cap, sub_cap_size);

    out_size= sizeof(*resp_size)+*resp_size;

    ret= tpm_submit_cmd(locality, TPM_ORD_GET_CAPABILITY, offset, &out_size);

#ifdef TPM_TRACE
    printk("TPM: get capability, return value= %08X\n", ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: get capability, return value= %08X\n", ret);
        return ret;
    }

    offset= 0;
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *resp_size);
    if(out_size<sizeof(*resp_size)+*resp_size) {
        printk("TPM: capability response too small\n");
        return TPM_FAIL;
    }
    LOAD_BLOB(WRAPPER_OUT_BUF, offset, resp, *resp_size);

    return ret;
}

typedef struct __packed {
    tpm_pcr_selection_t         pcr_selection;
    tpm_locality_selection_t    locality_at_release;
    tpm_composite_hash_t        digest_at_release;
} tpm_pcr_info_short_t;

typedef struct __packed {
    tpm_structure_tag_t tag;
    u32            attributes;
} tpm_nv_attributes_t;

typedef struct __packed {
    tpm_structure_tag_t     tag;
    tpm_nv_index_t          nv_index;
    tpm_pcr_info_short_t    pcr_info_read;
    tpm_pcr_info_short_t    pcr_info_write;
    tpm_nv_attributes_t     permission;
    byte                 b_read_st_clear;
    byte                 b_write_st_clear;
    byte                 b_write_define;
    u32                data_size;
} tpm_nv_data_public_t;

u32 tpm_get_nvindex_size(u32 locality,
                              tpm_nv_index_t index, u32 *size)
{
    u32 ret, offset, resp_size;
    byte sub_cap[sizeof(index)];
    byte resp[sizeof(tpm_nv_data_public_t)];
    tpm_nv_index_t idx;

    if(size==NULL) {
        printk("TPM: tpm_get_nvindex_size() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset= 0;
    UNLOAD_INTEGER(sub_cap, offset, index);

    resp_size= sizeof(resp);
    ret= tpm_get_capability(locality, TPM_CAP_NV_INDEX, sizeof(sub_cap),
                             sub_cap, &resp_size, resp);

#ifdef TPM_TRACE
    printk("TPM: get nvindex size, return value= %08X\n", ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: fail to get public data of 0x%08X in TPM NV\n", index);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk("TPM: ");
        print_hex(NULL, resp, resp_size);
    }
#endif

    /* check size */
    if(resp_size==0) {
        printk("TPM: Index 0x%08X does not exist\n", index);
        return TPM_BADINDEX;
    }

    /* check index */
    offset= sizeof(tpm_structure_tag_t);
    LOAD_INTEGER(resp, offset, idx);
#ifdef TPM_TRACE
    printk("TPM: get index value= %08X\n", idx);
#endif

    if(idx!=index) {
        printk("TPM: Index 0x%08X is not the one expected 0x%08X\n",
               idx, index);
        return TPM_BADINDEX;
    }

    if(resp_size!=sizeof(resp)) {
        printk("TPM: public data size of Index 0x%08X responsed incorrect\n",
               index);
        return TPM_FAIL;
    }

    offset= resp_size-sizeof(u32);
    LOAD_INTEGER(resp, offset, *size);

    return ret;
}


typedef struct __packed {
    tpm_structure_tag_t tag;
    byte disable;
    byte ownership;
    byte deactivated;
    byte read_pubek;
    byte disable_owner_clear;
    byte allow_maintenance;
    byte physical_presence_lifetime_lock;
    byte physical_presence_hw_enable;
    byte physical_presence_cmd_enable;
    byte cekp_used;
    byte tpm_post;
    byte tpm_post_lock;
    byte fips;
    byte operator;
    byte enable_revoke_ek;
    byte nv_locked;
    byte read_srk_pub;
    byte tpm_established;
    byte maintenance_done;
    byte disable_full_da_logic_info;
} tpm_permanent_flags_t;

typedef struct __packed {
    tpm_structure_tag_t tag;
    byte deactivated;
    byte disable_force_clear;
    byte physical_presence;
    byte phycical_presence_lock;
    byte b_global_lock;
} tpm_stclear_flags_t;

#define TPM_CAP_FLAG            0x00000004
#define TPM_CAP_FLAG_PERMANENT  0x00000108
#define TPM_CAP_FLAG_VOLATILE   0x00000109


static u32 tpm_get_flags(u32 locality, u32 flag_id,
                       byte *flags, u32 flag_size)
{
    u32 ret, offset, resp_size;
    byte sub_cap[sizeof(flag_id)];
    tpm_structure_tag_t tag;

    if(flags==NULL) {
        printk("TPM: tpm_get_flags() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset= 0;
    UNLOAD_INTEGER(sub_cap, offset, flag_id);
    resp_size= flag_size;
    ret= tpm_get_capability(locality, TPM_CAP_FLAG, sizeof(sub_cap),
                             sub_cap, &resp_size, flags);

#ifdef TPM_TRACE
    printk("TPM: get flags %08X, return value= %08X\n", flag_id, ret);
#endif
    if(ret!=TPM_SUCCESS)
        return ret;

    /* 1.2 spec, main part 2, rev 103 add one more byte to permanent flags, to
       be backward compatible, not assume all expected bytes can be gotten */
    if(resp_size>flag_size) {
        printk("TPM: tpm_get_flags() response size too small\n");
        return TPM_FAIL;
    }

    offset= 0;
    LOAD_INTEGER(flags, offset, tag);
    offset= 0;
    UNLOAD_BLOB_TYPE(flags, offset, &tag);

    return ret;
}

#define TPM_CAP_PROPERTY          0x00000005
#define TPM_CAP_PROP_TIS_TIMEOUT  0x00000115

static u32 tpm_get_timeout(u32 locality,
                       byte *prop, u32 prop_size)
{
    u32 ret, offset, resp_size, prop_id= TPM_CAP_PROP_TIS_TIMEOUT;
    byte sub_cap[sizeof(prop_id)];
    u32 resp[4];

    if((prop==NULL) || (prop_size<sizeof(resp))) {
        printk("TPM: tpm_get_timeout() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset= 0;
    UNLOAD_INTEGER(sub_cap, offset, prop_id);

    resp_size= prop_size;
    ret= tpm_get_capability(locality, TPM_CAP_PROPERTY, sizeof(sub_cap),
                             sub_cap, &resp_size, prop);

#ifdef TPM_TRACE
    printk("TPM: get prop %08X, return value= %08X\n", prop_id, ret);
#endif
    if(ret!=TPM_SUCCESS)
        return ret;

    if(resp_size!=prop_size) {
        printk("TPM: tpm_get_property() response size incorrect\n");
        return TPM_FAIL;
    }

    offset= 0;
    LOAD_INTEGER(prop, offset, resp);
    offset= 0;
    UNLOAD_BLOB_TYPE(prop, offset, &resp);

    return ret;
}

bool release_locality(u32 locality)
{
    u32 i;
#ifdef TPM_TRACE
    printk("TPM: releasing locality %u\n", locality);
#endif

    if(!tpm_validate_locality(locality))
        return true;
    tpm_reg_access_t reg_acc;
    read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
    if(reg_acc.active_locality==0)
        return true;

    /* make inactive by writing a 1 */
    reg_acc._raw[0]= 0;
    reg_acc.active_locality= 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    i= 0;
    do {
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if(reg_acc.active_locality==0)
            return true;
        else
            cpu_relax();
        i++;
    } while(i<=TPM_ACTIVE_LOCALITY_TIME_OUT);

    printk("TPM: access reg release locality timeout\n");
    return false;
}

bool prepare_tpm(void)
{
    /*
     * must ensure TPM_ACCESS_0.activeLocality bit is clear
     * (: locality is not active)
     */
    return release_locality(0);
}

/* ensure TPM is ready to accept commands */
bool is_tpm_ready(u32 locality)
{
    tpm_permanent_flags_t pflags;
    tpm_stclear_flags_t vflags;
    u32 timeout[4];
    u32 ret;

    if(!tpm_validate_locality(locality)) {
        printk("TPM is not available.\n");
        return false;
    }

    /* make sure tpm is not disabled/deactivated */
    memset(&pflags, 0, sizeof(pflags));
    ret= tpm_get_flags(locality, TPM_CAP_FLAG_PERMANENT,
                        (byte *)&pflags, sizeof(pflags));
    if(ret!=TPM_SUCCESS) {
        printk("TPM is disabled or deactivated.\n");
        return false;
    }
    if(pflags.disable) {
        printk("TPM is disabled.\n");
        return false;
    }

    memset(&vflags, 0, sizeof(vflags));
    ret= tpm_get_flags(locality, TPM_CAP_FLAG_VOLATILE,
                        (byte *)&vflags, sizeof(vflags));
    if(ret!=TPM_SUCCESS) {
        printk("TPM is disabled or deactivated.\n");
        return false;
    }
    if(vflags.deactivated) {
        printk("TPM is deactivated.\n");
        return false;
    }

    printk("TPM is ready\n");
    printk("TPM nv_locked: %s\n", (pflags.nv_locked!=0) ? "TRUE" : "FALSE");

    /* get tpm timeout values */
    ret= tpm_get_timeout(locality, (byte *)&timeout, sizeof(timeout));
    if(ret!=TPM_SUCCESS)
        printk("TPM timeout values are not achieved, "
               "default values will be used.\n");
    else {
        /*
         * timeout_x represents the number of milliseconds for the timeout
         * and timeout[x] represents the number of microseconds.
         */
        g_timeout.timeout_a= timeout[0]/1000;
        g_timeout.timeout_b= timeout[1]/1000;
        g_timeout.timeout_c= timeout[2]/1000;
        g_timeout.timeout_d= timeout[3]/1000;
        printk("TPM timeout values: A: %u, B: %u, C: %u, D: %u\n",
               g_timeout.timeout_a, g_timeout.timeout_b, g_timeout.timeout_c,
               g_timeout.timeout_d);
        /*
         * if any timeout values are less than default values, set to default
         * value (due to bug with some TPMs)
         */
        if(g_timeout.timeout_a<TIMEOUT_A) g_timeout.timeout_a= TIMEOUT_A;
        if(g_timeout.timeout_b<TIMEOUT_B) g_timeout.timeout_b= TIMEOUT_B;
        if(g_timeout.timeout_c<TIMEOUT_C) g_timeout.timeout_c= TIMEOUT_C;
        if(g_timeout.timeout_d<TIMEOUT_D) g_timeout.timeout_d= TIMEOUT_D;
    }

    return true;
}

u32 tpm_save_state(u32 locality)
{
    u32 ret, offset, out_size;
    u32 retries= 0;

    do {
        offset= 0;
        out_size= 0;

        ret= tpm_submit_cmd(locality, TPM_ORD_SAVE_STATE, offset, &out_size);
        if(retries==0)
            printk("TPM: save state, return value= %08X\n", ret);
        else if(retries==1)
            printk("retrying command: .");
        else
            printk(".");

        if(ret!=TPM_RETRY)
            break;

        retries++;
        delay(100);
    } while(retries<MAX_SAVESTATE_RETRIES);
    if(retries >= MAX_SAVESTATE_RETRIES)
        printk("TIMEOUT!");
    if(retries>0)
        printk("\n");

    return ret;
}

u32 tpm_get_random(u32 locality, byte *random_data,
                        u32 *data_size)
{
    u32 ret, in_size= 0, out_size, requested_size;
    static bool first_attempt;

    if(random_data==NULL || data_size==NULL)
        return TPM_BAD_PARAMETER;
    if(*data_size==0)
        return TPM_BAD_PARAMETER;

    first_attempt= true;
    requested_size= *data_size;

    /* copy the *data_size into buf in reversed byte order */
    reverse_copy(WRAPPER_IN_BUF+in_size, data_size, sizeof(*data_size));
    in_size+= sizeof(*data_size);

    out_size= *data_size+sizeof(*data_size);
    ret= tpm_submit_cmd(locality, TPM_ORD_GET_RANDOM, in_size, &out_size);

#ifdef TPM_TRACE
    printk("TPM: get random %u bytes, return value= %08X\n", *data_size, ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: get random %u bytes, return value= %08X\n", *data_size,
               ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk("TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    if(out_size<=sizeof(*data_size)) {
        *data_size= 0;
        return ret;
    }

    out_size-= sizeof(*data_size);
    reverse_copy(data_size, WRAPPER_OUT_BUF, sizeof(*data_size));
    if(*data_size>0)
        memcpy(random_data, WRAPPER_OUT_BUF+sizeof(*data_size), *data_size);

    /* data might be used as key, so clear from buffer memory */
    memset(WRAPPER_OUT_BUF+sizeof(*data_size), 0, *data_size);

    /* if TPM doesn't return all requested random bytes, try one more time */
    if(*data_size<requested_size) {
        printk("requested %x random bytes but only got %x\n", requested_size,
               *data_size);
        /* we're only going to try twice */
        if(first_attempt) {
            first_attempt= false;
            u32 second_size= requested_size-*data_size;
            printk("trying one more time to get remaining %x bytes\n",
                   second_size);
            ret= tpm_get_random(locality, random_data+*data_size,
                                 &second_size);
            *data_size+= second_size;
        }
    }

    return ret;
}



//  ----------------------------------------------------------------------------------


#if 0
static u32 setup_tpm_quote2(u32 locality, tpm_key_handle_t hkey,
                  const tpm_encauth_t *enc_auth, u32 pcr_info_size,
                  const tpm_pcr_info_long_t *pcr_info, u32 size_external,
                  const byte *external, tpm_authhandle_t hauth, const tpm_nonce_t *nonce_odd,
                  byte *cont_session, const tpm_authdata_t *pub_auth,
                  u32 *quote_size, byte *quote_data,
                  tpm_nonce_t *nonce_even, tpm_authdata_t *res_auth)
{
    u32 ret;
    tpm_nonce_t odd_osap, even_osap;
    tpm_nonce_t nonce_even, nonce_odd, nonce_even_d, nonce_odd_d;
    tpm_authhandle_t hauth, hauth_d;
    tpm_authdata_t shared_secret;
    tpm_authdata_t pub_auth, res_auth, pub_auth_d, res_auth_d;
    byte cont_session= false, cont_session_d= false;
    tpm_key_handle_t hkey= TPM_KH_SRK;
    u32 offset;
    u32 ordinal= TPM_ORD_UNSEAL;
    tpm_digest_t digest;

    /* skip generate nonce for odd_osap, just use the random value in stack */

    /* establish a osap session */
    ret= tpm_osap(locality, TPM_ET_SRK, TPM_KH_SRK, &odd_osap, &hauth,
                   &nonce_even, &even_osap);
    if(ret!=TPM_SUCCESS)
            return ret;

    /* calculate the shared secret
       shared-secret= HMAC(auth, even_osap || odd_osap) */
    offset= 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &even_osap);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &odd_osap);
    hmac((byte *)&srk_authdata, WRAPPER_IN_BUF, offset,
         (byte *)&shared_secret);

    /* establish a oiap session */
    ret= tpm_oiap(locality, &hauth_d, &nonce_even_d);
    if(ret!=TPM_SUCCESS)
            return ret;

    /* skip generate nonce_odd & nonce_odd_d, just use the random values */

    /* calculate authdata */
    /* in_param_digest= sha1(1S ~ 6S) */
    offset= 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, ordinal);
    UNLOAD_STORED_DATA12(WRAPPER_IN_BUF, offset, in_data);
    sha1_buffer(WRAPPER_IN_BUF, offset, (byte *)&digest);

    /* authdata1= hmac(key, in_param_digest || auth_params1) */
    offset= 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &digest);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_even);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_odd);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, cont_session);
    hmac((byte *)&shared_secret, WRAPPER_IN_BUF, offset,
         (byte *)&pub_auth);

    /* authdata2= hmac(key, in_param_digest || auth_params2) */
    offset= 0;
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &digest);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_even_d);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, &nonce_odd_d);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, cont_session_d);
    hmac((byte *)&blob_authdata, WRAPPER_IN_BUF, offset,
         (byte *)&pub_auth_d);

}


static u32 build_tpm_quote2_cmd(u32 ord, int* poffset, byte* blob, 
                                int sizeexternal, byte* external, 
                                TPM_AUTH* privAuth, u32 key, byte* nonce,
                                bool addVer, int pcrsize, byte* pcrdata, 
                                int versize, byte* verinfo)
{
    byte    quotecmd[];
    u32 ret, offset, out_size;

    if(in_data==NULL || nonce_odd==NULL || cont_session==NULL ||
         auth==NULL || nonce_odd_d==NULL || cont_session_d==NULL ||
         auth_d==NULL || secret_size==NULL || secret==NULL ||
         nonce_even==NULL || res_auth==NULL || nonce_even_d==NULL ||
         res_auth_d==NULL) {
        printk("TPM: _tpm_unseal() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    offset= 0;
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hkey);
    UNLOAD_STORED_DATA12(WRAPPER_IN_BUF, offset, in_data);

    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hauth);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, nonce_odd);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, *cont_session);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, auth);

    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, hauth_d);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, nonce_odd_d);
    UNLOAD_INTEGER(WRAPPER_IN_BUF, offset, *cont_session_d);
    UNLOAD_BLOB_TYPE(WRAPPER_IN_BUF, offset, auth_d);

    out_size= WRAPPER_OUT_MAX_SIZE;
    ret= tpm_submit_cmd_auth2(locality, TPM_ORD_UNSEAL, offset, &out_size);

#ifdef TPM_TRACE
    printk("TPM: unseal data, return value= %08X\n", ret);
#endif
    if(ret!=TPM_SUCCESS) {
        printk("TPM: unseal data, return value= %08X\n", ret);
        return ret;
    }

#ifdef TPM_TRACE
    {
        printk("TPM: ");
        print_hex(NULL, WRAPPER_OUT_BUF, out_size);
    }
#endif

    if(*secret_size <
        (out_size-sizeof(*secret_size)-sizeof(*nonce_even)
          -sizeof(*cont_session)-sizeof(*res_auth)-sizeof(*nonce_even_d)
          -sizeof(*cont_session_d)-sizeof(*res_auth_d))) {
        printk("TPM: unsealed data too small\n");
        return TPM_NOSPACE;
    }
}


static u32 parse_tpm_quote2_out(u32 ord, int* poffset, byte* blob, 
                                int sizeexternal, byte* external, TPM_AUTH* privAuth, 
                                u32 key, byte* nonce, bool addVer, int pcrsize, 
                                byte* pcrdata, int versize, byte* verinfo)
{

    offset= 0;
    LOAD_INTEGER(WRAPPER_OUT_BUF, offset, *secret_size);
    LOAD_BLOB(WRAPPER_OUT_BUF, offset, secret, *secret_size);
}


u32 tpm_quote(u32 locality, tpm_locality_selection_t release_locs,
                  u32 pcr_nr_create, const byte pcr_indcs_create[],
                  u32 pcr_nr_release, const byte pcr_indcs_release[],
                  const tpm_pcr_value_t *pcr_values_release[],
                  u32 size_external, const byte *external,
                  u32* psize_quote, const byte *quote,
                  u32 *secret_size, byte *secret)
{
    u32 ret;
    tpm_pcr_info_long_t pcr_info;

    if(locality >= TPM_NR_LOCALITIES ||
         size_external==0 || external==NULL ||
         psize_quote==NULL || quote==NULL ||
         *psize_quote==0) {
        printk("TPM: tpm_quote() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    if(!init_pcr_info(locality, release_locs, pcr_nr_create,
                      pcr_indcs_create, pcr_nr_release, pcr_indcs_release,
                      pcr_values_release, &pcr_info)) {
        printk("TPM: tpm_quote() bad parameter\n");
        return TPM_BAD_PARAMETER;
    }

    //  check auth

    //  make sure key is loaded

    //  build command
    build_tpm_quote2_cmd(u32 ord, int* poffset, byte* blob,
                         int size_external, byte* external, 
                         TPM_AUTH* privAuth, u32 key, byte* nonce,
                         bool addVer, int pcrsize, byte* pcrdata, 
                         int versize, byte* verinfo);
    //  submit

    //  parse response
    parse_tpm_quote2_out(u32 ord, int* poffset, byte* blob, 
                         int size_external, byte* external, TPM_AUTH* privAuth, 
                         u32 key, byte* nonce, bool addVer, int pcrsize, 
                         byte* pcrdata, int versize, byte* verinfo);

    //  release_auth

    return ret;
}
#endif


//  ----------------------------------------------------------------------------------



