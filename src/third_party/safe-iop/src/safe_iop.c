/* safe_iop
 * Author:: Will Drewry <redpig@dataspill.org>
 * See safe_iop.h for more info.
 *
 * Copyright (c) 2007,2008 Will Drewry <redpig@dataspill.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <safe_iop.h>

typedef enum { SAFE_IOP_TYPE_U8 = 1,
               SAFE_IOP_TYPE_S8,
               SAFE_IOP_TYPE_U16,
               SAFE_IOP_TYPE_S16,
               SAFE_IOP_TYPE_U32,
               SAFE_IOP_TYPE_S32,
               SAFE_IOP_TYPE_U64,
               SAFE_IOP_TYPE_S64,
               SAFE_IOP_TYPE_DEFAULT = SAFE_IOP_TYPE_S32,
               } sop_type_t;

#define SAFE_IOP_TYPE_PREFIXES "us"

/* _sopf_read_type
 * This is a static helper function for sopf which reads off
 * the type from the format string and advances the given pointer.
 */
static int _sopf_read_type(sop_type_t *type, const char **c) {
  if (type == NULL) {
    return 0;
  }

  if (c == NULL || *c == NULL) {
    return 0;
  }

  /* Leave it as default if end of fmt */
  if (**c == '\0')
    return 1;

  /* Extract a type for the operation if there is one */
  if (strchr(SAFE_IOP_TYPE_PREFIXES, **c) != NULL) {
    switch(**c) {
      case 'u':
        if (*(*c+1) && *(*c+1) == '8') {
          *type = SAFE_IOP_TYPE_U8;
          *c += 2; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '1') &&
                   (*(*c+2) && *(*c+2) == '6')) {
          *type = SAFE_IOP_TYPE_U16;
          *c += 3; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '3') &&
                   (*(*c+2) && *(*c+2) == '2')) {
          *type = SAFE_IOP_TYPE_U32;
          *c += 3; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '6') &&
                   (*(*c+2) && *(*c+2) == '4')) {
          *type = SAFE_IOP_TYPE_U64;
          *c += 3; /* Advance past type */
        }
        break;
      case 's':
        if (*(*c+1) && *(*c+1) == '8') {
          *type = SAFE_IOP_TYPE_S8;
          *c += 2; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '1') &&
                   (*(*c+2) && *(*c+2) == '6')) {
          *type = SAFE_IOP_TYPE_S16;
          *c += 3; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '3') &&
                   (*(*c+2) && *(*c+2) == '2')) {
          *type = SAFE_IOP_TYPE_S32;
          *c += 3; /* Advance past type */
        } else if ((*(*c+1) && *(*c+1) == '6') &&
                   (*(*c+2) && *(*c+2) == '4')) {
          *type = SAFE_IOP_TYPE_S64;
          *c += 3; /* Advance past type */
        }
        break;
      default:
        /* Unknown type */
        return 0;
    }
  }
  return 1;
}

/* Repeated code for va_args is here.  More code is not factored out this
 * way due to the C99 4096 byte limit for expanded macro text.  */
#define _SAFE_IOP_TYPE_CASE(_lhs, _va_lhs, _lhs_a, _rhs, _va_rhs, _rhs_a, _func) { \
  _rhs a; \
  _lhs value, *_h = (_lhs *) holder; \
  if (!baseline) { \
    value = (_lhs) va_arg(ap, _va_lhs); \
    a = (_rhs) va_arg(ap, _va_rhs); \
    baseline = 1; \
  } else { \
    value = *_h; \
    a = (_rhs) va_arg(ap, _va_rhs); \
  } \
  if (! _func(sop_##_lhs_a(_h), sop_##_lhs_a(value), sop_##_rhs_a(a))) \
    return 0; \
}


/* See header file for details. Or the README :) */
int sopf(void *result, const char *const fmt, ...) {
  va_list ap;
  int baseline = 0; /* indicates if the base value is present */

  const char *c = NULL;
  /* Holds the interim values and allows for result to be NULL. */
  unsigned char holder[sizeof(intmax_t)] = {0};
  sop_type_t lhs = SAFE_IOP_TYPE_DEFAULT, rhs = SAFE_IOP_TYPE_DEFAULT;

  va_start(ap, fmt);
  if (fmt == NULL || fmt[0] == '\0')
    return 0;

  /* Read the left-hand side type for the operation type if giveṅ.
   * sop_iop(f) always casts to the left so this is only read once
   * then carried through.
   */
  c=fmt;
  if (!_sopf_read_type(&lhs, &c)) {
    return 0;
  }

  while (*c) {
    /* Process the the operations */
    switch(*(c++)) { /* operation */
      case '+': /* add */
        /* Read the right-hand side type for the operation type if given */
        if (!_sopf_read_type(&rhs, &c))
          return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, sop_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, sop_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, sop_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, sop_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, sop_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, sop_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, sop_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, sop_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, sop_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, sop_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, sop_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, sop_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, sop_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, sop_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, sop_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, sop_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, sop_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, sop_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, sop_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, sop_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, sop_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, sop_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, sop_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, sop_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, sop_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, sop_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, sop_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, sop_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, sop_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, sop_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, sop_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, sop_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, sop_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, sop_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, sop_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, sop_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, sop_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, sop_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, sop_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, sop_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, sop_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, sop_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, sop_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, sop_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, sop_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, sop_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, sop_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, sop_addx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, sop_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, sop_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, sop_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, sop_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, sop_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, sop_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, sop_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, sop_addx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, sop_addx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, sop_addx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, sop_addx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, sop_addx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, sop_addx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, sop_addx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, sop_addx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, sop_addx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        break;
      case '-': /* sub */
        if (!_sopf_read_type(&rhs, &c))
          return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, sop_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, sop_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, sop_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, sop_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, sop_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, sop_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, sop_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, sop_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, sop_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, sop_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, sop_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, sop_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, sop_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, sop_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, sop_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, sop_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, sop_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, sop_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, sop_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, sop_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, sop_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, sop_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, sop_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, sop_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, sop_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, sop_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, sop_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, sop_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, sop_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, sop_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, sop_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, sop_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, sop_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, sop_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, sop_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, sop_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, sop_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, sop_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, sop_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, sop_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, sop_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, sop_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, sop_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, sop_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, sop_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, sop_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, sop_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, sop_subx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, sop_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, sop_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, sop_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, sop_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, sop_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, sop_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, sop_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, sop_subx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, sop_subx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, sop_subx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, sop_subx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, sop_subx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, sop_subx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, sop_subx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, sop_subx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, sop_subx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        break;
      case '*': /* mul */
        if (!_sopf_read_type(&rhs, &c))
          return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, sop_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, sop_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, sop_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, sop_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, sop_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, sop_mulx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, sop_mulx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, sop_mulx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, sop_mulx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, sop_mulx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        break;
      case '/': /* div */
        if (!_sopf_read_type(&rhs, &c))
          return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, sop_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, sop_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, sop_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, sop_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, sop_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, sop_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, sop_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, sop_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, sop_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, sop_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, sop_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, sop_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, sop_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, sop_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, sop_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, sop_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, sop_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, sop_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, sop_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, sop_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, sop_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, sop_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, sop_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, sop_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, sop_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, sop_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, sop_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, sop_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, sop_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, sop_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, sop_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, sop_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, sop_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, sop_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, sop_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, sop_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, sop_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, sop_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, sop_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, sop_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, sop_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, sop_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, sop_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, sop_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, sop_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, sop_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, sop_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, sop_divx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, sop_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, sop_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, sop_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, sop_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, sop_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, sop_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, sop_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, sop_divx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, sop_divx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, sop_divx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, sop_divx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, sop_divx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, sop_divx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, sop_divx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, sop_divx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, sop_divx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        break;
      case '%': /* mod */
        if (!_sopf_read_type(&rhs, &c))
          return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, sop_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, sop_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, sop_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, sop_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, sop_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, sop_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, sop_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, sop_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, sop_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, sop_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, sop_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, sop_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, sop_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, sop_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, sop_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, sop_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, sop_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, sop_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, sop_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, sop_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, sop_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, sop_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, sop_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, sop_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, sop_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, sop_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, sop_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, sop_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, sop_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, sop_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, sop_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, sop_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, sop_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, sop_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, sop_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, sop_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, sop_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, sop_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, sop_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, sop_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, sop_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, sop_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, sop_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, sop_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, sop_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, sop_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, sop_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, sop_modx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, sop_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, sop_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, sop_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, sop_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, sop_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, sop_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, sop_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, sop_modx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, sop_modx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, sop_modx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, sop_modx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, sop_modx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, sop_modx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, sop_modx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, sop_modx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, sop_modx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        break;
      case '<': /* shl */
        if (*c && *c == '<') {
          c++;
          if (!_sopf_read_type(&rhs, &c))
            return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, sop_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, sop_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, sop_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, sop_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, sop_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, sop_shlx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, sop_shlx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, sop_shlx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, sop_shlx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, sop_shlx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
          }
        } else {
          /* unknown op */
          return 0;
        }
        break;
      case '>': /* shr */
        if (*c && *c == '>') {
          c++;
          if (!_sopf_read_type(&rhs, &c))
            return 0;
        switch (lhs) {
          case SAFE_IOP_TYPE_U8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint8_t, uint32_t, u8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int8_t, int32_t, s8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint16_t, uint32_t, u16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int16_t, int32_t, s16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint32_t, uint32_t, u32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int32_t, int32_t, s32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    uint64_t, uint64_t, u64, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint8_t, uint32_t, u8,
                                    int64_t, int64_t, s64, sop_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S8:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint8_t, uint32_t, u8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int8_t, int32_t, s8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint16_t, uint32_t, u16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int16_t, int32_t, s16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint32_t, uint32_t, u32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int32_t, int32_t, s32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    uint64_t, uint64_t, u64, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int8_t, int32_t, s8,
                                    int64_t, int64_t, s64, sop_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint8_t, uint32_t, u8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int8_t, int32_t, s8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint16_t, uint32_t, u16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int16_t, int32_t, s16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint32_t, uint32_t, u32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int32_t, int32_t, s32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    uint64_t, uint64_t, u64, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint16_t, uint32_t, u16,
                                    int64_t, int64_t, s64, sop_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S16:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint8_t, uint32_t, u8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int8_t, int32_t, s8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint16_t, uint32_t, u16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int16_t, int32_t, s16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint32_t, uint32_t, u32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int32_t, int32_t, s32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    uint64_t, uint64_t, u64, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int16_t, int32_t, s16,
                                    int64_t, int64_t, s64, sop_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_U32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint8_t, uint32_t, u8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int8_t, int32_t, s8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint16_t, uint32_t, u16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int16_t, int32_t, s16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint32_t, uint32_t, u32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int32_t, int32_t, s32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    uint64_t, uint64_t, u64, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint32_t, uint32_t, u32,
                                    int64_t, int64_t, s64, sop_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S32:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint8_t, uint32_t, u8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int8_t, int32_t, s8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint16_t, uint32_t, u16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int16_t, int32_t, s16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint32_t, uint32_t, u32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int32_t, int32_t, s32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    uint64_t, uint64_t, u64, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int32_t, int32_t, s32,
                                    int64_t, int64_t, s64, sop_shrx);
                break;
              default:
                return 0;
            }

            break;
          case SAFE_IOP_TYPE_U64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint8_t, uint32_t, u8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int8_t, int32_t, s8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint16_t, uint32_t, u16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int16_t, int32_t, s16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint32_t, uint32_t, u32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int32_t, int32_t, s32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    uint64_t, uint64_t, u64, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(uint64_t, uint64_t, u64,
                                    int64_t, int64_t, s64, sop_shrx);
                break;
              default:
                return 0;
            }
            break;
          case SAFE_IOP_TYPE_S64:
            switch (rhs) {
              case SAFE_IOP_TYPE_U8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint8_t, uint32_t, u8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S8:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int8_t, int32_t, s8, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint16_t, uint32_t, u16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S16:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int16_t, int32_t, s16, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint32_t, uint32_t, u32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S32:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int32_t, int32_t, s32, sop_shrx);
                break;
              case SAFE_IOP_TYPE_U64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    uint64_t, uint64_t, u64, sop_shrx);
                break;
              case SAFE_IOP_TYPE_S64:
                _SAFE_IOP_TYPE_CASE(int64_t, int64_t, s64,
                                    int64_t, int64_t, s64, sop_shrx);
                break;
              default:
                return 0;
            }
            break;
          default:
            return 0;
        }
        } else {
          /* unknown op */
          return 0;
        }
        break;
      default:
       /* unknown op */
       return 0;
    }
    /* Once the lhs type is given, this becomes the default for
     * all remaining operands
     */
   rhs = lhs;
  }
  /* Success! Assign the holder value back to result using the stored lhs */
  if (result) {
    switch (lhs) {
      case SAFE_IOP_TYPE_U8: {
        uint8_t *r = result, *h = (uint8_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_S8: {
        int8_t *r = result, *h = (int8_t *)holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_U16: {
        uint16_t *r = result, *h = (uint16_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_S16: {
        int16_t *r = result, *h = (int16_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_U32: {
        uint32_t *r = result, *h = (uint32_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_S32: {
        int32_t *r = result, *h = (int32_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_U64: {
        uint64_t *r = result, *h = (uint64_t *) holder;
        *r = *h;
        } break;
      case SAFE_IOP_TYPE_S64: {
        int64_t *r = result, *h = (int64_t *) holder;
        *r = *h;
        } break;
      default:
        /* bad sign. maybe this should abort. */
        return 0;
    }
  }
  return 1;
}
