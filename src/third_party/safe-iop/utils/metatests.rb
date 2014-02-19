#!/usr/bin/ruby -w
# License:: BSD (see LICENSE)
# Author:: Will Drewry <redpig@dataspill.org>
#

require 'supported_types'

# Operation container
# This must have the formatted tests for each type so that we can autogenerate them below
# Use macros: %%<side>_<arg>%%
class Op
  attr_accessor :name, :prefix, :code, :block
  def initialize(prefix, name, code, &block)
    @name = name
    @prefix = prefix
    @code = code
    @block = block
  end
  def generate_test(lhs, rhs)
    @block.call(lhs, rhs)
  end
end

ops = [
  Op.new("addx", "addition", "+") { |lhs, rhs|
    print <<-EOF
      #{lhs.name} lhs;
      #{rhs.name} rhs;

      /* two positives */
      lhs = 5; rhs = 10;
      EXPECT_TRUE(sop_addx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 15);
      lhs = 5; rhs = 10;
      EXPECT_TRUE(sop_addx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
    EOF


    print(<<-EOF)
    /* nop */
    lhs = #{lhs.max}; rhs = 0;
    EXPECT_TRUE(sop_addx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
    EXPECT_EQUAL(lhs, #{lhs.max});
    lhs = #{lhs.max}; rhs = 0;
    EXPECT_TRUE(sop_addx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

    /* okay */
    lhs = #{lhs.max}-1; rhs = 1;
    EXPECT_TRUE(sop_addx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
    EXPECT_EQUAL(lhs, #{lhs.max});
    lhs = #{lhs.max}-1; rhs = 1;
    EXPECT_TRUE(sop_addx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

    /* overflow */
    lhs = #{lhs.max}; rhs = 1;
    EXPECT_FALSE(sop_addx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
    EXPECT_EQUAL(lhs, #{lhs.max});
    lhs = #{lhs.max}; rhs = 1;
    EXPECT_FALSE(sop_addx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

    /* overflow */
    lhs = #{lhs.max}; rhs = 2;
    EXPECT_FALSE(sop_addx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
    EXPECT_EQUAL(lhs, #{lhs.max});
    lhs = #{lhs.max}; rhs = 2;
    EXPECT_FALSE(sop_addx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
    EOF
    if lhs.signed && rhs.signed
      print(<<-EOF)
      /* two negatives */
      lhs = -5; rhs = -10;
      EXPECT_TRUE(sop_addx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, -15);
      lhs = -5; rhs = -10;
      EXPECT_TRUE(sop_addx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* nop */
      lhs = #{lhs.min}+1; rhs = -1;
      EXPECT_TRUE(sop_addx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.min});
      lhs = #{lhs.min}+1; rhs = -1;
      EXPECT_TRUE(sop_addx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* ok */
      lhs = #{lhs.min}+2; rhs = -2;
      EXPECT_TRUE(sop_addx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.min});
      lhs = #{lhs.min}+2; rhs = -2;
      EXPECT_TRUE(sop_addx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* underflow */
      lhs = #{lhs.min}; rhs = -1;
      EXPECT_FALSE(sop_addx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.min});
      lhs = #{lhs.min}; rhs = -1;
      EXPECT_FALSE(sop_addx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EOF
    end
  },
  Op.new("sub", "subtraction", "+") { |lhs, rhs|
    print <<-EOF
      #{lhs.name} lhs;
      #{rhs.name} rhs;

      /* two positives */
      lhs = 10; rhs = 5;
      EXPECT_TRUE(sop_subx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 5);
      lhs = 10; rhs = 5;
      EXPECT_TRUE(sop_subx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* nop */
      lhs = #{lhs.min}; rhs = 0;
      EXPECT_TRUE(sop_subx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.min});
      lhs = #{lhs.min}; rhs = 0;
      EXPECT_TRUE(sop_subx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* okay */
      lhs = #{lhs.min}+1; rhs = 1;
      EXPECT_TRUE(sop_subx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.min});
      lhs = #{lhs.min}+1; rhs = 1;
      EXPECT_TRUE(sop_subx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* underflow */
      lhs = #{lhs.min}; rhs = 1;
      EXPECT_FALSE(sop_subx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.min});
      lhs = #{lhs.min}; rhs = 1;
      EXPECT_FALSE(sop_subx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* underflow */
      lhs = #{lhs.min}; rhs = 2;
      EXPECT_FALSE(sop_subx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.min});
      lhs = #{lhs.min}; rhs = 2;
      EXPECT_FALSE(sop_subx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
    EOF
    if lhs.signed && rhs.signed
      print(<<-EOF)
      /* two negatives */
      lhs = -1; rhs = -1;
      EXPECT_TRUE(sop_subx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 0);
      lhs = -1; rhs = -1;
      EXPECT_TRUE(sop_subx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* one negative, one pos */
      lhs = 10; rhs = -1;
      EXPECT_TRUE(sop_subx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 11);
      lhs = 10; rhs = -1;
      EXPECT_TRUE(sop_subx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* nop */
      lhs = #{lhs.max}-1; rhs = -1;
      EXPECT_TRUE(sop_subx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.max});
      lhs = #{lhs.max}-1; rhs = -1;
      EXPECT_TRUE(sop_subx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* ok */
      lhs = #{lhs.max}-2; rhs = -2;
      EXPECT_TRUE(sop_subx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.max});
      lhs = #{lhs.max}-2; rhs = -2;
      EXPECT_TRUE(sop_subx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* overflow */
      lhs = #{lhs.max}; rhs = -1;
      EXPECT_FALSE(sop_subx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.max});
      lhs = #{lhs.max}; rhs = -1;
      EXPECT_FALSE(sop_subx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EOF
    end
  },
  Op.new("mul", "muliplication", "*") { |lhs, rhs|
    print <<-EOF
      #{lhs.name} lhs;
      #{rhs.name} rhs;

      /* two positives */
      lhs = 10; rhs = 5;
      EXPECT_TRUE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 50);
      lhs = 10; rhs = 5;
      EXPECT_TRUE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* nop */
      lhs = #{lhs.max}; rhs = 0;
      EXPECT_TRUE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 0);
      lhs = #{lhs.max}; rhs = 0;
      EXPECT_TRUE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* nop */
      lhs = #{lhs.max}; rhs = 1;
      EXPECT_TRUE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.max});
      lhs = #{lhs.max}; rhs = 1;
      EXPECT_TRUE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* okay */
      lhs = #{lhs.max}/10; rhs = 5;
      EXPECT_TRUE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, (#{lhs.max}/10)*5);
      lhs = #{lhs.max}/10; rhs = 5;
      EXPECT_TRUE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* overflow */
      lhs = #{lhs.max}; rhs = 2;
      EXPECT_FALSE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.max});
      lhs = #{lhs.max}; rhs = 2;
      EXPECT_FALSE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* underflow */
      lhs = #{lhs.max}; rhs = 8;
      EXPECT_FALSE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.max});
      lhs = #{lhs.max}; rhs = 8;
      EXPECT_FALSE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
    EOF
    if lhs.signed && rhs.signed
      print(<<-EOF)
      /* two negatives */
      lhs = -1; rhs = -1;
      EXPECT_TRUE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 1);
      lhs = -1; rhs = -1;
      EXPECT_TRUE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* one negative, one pos */
      lhs = 10; rhs = -1;
      EXPECT_TRUE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, -10);
      lhs = 10; rhs = -1;
      EXPECT_TRUE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* nop */
      lhs = #{lhs.max}; rhs = -1;
      EXPECT_TRUE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, -#{lhs.max});
      lhs = #{lhs.max}; rhs = -1;
      EXPECT_TRUE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* ok */
      lhs = #{lhs.max}/3; rhs = -2;
      EXPECT_TRUE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, (#{lhs.max}/3)*-2);
      lhs = #{lhs.max}/3; rhs = -2;
      EXPECT_TRUE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* underflow (no negative -min)*/
      lhs = #{lhs.min}; rhs = -1;
      EXPECT_FALSE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.min});
      lhs = #{lhs.min}; rhs = -1;
      EXPECT_FALSE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* underflow */
      lhs = #{lhs.min}; rhs = 2;
      EXPECT_FALSE(sop_mulx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.min});
      lhs = #{lhs.min}; rhs = 2;
      EXPECT_FALSE(sop_mulx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EOF
    end
  },
  Op.new("div", "division", "/") { |lhs, rhs|
    print <<-EOF
      #{lhs.name} lhs;
      #{rhs.name} rhs;

      /* two positives */
      lhs = 10; rhs = 5;
      EXPECT_TRUE(sop_divx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 2);
      lhs = 10; rhs = 5;
      EXPECT_TRUE(sop_divx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* div-by-zero */
      lhs = #{lhs.max}; rhs = 0;
      EXPECT_FALSE(sop_divx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.max});
      lhs = #{lhs.max}; rhs = 0;
      EXPECT_FALSE(sop_divx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* nop */
      lhs = #{lhs.max}; rhs = 1;
      EXPECT_TRUE(sop_divx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.max});
      lhs = #{lhs.max}; rhs = 1;
      EXPECT_TRUE(sop_divx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

    EOF
    if lhs.signed && rhs.signed
      print(<<-EOF)
      /* two negatives */
      lhs = -1; rhs = -1;
      EXPECT_TRUE(sop_divx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 1);
      lhs = -1; rhs = -1;
      EXPECT_TRUE(sop_divx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* one negative, one pos */
      lhs = 10; rhs = -1;
      EXPECT_TRUE(sop_divx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, -10);
      lhs = 10; rhs = -1;
      EXPECT_TRUE(sop_divx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* another div by zero */
      lhs = -1; rhs = 0;
      EXPECT_FALSE(sop_divx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, -1);
      lhs = -1; rhs = 0;
      EXPECT_FALSE(sop_divx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* bad div */
      lhs = #{lhs.min}; rhs = -1;
      EXPECT_FALSE(sop_divx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.min});
      lhs = #{lhs.min}; rhs = -1;
      EXPECT_FALSE(sop_divx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EOF
    end
  },
  Op.new("mod", "modulus", "%") { |lhs, rhs|
    print <<-EOF
      #{lhs.name} lhs;
      #{rhs.name} rhs;

      /* two positives */
      lhs = 10; rhs = 5;
      EXPECT_TRUE(sop_modx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 0);
      lhs = 10; rhs = 5;
      EXPECT_TRUE(sop_modx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* mod-by-zero */
      lhs = #{lhs.max}; rhs = 0;
      EXPECT_FALSE(sop_modx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.max});
      lhs = #{lhs.max}; rhs = 0;
      EXPECT_FALSE(sop_modx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* nop */
      lhs = #{lhs.max}; rhs = 1;
      EXPECT_TRUE(sop_modx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 0);
      lhs = #{lhs.max}; rhs = 1;
      EXPECT_TRUE(sop_modx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

    EOF
    if lhs.signed && rhs.signed
      print(<<-EOF)
      /* two negatives */
      lhs = -1; rhs = -1;
      EXPECT_TRUE(sop_modx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 0);
      lhs = -1; rhs = -1;
      EXPECT_TRUE(sop_modx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* one negative, one pos */
      lhs = 10; rhs = -1;
      EXPECT_TRUE(sop_modx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, 0);
      lhs = 10; rhs = -1;
      EXPECT_TRUE(sop_modx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* another mod by zero */
      lhs = -1; rhs = 0;
      EXPECT_FALSE(sop_modx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, -1);
      lhs = -1; rhs = 0;
      EXPECT_FALSE(sop_modx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));

      /* bad mod */
      lhs = #{lhs.min}; rhs = -1;
      EXPECT_FALSE(sop_modx(sop_#{lhs.prefix}(&lhs), sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EXPECT_EQUAL(lhs, #{lhs.min});
      lhs = #{lhs.min}; rhs = -1;
      EXPECT_FALSE(sop_modx(NULL, sop_#{lhs.prefix}(lhs), sop_#{rhs.prefix}(rhs)));
      EOF
    end
  },
  # TODO
  #Op.new("shl", "left shift", "<<"),
  #Op.new("shr", "right shift", ">>"),
]

# Print file header
print <<EOF
/* THIS FILE WAS AUTOGENERATED. DO NOT EDIT BY HAND */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <sys/SupportedTypes::TYPES.h>
#include <safe_iop.h>
#include <limits.h>

/* __LP64__ is given by GCC. Without more work, this is bound to GCC. */
#if __LP64__ == 1 || __SIZEOF_LONG__ > __SIZEOF_INT__
#  define SAFE_INT64_MAX 0x7fffffffffffffffL
#  define SAFE_UINT64_MAX 0xffffffffffffffffUL
#  define SAFE_INT64_MIN (-SAFE_INT64_MAX - 1L)
#elif __SIZEOF_LONG__ == __SIZEOF_INT__
#  define SAFE_INT64_MAX 0x7fffffffffffffffLL
#  define SAFE_UINT64_MAX 0xffffffffffffffffULL
#  define SAFE_INT64_MIN (-SAFE_INT64_MAX - 1LL)
#else
#  warning "64-bit support disabled"
#  define SAFE_IOP_NO_64 1
#endif

/* Pull these from GNU's limit.h */
#ifndef LLONG_MAX
#  define LLONG_MAX 9223372036854775807LL
#endif
#ifndef LLONG_MIN
#  define LLONG_MIN (-LLONG_MAX - 1LL)
#endif
#ifndef ULLONG_MAX
#  define ULLONG_MAX 18446744073709551615ULL
#endif

/* Assumes SSIZE_MAX */
#ifndef SSIZE_MIN
#  if SSIZE_MAX == LONG_MAX
#    define SSIZE_MIN LONG_MIN
#  elif SSIZE_MAX == LONG_LONG_MAX
#    define SSIZE_MIN LONG_LONG_MIN
#  else
#    error "SSIZE_MIN is not defined and could not be guessed"
#  endif
#endif

#define EXPECT_FALSE(cmd) { \\
  printf("%s:%d:%s: EXPECT_FALSE(" #cmd ") => ", __FILE__, __LINE__, __func__); \\
  if ((cmd) != 0) { printf(" FAILED\\n"); expect_fail++; r = 0; } \\
  else { printf(" PASSED\\n"); expect_succ++; } \\
  expect++; \\
  }
#define EXPECT_TRUE(cmd) { \\
  printf("%s:%d:%s: EXPECT_TRUE(" #cmd ") => ", __FILE__, __LINE__, __func__); \\
  if ((cmd) != 1) { printf(" FAILED\\n"); expect_fail++; r = 0; } \\
  else { printf(" PASSED\\n"); expect_succ++; } \\
  expect++; \\
  }
/* Not perfect, but good for basic debugging */
#define EXPECT_EQUAL(lhs,rhs) { \\
  printf("%s:%d:%s: EXPECT_EQUAL(" #lhs " == " #rhs ") -> ", \\
         __FILE__, __LINE__, __func__); \\
  printf("(%d == %d) => ", (int)(lhs), (int)(rhs)); \\
  if ((lhs) != (rhs)) { printf(" FAILED\\n"); expect_fail++; r = 0; } \\
  else { printf(" PASSED\\n"); expect_succ++; } \\
  expect++; \\
  }

static int expect = 0, expect_succ = 0, expect_fail = 0;
EOF


# Print all test cases
SupportedTypes::TYPES.each do |lhs|
  SupportedTypes::TYPES.each do |rhs|
    ops.each do |op|
      print "int T_#{op.prefix}_#{lhs.prefix}_#{rhs.prefix}() { \n"
         print "  int r = 1;\n"
         op.generate_test(lhs, rhs)
         print "  return r;\n"
      print "}\n\n"
    end
  end
end

print <<EOF
int main(int argc, char **argv) {
  int tests = 0, succ = 0, fail = 0;
EOF

# Now list all generated functions in main
SupportedTypes::TYPES.each do |lhs|
  SupportedTypes::TYPES.each do |rhs|
    ops.each do |op|
      print "  tests++; if (T_#{op.prefix}_#{lhs.prefix}_#{rhs.prefix}()) succ++; else fail++;\n"
    end
  end
end

print <<EOF
  printf("%d/%d expects succeeded (%d failures)\\n",
         expect_succ, expect, expect_fail);
  printf("%d/%d tests succeeded (%d failures)\\n", succ, tests, fail);
  return fail;
}
EOF

