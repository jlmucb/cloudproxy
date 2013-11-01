#!/usr/bin/ruby -w
# License:: BSD (see LICENSE)
# Author:: Will Drewry <redpig@dataspill.org>


# Type container
# Must contain enough information to be able to generate tests
module SupportedTypes
  class Type
    attr_accessor :prefix, :name, :signed, :bits
    def initialize(prefix, name, signed, bits)
      @prefix = prefix
      @name = name
      @signed = signed
      @bits = bits
    end
    def umax() "__sop(m)(umax)(#{self.name})"; end
    def smax() "__sop(m)(smax)(#{self.name})"; end
    def smin() "__sop(m)(smin)(#{self.name})"; end
    def max
      return smax() if @signed
      return umax()
    end
    def min
      return smin() if @signed
      return 0
    end
    def to_s() "sop_" + @prefix; end
  end

  # Configure new types here
  # bits == 0 means that sizes are platform specific
  TYPES = [
    # signed types
    Type.new('s8', 'int8_t', true, 8),
    Type.new('s16', 'int16_t', true, 16),
    Type.new('s32', 'int32_t', true, 32),
    Type.new('s64', 'int64_t', true, 64),
    Type.new('sszt', 'ssize_t', true, 0),
    Type.new('sl', 'signed long', true, 0),
    Type.new('sll', 'signed long long', true, 0),
    Type.new('si', 'signed int', true, 0),
    Type.new('sc', 'signed char', true, 0),
    # Unsigned types
    Type.new('u8', 'uint8_t', false, 8),
    Type.new('u16', 'uint16_t', false, 16),
    Type.new('u32', 'uint32_t', false, 32),
    Type.new('u64', 'uint64_t', false, 64),
    Type.new('szt', 'size_t', false, 0),
    Type.new('ul', 'unsigned long', false, 0),
    Type.new('ull', 'unsigned long long', false, 0),
    Type.new('ui', 'unsigned int', false, 0),
    Type.new('uc', 'unsigned char', false, 0),
    ]

  ###
  SIGNED, UNSIGNED = TYPES.partition {|x| x.signed}

end   # SupportedTypes

