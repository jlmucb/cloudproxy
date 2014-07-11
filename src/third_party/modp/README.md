modp library
============

Code in this directory is from the stringencoders library:
    https://code.google.com/p/stringencoders/

See licenses in `src/modp_b64w.c` and other files.

Changes were made to fix several bugs in the Base64 code:
 * Use `size_t` instead of `int`, where appropriate.
 * Fix buffer overflows when decoding four bytes at a time.
 * Fix broken NOPAD handling.
