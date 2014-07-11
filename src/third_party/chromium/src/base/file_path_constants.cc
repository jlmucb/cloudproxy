// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This code is adapted from Chromium. For the original, see:
// https://code.google.com/p/chromium/codesearch#chromium/src/
// The code has been modified to compile as a standalone library
// and to eliminate some Chromimum dependencies and unneeded functionality.

#include "base/file_path.h"

#include "macros.h"

namespace chromium {
namespace base {

#if defined(FILE_PATH_USES_WIN_SEPARATORS)
const FilePath::CharType FilePath::kSeparators[] = FILE_PATH_LITERAL("\\/");
#else  // FILE_PATH_USES_WIN_SEPARATORS
const FilePath::CharType FilePath::kSeparators[] = FILE_PATH_LITERAL("/");
#endif  // FILE_PATH_USES_WIN_SEPARATORS

const size_t FilePath::kSeparatorsLength = arraysize(kSeparators);

const FilePath::CharType FilePath::kCurrentDirectory[] = FILE_PATH_LITERAL(".");
const FilePath::CharType FilePath::kParentDirectory[] = FILE_PATH_LITERAL("..");

const FilePath::CharType FilePath::kExtensionSeparator = FILE_PATH_LITERAL('.');

}  // namespace base
}  // namespace chromium
