// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This code is adapted from Chromium. For the original, see:
// https://code.google.com/p/chromium/codesearch#chromium/src/
// The code has been modified to compile as a standalone library
// and to eliminate some Chromimum dependencies and unneeded functionality.

#include "base/file_util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(OS_MACOSX)
#include <AvailabilityMacros.h>
#include "base/mac/foundation_util.h"
#elif !defined(OS_CHROMEOS) && defined(USE_GLIB)
#include <glib.h>  // for g_get_home_dir()
#endif

#include <fstream>
#include <set>
#include <stack>

#include <glog/logging.h>
#define DPLOG PLOG

// #include "base/basictypes.h"
// #include "base/files/file_enumerator.h"
#include "base/file_path.h"
// #include "base/files/scoped_file.h"
// #include "base/logging.h"
// #include "base/memory/scoped_ptr.h"
// #include "base/memory/singleton.h"
// #include "base/path_service.h"
#include "eintr_wrapper.h"
// #include "base/stl_util.h"
// #include "base/strings/string_util.h"
// #include "base/strings/stringprintf.h"
// #include "base/strings/sys_string_conversions.h"
// #include "base/strings/utf_string_conversions.h"
// #include "base/sys_info.h"
// #include "base/threading/thread_restrictions.h"
// #include "base/time/time.h"
#include "macros.h"

#if defined(OS_ANDROID)
#include "base/android/content_uri_utils.h"
#include "base/os_compat_android.h"
#endif

#if !defined(OS_IOS)
#include <grp.h>
#endif

namespace chromium {
namespace base {

class ThreadRestrictions {
 public:
  static void AssertIOAllowed() {}
};

namespace {

#if defined(OS_POSIX)
#if defined(OS_BSD) || defined(OS_MACOSX) || defined(OS_NACL)
typedef struct stat stat_wrapper_t;
#else
typedef struct stat64 stat_wrapper_t;
#endif
#endif  // defined(OS_POSIX)

#if defined(OS_BSD) || defined(OS_MACOSX) || defined(OS_NACL)
static int CallStat(const char *path, stat_wrapper_t *sb) {
  ThreadRestrictions::AssertIOAllowed();
  return stat(path, sb);
}
static int CallLstat(const char *path, stat_wrapper_t *sb) {
  ThreadRestrictions::AssertIOAllowed();
  return lstat(path, sb);
}
#else  //  defined(OS_BSD) || defined(OS_MACOSX) || defined(OS_NACL)
static int CallStat(const char *path, stat_wrapper_t *sb) {
  ThreadRestrictions::AssertIOAllowed();
  return stat64(path, sb);
}
static int CallLstat(const char *path, stat_wrapper_t *sb) {
  ThreadRestrictions::AssertIOAllowed();
  return lstat64(path, sb);
}
#endif  // !(defined(OS_BSD) || defined(OS_MACOSX) || defined(OS_NACL))

// Helper for NormalizeFilePath(), defined below.
bool RealPath(const FilePath& path, FilePath* real_path) {
  ThreadRestrictions::AssertIOAllowed();  // For realpath().
  FilePath::CharType buf[PATH_MAX];
  if (!realpath(path.value().c_str(), buf))
    return false;

  *real_path = FilePath(buf);
  return true;
}

// Test to see if a set, map, hash_set or hash_map contains a particular key.
// Returns true if the key is in the collection.
template <typename Collection, typename Key>
bool ContainsKey(const Collection& collection, const Key& key) {
  return collection.find(key) != collection.end();
}

// Helper for VerifyPathControlledByUser.
bool VerifySpecificPathControlledByUser(const FilePath& path,
                                        uid_t owner_uid,
                                        const std::set<gid_t>& group_gids) {
  stat_wrapper_t stat_info;
  if (CallLstat(path.value().c_str(), &stat_info) != 0) {
    DPLOG(ERROR) << "Failed to get information on path "
                 << path.value();
    return false;
  }

  if (S_ISLNK(stat_info.st_mode)) {
    DLOG(ERROR) << "Path " << path.value()
               << " is a symbolic link.";
    return false;
  }

  if (stat_info.st_uid != owner_uid) {
    DLOG(ERROR) << "Path " << path.value()
                << " is owned by the wrong user.";
    return false;
  }

  if ((stat_info.st_mode & S_IWGRP) &&
      !ContainsKey(group_gids, stat_info.st_gid)) {
    DLOG(ERROR) << "Path " << path.value()
                << " is writable by an unprivileged group.";
    return false;
  }

  if (stat_info.st_mode & S_IWOTH) {
    DLOG(ERROR) << "Path " << path.value()
                << " is writable by any user.";
    return false;
  }

  return true;
}

std::string TempFileName() {
#if defined(OS_MACOSX)
  return StringPrintf(".%s.XXXXXX", base::mac::BaseBundleID());
#endif

#if defined(GOOGLE_CHROME_BUILD)
  return std::string(".com.google.Chrome.XXXXXX");
#else
  return std::string(".org.chromium.Chromium.XXXXXX");
#endif
}

// Creates and opens a temporary file in |directory|, returning the
// file descriptor. |path| is set to the temporary file path.
// This function does NOT unlink() the file.
int CreateAndOpenFdForTemporaryFile(FilePath directory, FilePath* path) {
  ThreadRestrictions::AssertIOAllowed();  // For call to mkstemp().
  *path = directory.Append(base::TempFileName());
  const std::string& tmpdir_string = path->value();
  // this should be OK since mkstemp just replaces characters in place
  char* buffer = const_cast<char*>(tmpdir_string.c_str());

  return HANDLE_EINTR(mkstemp(buffer));
}

}  // namespace

FilePath MakeAbsoluteFilePath(const FilePath& input) {
  ThreadRestrictions::AssertIOAllowed();
  char full_path[PATH_MAX];
  if (realpath(input.value().c_str(), full_path) == NULL)
    return FilePath();
  return FilePath(full_path);
}

template <typename CHAR>
size_t lcpyT(CHAR* dst, const CHAR* src, size_t dst_size) {
  for (size_t i = 0; i < dst_size; ++i) {
    if ((dst[i] = src[i]) == 0)  // We hit and copied the terminating NULL.
      return i;
  }

  // We were left off at dst_size.  We over copied 1 byte.  Null terminate.
  if (dst_size != 0)
    dst[dst_size - 1] = 0;

  // Count the rest of the |src|, and return it's length in characters.
  while (src[dst_size]) ++dst_size;
  return dst_size;
}

size_t strlcpy(char* dst, const char* src, size_t dst_size) {
  return lcpyT<char>(dst, src, dst_size);
}

// TODO(erikkay): The Windows version of this accepts paths like "foo/bar/*"
// which works both with and without the recursive flag.  I'm not sure we need
// that functionality. If not, remove from file_util_win.cc, otherwise add it
// here.
/// This function taken from an older version of chromium
bool Delete(const FilePath& path, bool recursive) {
  const char* path_str = path.value().c_str();
  stat_wrapper_t file_info;
  int test = CallStat(path_str, &file_info);
  if (test != 0) {
    // The Windows version defines this condition as success.
    bool ret = (errno == ENOENT || errno == ENOTDIR);
    return ret;
  }
  if (!S_ISDIR(file_info.st_mode))
    return (unlink(path_str) == 0);
  if (!recursive)
    return (rmdir(path_str) == 0);

  bool success = true;
  int ftsflags = FTS_PHYSICAL | FTS_NOSTAT;
  char top_dir[PATH_MAX];
  if (strlcpy(top_dir, path_str,
                             arraysize(top_dir)) >= arraysize(top_dir)) {
    return false;
  }
  char* dir_list[2] = { top_dir, NULL };
  FTS* fts = fts_open(dir_list, ftsflags, NULL);
  if (fts) {
    FTSENT* fts_ent = fts_read(fts);
    while (success && fts_ent != NULL) {
      switch (fts_ent->fts_info) {
        case FTS_DNR:
        case FTS_ERR:
          // log error
          success = false;
          continue;
          break;
        case FTS_DP:
          success = (rmdir(fts_ent->fts_accpath) == 0);
          break;
        case FTS_D:
          break;
        case FTS_NSOK:
        case FTS_F:
        case FTS_SL:
        case FTS_SLNONE:
          success = (unlink(fts_ent->fts_accpath) == 0);
          break;
        default:
          DCHECK(false);
          break;
      }
      fts_ent = fts_read(fts);
    }
    fts_close(fts);
  }
  return success;
}

bool PathExists(const FilePath& path) {
  ThreadRestrictions::AssertIOAllowed();
#if defined(OS_ANDROID)
  if (path.IsContentUri()) {
    return ContentUriExists(path);
  }
#endif
  return access(path.value().c_str(), F_OK) == 0;
}

bool PathIsWritable(const FilePath& path) {
  ThreadRestrictions::AssertIOAllowed();
  return access(path.value().c_str(), W_OK) == 0;
}

bool DirectoryExists(const FilePath& path) {
  ThreadRestrictions::AssertIOAllowed();
  stat_wrapper_t file_info;
  if (CallStat(path.value().c_str(), &file_info) == 0)
    return S_ISDIR(file_info.st_mode);
  return false;
}

bool ReadFromFD(int fd, char* buffer, size_t bytes) {
  size_t total_read = 0;
  while (total_read < bytes) {
    ssize_t bytes_read =
        HANDLE_EINTR(read(fd, buffer + total_read, bytes - total_read));
    if (bytes_read <= 0)
      break;
    total_read += bytes_read;
  }
  return total_read == bytes;
}

bool CreateSymbolicLink(const FilePath& target_path,
                        const FilePath& symlink_path) {
  DCHECK(!symlink_path.empty());
  DCHECK(!target_path.empty());
  return ::symlink(target_path.value().c_str(),
                   symlink_path.value().c_str()) != -1;
}

bool ReadSymbolicLink(const FilePath& symlink_path, FilePath* target_path) {
  DCHECK(!symlink_path.empty());
  DCHECK(target_path);
  char buf[PATH_MAX];
  ssize_t count = ::readlink(symlink_path.value().c_str(), buf, arraysize(buf));

  if (count <= 0) {
    target_path->clear();
    return false;
  }

  *target_path = FilePath(FilePath::StringType(buf, count));
  return true;
}

bool GetPosixFilePermissions(const FilePath& path, int* mode) {
  ThreadRestrictions::AssertIOAllowed();
  DCHECK(mode);

  stat_wrapper_t file_info;
  // Uses stat(), because on symbolic link, lstat() does not return valid
  // permission bits in st_mode
  if (CallStat(path.value().c_str(), &file_info) != 0)
    return false;

  *mode = file_info.st_mode & FILE_PERMISSION_MASK;
  return true;
}

bool SetPosixFilePermissions(const FilePath& path,
                             int mode) {
  ThreadRestrictions::AssertIOAllowed();
  DCHECK((mode & ~FILE_PERMISSION_MASK) == 0);

  // Calls stat() so that we can preserve the higher bits like S_ISGID.
  stat_wrapper_t stat_buf;
  if (CallStat(path.value().c_str(), &stat_buf) != 0)
    return false;

  // Clears the existing permission bits, and adds the new ones.
  mode_t updated_mode_bits = stat_buf.st_mode & ~FILE_PERMISSION_MASK;
  updated_mode_bits |= mode & FILE_PERMISSION_MASK;

  if (HANDLE_EINTR(chmod(path.value().c_str(), updated_mode_bits)) != 0)
    return false;

  return true;
}

#if !defined(OS_MACOSX)
// This is implemented in file_util_mac.mm for Mac.
bool GetTempDir(FilePath* path) {
  const char* tmp = getenv("TMPDIR");
  if (tmp) {
    *path = FilePath(tmp);
  } else {
#if defined(OS_ANDROID)
    return PathService::Get(base::DIR_CACHE, path);
#else
    *path = FilePath("/tmp");
#endif
  }
  return true;
}
#endif  // !defined(OS_MACOSX)

#if !defined(OS_MACOSX)  // Mac implementation is in file_util_mac.mm.
FilePath GetHomeDir() {
#if defined(OS_CHROMEOS)
  if (SysInfo::IsRunningOnChromeOS()) {
    // On Chrome OS chrome::DIR_USER_DATA is overridden with a primary user
    // homedir once it becomes available. Return / as the safe option.
    return FilePath("/");
  }
#endif

  const char* home_dir = getenv("HOME");
  if (home_dir && home_dir[0])
    return FilePath(home_dir);

#if defined(OS_ANDROID)
  DLOG(WARNING) << "OS_ANDROID: Home directory lookup not yet implemented.";
#elif defined(USE_GLIB) && !defined(OS_CHROMEOS)
  // g_get_home_dir calls getpwent, which can fall through to LDAP calls so
  // this may do I/O. However, it should be rare that $HOME is not defined and
  // this is typically called from the path service which has no threading
  // restrictions. The path service will cache the result which limits the
  // badness of blocking on I/O. As a result, we don't have a thread
  // restriction here.
  home_dir = g_get_home_dir();
  if (home_dir && home_dir[0])
    return FilePath(home_dir);
#endif

  FilePath rv;
  if (GetTempDir(&rv))
    return rv;

  // Last resort.
  return FilePath("/tmp");
}
#endif  // !defined(OS_MACOSX)

bool CreateTemporaryFile(FilePath* path) {
  ThreadRestrictions::AssertIOAllowed();  // For call to close().
  FilePath directory;
  if (!GetTempDir(&directory))
    return false;
  int fd = CreateAndOpenFdForTemporaryFile(directory, path);
  if (fd < 0)
    return false;
  close(fd);
  return true;
}

FILE* CreateAndOpenTemporaryFileInDir(const FilePath& dir, FilePath* path) {
  int fd = CreateAndOpenFdForTemporaryFile(dir, path);
  if (fd < 0)
    return NULL;

  FILE* file = fdopen(fd, "a+");
  if (!file)
    close(fd);
  return file;
}

bool CreateTemporaryFileInDir(const FilePath& dir, FilePath* temp_file) {
  ThreadRestrictions::AssertIOAllowed();  // For call to close().
  int fd = CreateAndOpenFdForTemporaryFile(dir, temp_file);
  return ((fd >= 0) && !IGNORE_EINTR(close(fd)));
}

static bool CreateTemporaryDirInDirImpl(const FilePath& base_dir,
                                        const FilePath::StringType& name_tmpl,
                                        FilePath* new_dir) {
  ThreadRestrictions::AssertIOAllowed();  // For call to mkdtemp().
  DCHECK(name_tmpl.find("XXXXXX") != FilePath::StringType::npos)
      << "Directory name template must contain \"XXXXXX\".";

  FilePath sub_dir = base_dir.Append(name_tmpl);
  std::string sub_dir_string = sub_dir.value();

  // this should be OK since mkdtemp just replaces characters in place
  char* buffer = const_cast<char*>(sub_dir_string.c_str());
  char* dtemp = mkdtemp(buffer);
  if (!dtemp) {
    DPLOG(ERROR) << "mkdtemp";
    return false;
  }
  *new_dir = FilePath(dtemp);
  return true;
}

bool CreateTemporaryDirInDir(const FilePath& base_dir,
                             const FilePath::StringType& prefix,
                             FilePath* new_dir) {
  FilePath::StringType mkdtemp_template = prefix;
  mkdtemp_template.append(FILE_PATH_LITERAL("XXXXXX"));
  return CreateTemporaryDirInDirImpl(base_dir, mkdtemp_template, new_dir);
}

bool CreateNewTempDirectory(const FilePath::StringType& prefix,
                            FilePath* new_temp_path) {
  FilePath tmpdir;
  if (!GetTempDir(&tmpdir))
    return false;

  return CreateTemporaryDirInDirImpl(tmpdir, TempFileName(), new_temp_path);
}

bool CreateDirectory(const FilePath& full_path) {
  ThreadRestrictions::AssertIOAllowed();  // For call to mkdir().
  std::vector<FilePath> subpaths;

  // Collect a list of all parent directories.
  FilePath last_path = full_path;
  subpaths.push_back(full_path);
  for (FilePath path = full_path.DirName();
       path.value() != last_path.value(); path = path.DirName()) {
    subpaths.push_back(path);
    last_path = path;
  }

  // Iterate through the parents and create the missing ones.
  for (std::vector<FilePath>::reverse_iterator i = subpaths.rbegin();
       i != subpaths.rend(); ++i) {
    if (DirectoryExists(*i))
      continue;
    if (mkdir(i->value().c_str(), 0700) == 0)
      continue;
    // Mkdir failed, but it might have failed with EEXIST, or some other error
    // due to the the directory appearing out of thin air. This can occur if
    // two processes are trying to create the same file system tree at the same
    // time. Check to see if it exists and make sure it is a directory.
    int saved_errno = errno;
    if (!DirectoryExists(*i)) {
      return false;
    }
  }
  return true;
}

bool NormalizeFilePath(const FilePath& path, FilePath* normalized_path) {
  FilePath real_path_result;
  if (!RealPath(path, &real_path_result))
    return false;

  // To be consistant with windows, fail if |real_path_result| is a
  // directory.
  stat_wrapper_t file_info;
  if (CallStat(real_path_result.value().c_str(), &file_info) != 0 ||
      S_ISDIR(file_info.st_mode))
    return false;

  *normalized_path = real_path_result;
  return true;
}

// TODO(rkc): Refactor GetFileInfo and FileEnumerator to handle symlinks
// correctly. http://code.google.com/p/chromium-os/issues/detail?id=15948
bool IsLink(const FilePath& file_path) {
  stat_wrapper_t st;
  // If we can't lstat the file, it's safe to assume that the file won't at
  // least be a 'followable' link.
  if (CallLstat(file_path.value().c_str(), &st) != 0)
    return false;

  if (S_ISLNK(st.st_mode))
    return true;
  else
    return false;
}

FILE* OpenFile(const FilePath& filename, const char* mode) {
  ThreadRestrictions::AssertIOAllowed();
  FILE* result = NULL;
  do {
    result = fopen(filename.value().c_str(), mode);
  } while (!result && errno == EINTR);
  return result;
}

int ReadFile(const FilePath& filename, char* data, int max_size) {
  ThreadRestrictions::AssertIOAllowed();
  int fd = HANDLE_EINTR(open(filename.value().c_str(), O_RDONLY));
  if (fd < 0)
    return -1;

  ssize_t bytes_read = HANDLE_EINTR(read(fd, data, max_size));
  if (IGNORE_EINTR(close(fd)) < 0)
    return -1;
  return bytes_read;
}

int WriteFile(const FilePath& filename, const char* data, int size) {
  ThreadRestrictions::AssertIOAllowed();
  int fd = HANDLE_EINTR(creat(filename.value().c_str(), 0640));
  if (fd < 0)
    return -1;

  int bytes_written = WriteFileDescriptor(fd, data, size);
  if (IGNORE_EINTR(close(fd)) < 0)
    return -1;
  return bytes_written;
}

int WriteFileDescriptor(const int fd, const char* data, int size) {
  // Allow for partial writes.
  ssize_t bytes_written_total = 0;
  for (ssize_t bytes_written_partial = 0; bytes_written_total < size;
       bytes_written_total += bytes_written_partial) {
    bytes_written_partial =
        HANDLE_EINTR(write(fd, data + bytes_written_total,
                           size - bytes_written_total));
    if (bytes_written_partial < 0)
      return -1;
  }

  return bytes_written_total;
}

int AppendToFile(const FilePath& filename, const char* data, int size) {
  ThreadRestrictions::AssertIOAllowed();
  int fd = HANDLE_EINTR(open(filename.value().c_str(), O_WRONLY | O_APPEND));
  if (fd < 0)
    return -1;

  int bytes_written = WriteFileDescriptor(fd, data, size);
  if (IGNORE_EINTR(close(fd)) < 0)
    return -1;
  return bytes_written;
}

// Gets the current working directory for the process.
bool GetCurrentDirectory(FilePath* dir) {
  // getcwd can return ENOENT, which implies it checks against the disk.
  ThreadRestrictions::AssertIOAllowed();

  char system_buffer[PATH_MAX] = "";
  if (!getcwd(system_buffer, sizeof(system_buffer))) {
    // NOTREACHED();
    return false;
  }
  *dir = FilePath(system_buffer);
  return true;
}

// Sets the current working directory for the process.
bool SetCurrentDirectory(const FilePath& path) {
  ThreadRestrictions::AssertIOAllowed();
  int ret = chdir(path.value().c_str());
  return !ret;
}

bool VerifyPathControlledByUser(const FilePath& base,
                                const FilePath& path,
                                uid_t owner_uid,
                                const std::set<gid_t>& group_gids) {
  if (base != path && !base.IsParent(path)) {
     DLOG(ERROR) << "|base| must be a subdirectory of |path|.  base = \""
                 << base.value() << "\", path = \"" << path.value() << "\"";
     return false;
  }

  std::vector<FilePath::StringType> base_components;
  std::vector<FilePath::StringType> path_components;

  base.GetComponents(&base_components);
  path.GetComponents(&path_components);

  std::vector<FilePath::StringType>::const_iterator ib, ip;
  for (ib = base_components.begin(), ip = path_components.begin();
       ib != base_components.end(); ++ib, ++ip) {
    // |base| must be a subpath of |path|, so all components should match.
    // If these CHECKs fail, look at the test that base is a parent of
    // path at the top of this function.
    DCHECK(ip != path_components.end());
    DCHECK(*ip == *ib);
  }

  FilePath current_path = base;
  if (!VerifySpecificPathControlledByUser(current_path, owner_uid, group_gids))
    return false;

  for (; ip != path_components.end(); ++ip) {
    current_path = current_path.Append(*ip);
    if (!VerifySpecificPathControlledByUser(
            current_path, owner_uid, group_gids))
      return false;
  }
  return true;
}

#if defined(OS_MACOSX) && !defined(OS_IOS)
bool VerifyPathControlledByAdmin(const FilePath& path) {
  const unsigned kRootUid = 0;
  const FilePath kFileSystemRoot("/");

  // The name of the administrator group on mac os.
  const char* const kAdminGroupNames[] = {
    "admin",
    "wheel"
  };

  // Reading the groups database may touch the file system.
  ThreadRestrictions::AssertIOAllowed();

  std::set<gid_t> allowed_group_ids;
  for (int i = 0, ie = arraysize(kAdminGroupNames); i < ie; ++i) {
    struct group *group_record = getgrnam(kAdminGroupNames[i]);
    if (!group_record) {
      DPLOG(ERROR) << "Could not get the group ID of group \""
                   << kAdminGroupNames[i] << "\".";
      continue;
    }

    allowed_group_ids.insert(group_record->gr_gid);
  }

  return VerifyPathControlledByUser(
      kFileSystemRoot, path, kRootUid, allowed_group_ids);
}
#endif  // defined(OS_MACOSX) && !defined(OS_IOS)

int GetMaximumPathComponentLength(const FilePath& path) {
  ThreadRestrictions::AssertIOAllowed();
  return pathconf(path.value().c_str(), _PC_NAME_MAX);
}

// -----------------------------------------------------------------------------

namespace internal {

bool MoveUnsafe(const FilePath& from_path, const FilePath& to_path) {
  ThreadRestrictions::AssertIOAllowed();
  // Windows compatibility: if to_path exists, from_path and to_path
  // must be the same type, either both files, or both directories.
  stat_wrapper_t to_file_info;
  if (CallStat(to_path.value().c_str(), &to_file_info) == 0) {
    stat_wrapper_t from_file_info;
    if (CallStat(from_path.value().c_str(), &from_file_info) == 0) {
      if (S_ISDIR(to_file_info.st_mode) != S_ISDIR(from_file_info.st_mode))
        return false;
    } else {
      return false;
    }
  }

  if (rename(from_path.value().c_str(), to_path.value().c_str()) == 0)
    return true;

  if (!CopyDirectory(from_path, to_path, true))
    return false;

  DeleteFile(from_path, true);
  return true;
}

#if !defined(OS_MACOSX)
// Mac has its own implementation, this is for all other Posix systems.
bool CopyFileUnsafe(const FilePath& from_path, const FilePath& to_path) {
  ThreadRestrictions::AssertIOAllowed();
  int infile = HANDLE_EINTR(open(from_path.value().c_str(), O_RDONLY));
  if (infile < 0)
    return false;

  int outfile = HANDLE_EINTR(creat(to_path.value().c_str(), 0666));
  if (outfile < 0) {
    close(infile);
    return false;
  }

  const size_t kBufferSize = 32768;
  std::vector<char> buffer(kBufferSize);
  bool result = true;

  while (result) {
    ssize_t bytes_read = HANDLE_EINTR(read(infile, &buffer[0], buffer.size()));
    if (bytes_read < 0) {
      result = false;
      break;
    }
    if (bytes_read == 0)
      break;
    // Allow for partial writes
    ssize_t bytes_written_per_read = 0;
    do {
      ssize_t bytes_written_partial = HANDLE_EINTR(write(
          outfile,
          &buffer[bytes_written_per_read],
          bytes_read - bytes_written_per_read));
      if (bytes_written_partial < 0) {
        result = false;
        break;
      }
      bytes_written_per_read += bytes_written_partial;
    } while (bytes_written_per_read < bytes_read);
  }

  if (IGNORE_EINTR(close(infile)) < 0)
    result = false;
  if (IGNORE_EINTR(close(outfile)) < 0)
    result = false;

  return result;
}
#endif  // !defined(OS_MACOSX)

}  // namespace internal
}  // namespace base
}  // namespace chromium
