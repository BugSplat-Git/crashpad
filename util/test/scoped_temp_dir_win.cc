// Copyright 2015 The Crashpad Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "util/test/scoped_temp_dir.h"

#include <windows.h>

#include "base/logging.h"
#include "base/rand_util.h"
#include "base/strings/string16.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"

namespace crashpad {
namespace test {

// static
base::FilePath ScopedTempDir::CreateTemporaryDirectory() {
  wchar_t temp_path[MAX_PATH + 1];
  DWORD path_len = GetTempPath(MAX_PATH, temp_path);
  PCHECK(path_len != 0) << "GetTempPath";
  base::FilePath system_temp_dir(temp_path);

  for (int count = 0; count < 50; ++count) {
    // Try create a new temporary directory with random generated name. If the
    // one we generate exists, keep trying another path name until we reach some
    // limit.
    base::string16 new_dir_name = base::UTF8ToUTF16(base::StringPrintf(
        "crashpad.test.%d.%I64x", GetCurrentProcessId(), base::RandUint64()));

    base::FilePath path_to_create = system_temp_dir.Append(new_dir_name);
    if (CreateDirectory(path_to_create.value().c_str(), NULL))
      return path_to_create;
  }

  CHECK(false) << "Couldn't find temp dir name";
  return base::FilePath();
}

// static
void ScopedTempDir::RecursivelyDeleteTemporaryDirectory(
    const base::FilePath& path) {
  const std::wstring all_files_mask(L"\\*");

  std::wstring search_mask = path.value() + all_files_mask;
  WIN32_FIND_DATA find_data;
  HANDLE search_handle = FindFirstFile(search_mask.c_str(), &find_data);
  if (search_handle == INVALID_HANDLE_VALUE) {
    ASSERT_EQ(GetLastError(), ERROR_FILE_NOT_FOUND);
    return;
  }
  for (;;) {
    if (wcscmp(find_data.cFileName, L".") != 0 &&
        wcscmp(find_data.cFileName, L"..") != 0) {
      bool is_dir =
          (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
          (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
      base::FilePath entry_path = path.Append(find_data.cFileName);
      if (is_dir)
        RecursivelyDeleteTemporaryDirectory(entry_path);
      else
        EXPECT_TRUE(DeleteFile(entry_path.value().c_str()));
    }

    if (!FindNextFile(search_handle, &find_data)) {
      EXPECT_EQ(GetLastError(), ERROR_NO_MORE_FILES);
      break;
    }
  }

  EXPECT_TRUE(FindClose(search_handle));
  EXPECT_TRUE(RemoveDirectory(path.value().c_str()));
}

}  // namespace test
}  // namespace crashpad
