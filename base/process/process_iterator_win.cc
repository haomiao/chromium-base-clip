// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/process_iterator.h"

namespace base {

ProcessIterator::ProcessIterator(const ProcessFilter* filter)
    : started_iteration_(false),
      filter_(filter) {
  snapshot_ = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

ProcessIterator::~ProcessIterator() {
  CloseHandle(snapshot_);
}

bool ProcessIterator::CheckForNextProcess() {
  InitProcessEntry(&entry_);

  if (!started_iteration_) {
    started_iteration_ = true;
    return !!Process32First(snapshot_, &entry_);
  }

  return !!Process32Next(snapshot_, &entry_);
}

void ProcessIterator::InitProcessEntry(ProcessEntry* entry) {
  memset(entry, 0, sizeof(*entry));
  entry->dwSize = sizeof(*entry);
}

bool NamedProcessIterator::IncludeEntry() {
  // Case insensitive.
  const wchar_t* exeFile = entry().exe_file();
  DWORD processId = entry().pid();
  DWORD sessionId = 0;
  ProcessIdToSessionId(processId, &sessionId);
  LOG(INFO) << "NamedProcessIterator: " << exeFile << " pid = " << processId << " sessionId = " << sessionId;
  return _wcsicmp(executable_name_.c_str(), exeFile) == 0 &&
         ProcessIterator::IncludeEntry();
}

}  // namespace base
