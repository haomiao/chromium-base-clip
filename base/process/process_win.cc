// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/process.h"

#include "base/debug/activity_tracker.h"
#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/process/kill.h"
#include "base/threading/thread_restrictions.h"

#include <windows.h>
#include "tlhelp32.h"
#include <shellapi.h>

namespace {

DWORD kBasicProcessAccess =
  PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE;

} // namespace

namespace base {

Process::Process(ProcessHandle handle)
    : process_(handle), is_current_process_(false) {
  CHECK_NE(handle, ::GetCurrentProcess());
}

Process::Process(Process&& other)
    : process_(other.process_.Take()),
      is_current_process_(other.is_current_process_) {
  other.Close();
}

Process::~Process() {
}

Process& Process::operator=(Process&& other) {
  DCHECK_NE(this, &other);
  process_.Set(other.process_.Take());
  is_current_process_ = other.is_current_process_;
  other.Close();
  return *this;
}

// static
Process Process::Current() {
  Process process;
  process.is_current_process_ = true;
  return process;
}

// static
Process Process::Open(ProcessId pid) {
  return Process(::OpenProcess(kBasicProcessAccess, FALSE, pid));
}

// static
Process Process::OpenWithExtraPrivileges(ProcessId pid) {
  DWORD access = kBasicProcessAccess | PROCESS_DUP_HANDLE | PROCESS_VM_READ;
  return Process(::OpenProcess(access, FALSE, pid));
}

// static
Process Process::OpenWithAccess(ProcessId pid, DWORD desired_access) {
  return Process(::OpenProcess(desired_access, FALSE, pid));
}

// static
Process Process::DeprecatedGetProcessFromHandle(ProcessHandle handle) {
  DCHECK_NE(handle, ::GetCurrentProcess());
  ProcessHandle out_handle;
  if (!::DuplicateHandle(GetCurrentProcess(), handle,
                         GetCurrentProcess(), &out_handle,
                         0, FALSE, DUPLICATE_SAME_ACCESS)) {
    return Process();
  }
  return Process(out_handle);
}

// static
bool Process::CanBackgroundProcesses() {
  return true;
}

// static
void Process::TerminateCurrentProcessImmediately(int exit_code) {
  ::TerminateProcess(GetCurrentProcess(), exit_code);
  // There is some ambiguity over whether the call above can return. Rather than
  // hitting confusing crashes later on we should crash right here.
  IMMEDIATE_CRASH();
}

bool Process::IsValid() const {
  return process_.IsValid() || is_current();
}

ProcessHandle Process::Handle() const {
  return is_current_process_ ? GetCurrentProcess() : process_.Get();
}

Process Process::Duplicate() const {
  if (is_current())
    return Current();

  ProcessHandle out_handle;
  if (!IsValid() || !::DuplicateHandle(GetCurrentProcess(),
                                       Handle(),
                                       GetCurrentProcess(),
                                       &out_handle,
                                       0,
                                       FALSE,
                                       DUPLICATE_SAME_ACCESS)) {
    return Process();
  }
  return Process(out_handle);
}

ProcessId Process::Pid() const {
  DCHECK(IsValid());
  return GetProcId(Handle());
}

bool Process::is_current() const {
  return is_current_process_;
}

void Process::Close() {
  is_current_process_ = false;
  if (!process_.IsValid())
    return;

  process_.Close();
}

bool Process::Terminate(int exit_code, bool wait) const {
  constexpr DWORD kWaitMs = 60 * 1000;

  // exit_code cannot be implemented.
  DCHECK(IsValid());
  bool result = (::TerminateProcess(Handle(), exit_code) != FALSE);
  if (result) {
    // The process may not end immediately due to pending I/O
    if (wait && ::WaitForSingleObject(Handle(), kWaitMs) != WAIT_OBJECT_0)
      DPLOG(ERROR) << "Error waiting for process exit";
    Exited(exit_code);
  } else {
    // The process can't be terminated, perhaps because it has already
    // exited or is in the process of exiting. A non-zero timeout is necessary
    // here for the same reasons as above.
    DPLOG(ERROR) << "Unable to terminate process";
    if (::WaitForSingleObject(Handle(), kWaitMs) == WAIT_OBJECT_0) {
      DWORD actual_exit;
      Exited(::GetExitCodeProcess(Handle(), &actual_exit) ? actual_exit
                                                          : exit_code);
      result = true;
    }
  }
  return result;
}

bool Process::WaitForExit(int* exit_code) const {
  return WaitForExitWithTimeout(TimeDelta::FromMilliseconds(INFINITE),
                                exit_code);
}

bool Process::WaitForExitWithTimeout(TimeDelta timeout, int* exit_code) const {
  if (!timeout.is_zero())
    internal::AssertBaseSyncPrimitivesAllowed();

  // Record the event that this thread is blocking upon (for hang diagnosis).
  base::debug::ScopedProcessWaitActivity process_activity(this);

  // Limit timeout to INFINITE.
  DWORD timeout_ms = saturated_cast<DWORD>(timeout.InMilliseconds());
  if (::WaitForSingleObject(Handle(), timeout_ms) != WAIT_OBJECT_0)
    return false;

  DWORD temp_code;  // Don't clobber out-parameters in case of failure.
  if (!::GetExitCodeProcess(Handle(), &temp_code))
    return false;

  if (exit_code)
    *exit_code = temp_code;

  Exited(temp_code);
  return true;
}

void Process::Exited(int exit_code) const {
  base::debug::GlobalActivityTracker::RecordProcessExitIfEnabled(Pid(),
                                                                 exit_code);
}

bool Process::IsProcessBackgrounded() const {
  DCHECK(IsValid());
  DWORD priority = GetPriority();
  if (priority == 0)
    return false;  // Failure case.
  return ((priority == BELOW_NORMAL_PRIORITY_CLASS) ||
          (priority == IDLE_PRIORITY_CLASS));
}

bool Process::SetProcessBackgrounded(bool value) {
  DCHECK(IsValid());
  // Vista and above introduce a real background mode, which not only
  // sets the priority class on the threads but also on the IO generated
  // by it. Unfortunately it can only be set for the calling process.
  DWORD priority;
  if (is_current()) {
    priority = value ? PROCESS_MODE_BACKGROUND_BEGIN :
                       PROCESS_MODE_BACKGROUND_END;
  } else {
    priority = value ? IDLE_PRIORITY_CLASS : NORMAL_PRIORITY_CLASS;
  }

  return (::SetPriorityClass(Handle(), priority) != 0);
}

int Process::GetPriority() const {
  DCHECK(IsValid());
  return ::GetPriorityClass(Handle());
}


HANDLE OpenProcessByID(const DWORD id)
{
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
  if (!hProcess)
  {
    LOG(INFO) << "OpenProcess failed, id = " << id << " error = " << std::strerror(::GetLastError());
    return NULL;
  }
  return hProcess;
}

DWORD GetProcessID(const wchar_t *name, int32_t sessionId)
{
  DWORD currentProcessId = ::GetProcessId(GetCurrentProcess());
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE)
  {
    LOG(ERROR) << "CreateToolhelp32Snapshot failed, name = " << name;
    return 0;
  }

  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);
  if (!Process32First(hSnapshot, &pe32))
  {
    LOG(ERROR) << "Process32First failed, name = " << name;
    CloseHandle(hSnapshot);
    return 0;
  }

  DWORD id = 0;
  while (Process32Next(hSnapshot, &pe32))
  {
    if (_wcsicmp(pe32.szExeFile, name) == 0 && currentProcessId != pe32.th32ProcessID)
    {
      if (sessionId != -1)
      {
        DWORD processSessionId = 0;
        ProcessIdToSessionId(pe32.th32ProcessID, &processSessionId);
        if (processSessionId == sessionId)
        {
          id = pe32.th32ProcessID;
          break;
        }
      }
      else
      {
        id = pe32.th32ProcessID;
        break;
      }
    }
  }

  CloseHandle(hSnapshot);
  return id;
}

HANDLE OpenProcessByProcessName(const wchar_t *name, int32_t sessionId)
{
  DWORD dwPID = GetProcessID(name, sessionId);
  if (dwPID != 0)
    return OpenProcessByID(dwPID);

  LOG(INFO) << "OpenProcessByProcessNmae failed, name = " << name;
  return NULL;
}

bool RunAsAdmin(const wchar_t* path, const wchar_t* param)
{
  LOG(INFO) << "RunAsAdmin path = " << path;
  SHELLEXECUTEINFO execinfo;
  memset(&execinfo, 0, sizeof(execinfo));
  execinfo.lpFile = path;
  execinfo.cbSize = sizeof(execinfo);
  execinfo.lpVerb = L"runas";
  execinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
  execinfo.nShow = SW_HIDE;
  execinfo.lpParameters = param;
  BOOL ret = ShellExecuteExW(&execinfo);
  if (ret && execinfo.hProcess)
    ::CloseHandle(execinfo.hProcess);
  else
    LOG(ERROR) << "ShellExecuteExW failed, path = " << path;
  return !!ret;
}

bool RunAsAdminAndWaitExit(const wchar_t* path, const wchar_t* param, DWORD* exitCode)
{
  LOG(INFO) << "RunAsAdminAndWaitExit path = " << path;
  SHELLEXECUTEINFO execinfo;
  memset(&execinfo, 0, sizeof(execinfo));
  execinfo.lpFile = path;
  execinfo.cbSize = sizeof(execinfo);
  execinfo.lpVerb = L"runas";
  execinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
  execinfo.nShow = SW_HIDE;
  execinfo.lpParameters = param;
  BOOL ret = ShellExecuteExW(&execinfo);
  if (!ret)
  {
    LOG(ERROR) << "ShellExecuteExW failed, path = " << path;
    return false;
  }

  DWORD waitRet = ::WaitForSingleObject(execinfo.hProcess, INFINITE);
  if (waitRet != WAIT_OBJECT_0)
  {
    LOG(ERROR) << "WaitForSingleObject failed, path = " << path;
    return false;
  }

  ret = ::GetExitCodeProcess(execinfo.hProcess, exitCode);
  ::CloseHandle(execinfo.hProcess);
  return !!ret;
}

DWORD GetMainThreadID(DWORD pid)
{
  HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
  if (hThreadSnap == INVALID_HANDLE_VALUE)
  {
    LOG(ERROR) << "CreateToolhelp32Snapshot failed, pid = " << pid;
    return 0;
  }

  DWORD tid = 0;
  THREADENTRY32 te32 = { 0 };
  te32.dwSize = sizeof(THREADENTRY32);
  if (!Thread32First(hThreadSnap, &te32))
  {
    LOG(ERROR) << "Thread32First failed, pid = " << pid;
    ::CloseHandle(hThreadSnap);
    return 0;
  }

  do
  {
    if (te32.th32OwnerProcessID == pid)
    {
      tid = te32.th32ThreadID;
      break;
    }
  } while (Thread32Next(hThreadSnap, &te32));

  if (tid == 0)
  {
    LOG(ERROR) << "Thread32Next failed, pid = " << pid;
  }
  ::CloseHandle(hThreadSnap);
  return tid;
}

typedef void (WINAPI *PFN_GetNativeSystemInfo)(LPSYSTEM_INFO);
int GetSystemBits()
{
  SYSTEM_INFO si;
  HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
  PFN_GetNativeSystemInfo pfnGetNativeSystemInfo = (PFN_GetNativeSystemInfo)GetProcAddress(hKernel32, "GetNativeSystemInfo");
  if (!pfnGetNativeSystemInfo)
  {
    LOG(ERROR) << "pfnGetNativeSystemInfo is null";
    return 32;
  }

  pfnGetNativeSystemInfo(&si);
  if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
    return 64;

  return 32;
}

BOOL Is64BitPorcess(DWORD dwProcessID)
{
  BOOL ret = FALSE;
  if (GetSystemBits() != 64)
    return FALSE;

  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessID);
  if (!hProcess)
  {
    LOG(ERROR) << "OpenProcess failed, dwProcessID = " << dwProcessID;
    return FALSE;
  }

  typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
  LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");
  if (NULL == fnIsWow64Process)
  {
    LOG(ERROR) << "GetProcAddress IsWow64Process failed";
    return FALSE;
  }

  BOOL bIsWow64 = FALSE;
  fnIsWow64Process(hProcess, &bIsWow64);
  if (!bIsWow64)
    ret = TRUE;
  CloseHandle(hProcess);
  return ret;
}

}  // namespace base
