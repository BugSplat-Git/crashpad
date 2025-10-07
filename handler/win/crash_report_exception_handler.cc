// Copyright 2015 The Crashpad Authors
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

#include "handler/win/crash_report_exception_handler.h"

#include <type_traits>
#include <utility>
#include <sstream>

#include "base/strings/utf_string_conversions.h"
#include "snapshot/win/process_snapshot_win.h"
#include "client/crash_report_database.h"
#include "client/settings.h"
#include "handler/crash_report_upload_thread.h"
#include "minidump/minidump_file_writer.h"
#include "minidump/minidump_user_extension_stream_data_source.h"
#include "snapshot/win/process_snapshot_win.h"
#include "util/file/file_helper.h"
#include "util/file/file_writer.h"
#include "util/misc/metrics.h"
#include "util/win/registration_protocol_win.h"
#include "util/win/scoped_process_suspend.h"
#include "util/win/termination_codes.h"

namespace crashpad {

namespace {

// Dialog communication structures
struct DialogRequest {
  char report_id[37];  // UUID string + null terminator
  char process_name[MAX_PATH];
};

const wchar_t kDialogPipeName[] = L"\\\\.\\pipe\\CrashpadDialogPipe";
const wchar_t kDialogAppName[] = L"CustomerCrashDialog.exe";

}  // namespace

CrashReportExceptionHandler::CrashReportExceptionHandler(
    CrashReportDatabase* database,
    CrashReportUploadThread* upload_thread,
    const std::map<std::string, std::string>* process_annotations,
    const std::vector<base::FilePath>* attachments,
    const UserStreamDataSources* user_stream_data_sources,
    bool enable_crash_dialog)
    : database_(database),
      upload_thread_(upload_thread),
      process_annotations_(process_annotations),
      attachments_(attachments),
      user_stream_data_sources_(user_stream_data_sources),
      enable_crash_dialog_(enable_crash_dialog) {}

CrashReportExceptionHandler::~CrashReportExceptionHandler() {}

void CrashReportExceptionHandler::ExceptionHandlerServerStarted() {}

// Launches the customer dialog application and waits for response
DialogResponse CrashReportExceptionHandler::LaunchDialogAndGetResponse(
    const UUID& report_id,
    const std::string& process_name) {
  DialogResponse response = {false, "", ""};

  // Create named pipe for communication
  HANDLE pipe = CreateNamedPipe(
      kDialogPipeName,
      PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
      1,  // Max instances
      sizeof(DialogRequest),  // Output buffer size
      sizeof(DialogResponse), // Input buffer size
      30000,  // Timeout (30 seconds)
      nullptr);

  if (pipe == INVALID_HANDLE_VALUE) {
    LOG(ERROR) << "Failed to create named pipe for dialog communication";
    return response;
  }

  // Prepare dialog request
  DialogRequest request;
  std::string report_id_str = report_id.ToString();
  strncpy_s(request.report_id, report_id_str.c_str(), sizeof(request.report_id) - 1);
  strncpy_s(request.process_name, process_name.c_str(), sizeof(request.process_name) - 1);

  // Launch dialog application
  std::wstringstream command_stream;
  command_stream << kDialogAppName << L" " << base::UTF8ToWide(report_id_str);

  STARTUPINFO si = { sizeof(si) };
  PROCESS_INFORMATION pi;

  if (CreateProcess(nullptr,
                   const_cast<wchar_t*>(command_stream.str().c_str()),
                   nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {

    // Wait for dialog to connect to pipe
    if (ConnectNamedPipe(pipe, nullptr)) {
      // Send request to dialog
      DWORD bytes_written;
      if (::WriteFile(pipe, &request, sizeof(request), &bytes_written, nullptr)) {
        // Wait for response (with timeout)
        DWORD bytes_read;
        DWORD wait_result = WaitForSingleObject(pipe, 30000);  // 30 second timeout

        if (wait_result == WAIT_OBJECT_0 &&
            ::ReadFile(pipe, &response, sizeof(response), &bytes_read, nullptr)) {
          // Successfully received response
        }
      }
    }

    // Clean up dialog process
    WaitForSingleObject(pi.hProcess, 5000);  // Wait up to 5 seconds
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  }

  CloseHandle(pipe);
  return response;
}

unsigned int CrashReportExceptionHandler::ExceptionHandlerServerException(
    HANDLE process,
    WinVMAddress exception_information_address,
    WinVMAddress debug_critical_section_address) {
  Metrics::ExceptionEncountered();

  ScopedProcessSuspend suspend(process);

  ProcessSnapshotWin process_snapshot;
  if (!process_snapshot.Initialize(process,
                                   ProcessSuspensionState::kSuspended,
                                   exception_information_address,
                                   debug_critical_section_address)) {
    Metrics::ExceptionCaptureResult(Metrics::CaptureResult::kSnapshotFailed);
    return kTerminationCodeSnapshotFailed;
  }

  // Now that we have the exception information, even if something else fails we
  // can terminate the process with the correct exit code.
  const unsigned int termination_code =
      process_snapshot.Exception()->Exception();
  static_assert(
      std::is_same<std::remove_const<decltype(termination_code)>::type,
                   decltype(process_snapshot.Exception()->Exception())>::value,
      "expected ExceptionCode() and process termination code to match");

  Metrics::ExceptionCode(termination_code);

  CrashpadInfoClientOptions client_options;
  process_snapshot.GetCrashpadOptions(&client_options);
  if (client_options.crashpad_handler_behavior != TriState::kDisabled) {
    UUID client_id;
    Settings* const settings = database_->GetSettings();
    if (settings && settings->GetClientID(&client_id)) {
      process_snapshot.SetClientID(client_id);
    }

    process_snapshot.SetAnnotationsSimpleMap(*process_annotations_);

    std::unique_ptr<CrashReportDatabase::NewReport> new_report;
    CrashReportDatabase::OperationStatus database_status =
        database_->PrepareNewCrashReport(&new_report);
    if (database_status != CrashReportDatabase::kNoError) {
      LOG(ERROR) << "PrepareNewCrashReport failed";
      Metrics::ExceptionCaptureResult(
          Metrics::CaptureResult::kPrepareNewCrashReportFailed);
      return termination_code;
    }

    process_snapshot.SetReportID(new_report->ReportID());

    MinidumpFileWriter minidump;
    minidump.InitializeFromSnapshot(&process_snapshot);
    AddUserExtensionStreams(
        user_stream_data_sources_, &process_snapshot, &minidump);

    if (!minidump.WriteEverything(new_report->Writer())) {
      LOG(ERROR) << "WriteEverything failed";
      Metrics::ExceptionCaptureResult(
          Metrics::CaptureResult::kMinidumpWriteFailed);
      return termination_code;
    }

    for (const auto& attachment : (*attachments_)) {
      FileReader file_reader;
      if (!file_reader.Open(attachment)) {
        LOG(ERROR) << "attachment " << attachment
                   << " couldn't be opened, skipping";
        continue;
      }

      base::FilePath filename = attachment.BaseName();
      FileWriter* file_writer =
          new_report->AddAttachment(base::WideToUTF8(filename.value()));
      if (file_writer == nullptr) {
        LOG(ERROR) << "attachment " << filename
                   << " couldn't be created, skipping";
        continue;
      }

      CopyFileContent(&file_reader, file_writer);
    }

    UUID uuid;
    database_status =
        database_->FinishedWritingCrashReport(std::move(new_report), &uuid);
    if (database_status != CrashReportDatabase::kNoError) {
      LOG(ERROR) << "FinishedWritingCrashReport failed";
      Metrics::ExceptionCaptureResult(
          Metrics::CaptureResult::kFinishedWritingCrashReportFailed);
      return termination_code;
    }

    // NEW: Handle crash dialog if enabled
    if (enable_crash_dialog_) {
      // Get process name for dialog
      std::string process_name = "Unknown Process";

      // Extract actual process name from process snapshot
      ProcessSnapshotWin process_snapshot_for_name;
      if (process_snapshot_for_name.Initialize(process,
                                             ProcessSuspensionState::kRunning,
                                             exception_information_address,
                                             debug_critical_section_address)) {
        const std::vector<const ModuleSnapshot*> modules = process_snapshot_for_name.Modules();
        if (!modules.empty()) {
          std::string module_name = modules[0]->Name();
          // Extract just the filename from the full path
          size_t last_slash = module_name.find_last_of("\\/");
          if (last_slash != std::string::npos) {
            process_name = module_name.substr(last_slash + 1);
          } else {
            process_name = module_name;
          }
        }
      }

      // Launch dialog and get response
      DialogResponse dialog_response = LaunchDialogAndGetResponse(uuid, process_name);

      // If user cancelled or dialog failed, don't upload
      if (!dialog_response.should_upload) {
        Metrics::ExceptionCaptureResult(Metrics::CaptureResult::kSuccess);
        return termination_code;
      }

      // Add user input to process annotations for upload
      if (strlen(dialog_response.user_email) > 0) {
        // Note: We need to modify process_annotations_ to include dialog data
        // For now, we'll log it - in a full implementation, you'd modify the annotations
        LOG(INFO) << "User email: " << dialog_response.user_email;
        LOG(INFO) << "User description: " << dialog_response.user_description;
      }
    }

    if (upload_thread_) {
      upload_thread_->ReportPending(uuid);
    }
  }

  Metrics::ExceptionCaptureResult(Metrics::CaptureResult::kSuccess);
  return termination_code;
}

}  // namespace crashpad
