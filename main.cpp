#define WIN32_LEAN_AND_MEAN

#include <errhandlingapi.h>
#include <fileapi.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>
#include <winnt.h>
#include <winreg.h>

struct WatchState {
  OVERLAPPED overlapped;
  HANDLE hDirectory;
  std::vector<BYTE> buffer;
  std::wstring directoryPath;
};

enum class SteamAppState {
  Unknown,
  Suspended,
  Installing,
  Installed,
  Uninstalled
};

bool shutdownStarted = false;
int currentAppID = -1;
int storedAppID = -1;
SteamAppState lastState = SteamAppState::Unknown;

int ExtractAppID(const std::string &line) {
  std::cout << "Extracting AppID from line: " << line << std::endl;
  std::string key = "AppID";
  size_t pos = line.find(key);
  if (pos != std::string::npos) {
    size_t start = pos + key.length() + 1;

    size_t end = line.find(' ', start);

    if (end != std::string::npos) {
      std::string idStr = line.substr(start, end - start);
      try {
        return std::stoi(idStr);
      } catch (...) {
        return -1;
      }
    }
  }
  return -1;
}

void StartShutdown(bool abort) {
  if (!abort && !shutdownStarted) {
    shutdownStarted = true;
    std::cout << "System will shutdown in 1 minute..." << std::endl;
    BOOL result = InitiateSystemShutdownExW(NULL, NULL, 60, TRUE, FALSE,
                                            SHTDN_REASON_MAJOR_OTHER |
                                                SHTDN_REASON_MINOR_OTHER |
                                                SHTDN_REASON_FLAG_PLANNED);
    if (!result) {
      std::cerr << "Failed to initiate shutdown. Error Code: " << GetLastError()
                << std::endl;
    }
  } else if (abort) {
    shutdownStarted = false;
    AbortSystemShutdownW(NULL);
  }
}

std::string StateToString(SteamAppState state) {
  switch (state) {
  case SteamAppState::Suspended:
    return "SUSPENDED";
  case SteamAppState::Installed:
    return "INSTALLED";
  case SteamAppState::Installing:
    return "INSTALLING";
  case SteamAppState::Uninstalled:
    return "UNINSTALLED";
  default:
    return "UNKNOWN/PROCESSING";
  }
}

SteamAppState ParseSteamLogState(const std::string &logContent) {
  std::istringstream stream(logContent);
  std::string line;
  std::vector<std::string> lines;

  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (!line.empty()) {
      lines.push_back(line);
    }
  }

  for (auto it = lines.rbegin(); it != lines.rend(); ++it) {
    std::string &currentLine = *it;

    if (currentLine.find("AppID") == std::string::npos) {
      continue;
    }

    currentAppID = ExtractAppID(currentLine);

    if (currentLine.find("Uninstalled") != std::string::npos ||
        currentLine.find(
            "removed from schedule (result Canceled, state 0x202)") !=
            std::string::npos) {
      return SteamAppState::Uninstalled;
    }

    if (currentLine.find("result Suspended") != std::string::npos) {
      return SteamAppState::Suspended;
    }

    if (currentLine.find("scheduler finished") != std::string::npos &&
        currentLine.find("result No Error") != std::string::npos) {
      return SteamAppState::Installed;
    }

    if (currentLine.find("Running Update,Preallocating,") !=
        std::string::npos) {
      return SteamAppState::Installing;
    }
  }

  return SteamAppState::Unknown;
}

void CALLBACK ChangeCallback(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered,
                             LPOVERLAPPED lpOverlapped) {
  if (dwErrorCode == ERROR_SUCCESS) {

    WatchState *state = (WatchState *)lpOverlapped;

    FILE_NOTIFY_INFORMATION *pNotify = nullptr;
    size_t offset = 0;
    do {
      pNotify = (FILE_NOTIFY_INFORMATION *)(state->buffer.data() + offset);
      if (pNotify == nullptr) {
        break;
      }
      if (pNotify->Action == FILE_ACTION_MODIFIED) {
        std::wstring fileName(pNotify->FileName,
                              pNotify->FileNameLength / sizeof(WCHAR));

        if (fileName != L"content_log.txt") {
          continue;
        }

        std::wstring fullPath = state->directoryPath + L"\\" + fileName;
        HANDLE hFile =
            CreateFileW(fullPath.c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile != INVALID_HANDLE_VALUE) {
          const DWORD fileSize = GetFileSize(hFile, NULL);
          std::vector<char> fileBuffer(fileSize + 1);
          DWORD bytesRead;

          if (ReadFile(hFile, fileBuffer.data(), fileSize, &bytesRead, NULL)) {
            fileBuffer[bytesRead] = '\0';

            std::string content(fileBuffer.data());

            SteamAppState currentState = ParseSteamLogState(content);

            std::cout << "------------------------------------------------"
                      << std::endl;
            std::cout << "Log Parse Result: " << StateToString(currentState)
                      << std::endl;
            std::cout << "AppID: " << currentAppID << std::endl;

            if (storedAppID != currentAppID && currentAppID != -1) {
              std::cout << "Detected new AppID: " << currentAppID << std::endl;
              storedAppID = currentAppID;
              shutdownStarted = false;
              StartShutdown(true);
            }

            switch (currentState) {
            case SteamAppState::Uninstalled:
              std::cout
                  << "Detected uninstallation. Aborting any pending shutdown."
                  << std::endl;
              StartShutdown(true);
              storedAppID = -1;
              break;

            case SteamAppState::Suspended:
              std::cout << "Download suspended. Aborting shutdown."
                        << std::endl;
              StartShutdown(true);
              break;

            case SteamAppState::Installing:
              std::cout << "Installation in progress." << std::endl;
              StartShutdown(true);
              break;

            case SteamAppState::Installed:
              std::cout << "Installation completed successfully." << std::endl;
              std::cout << "If no changes are detected within 60 seconds, "
                           "shutdown will start."
                        << std::endl;
              StartShutdown(false);
              break;

            case SteamAppState::Unknown:
            default:
              break;
            }

            lastState = currentState;

          } else {
            std::wcerr << L"Failed to read content_log.txt. Error Code: "
                       << GetLastError() << std::endl;
          }
          CloseHandle(hFile);
        } else {
          std::wcerr << L"Failed to open content_log.txt. Error Code: "
                     << GetLastError() << std::endl;
        }
      }
      offset += pNotify->NextEntryOffset;
    } while (pNotify->NextEntryOffset != 0);

    ReadDirectoryChangesW(state->hDirectory, state->buffer.data(),
                          state->buffer.size(), TRUE,
                          FILE_NOTIFY_CHANGE_LAST_WRITE, NULL,
                          &state->overlapped, ChangeCallback);

  } else {
    std::wcerr << L"Callback error: " << dwErrorCode << std::endl;
  }
}

int main() {
  std::wstring steamPath;
  steamPath.resize(MAX_PATH);

  // from
  // https://www.daniweb.com/programming/software-development/threads/182433/how-to-shutdown-your-computer-using-c
  HANDLE tok{};
  if (OpenProcessToken(GetCurrentProcess(),
                       TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
    LUID luid{};
    TOKEN_PRIVILEGES tp{};
    if (LookupPrivilegeValue(nullptr, SE_SHUTDOWN_NAME, &luid)) {
      tp.PrivilegeCount = 1;
      tp.Privileges[0].Luid = luid;
      tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
      AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr, nullptr);
    }
    CloseHandle(tok);
  }

  DWORD size = steamPath.size();
  LONG status = RegGetValueW(
      HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Valve\\Steam",
      L"InstallPath", RRF_RT_REG_SZ, nullptr, &steamPath[0], &size);

  if (status == ERROR_SUCCESS) {
    steamPath.resize((size / sizeof(wchar_t)) - 1);
    std::wcout << L"Steam Install Path: " << &steamPath[0] << std::endl;

    std::wstring LogPath = steamPath + L"\\logs";
    std::wstring LogContentPath = steamPath + L"\\logs\\content_log.txt";
    std::wcout << L"Watching: " << LogContentPath << std::endl;

    HANDLE hDirectory = CreateFileW(
        LogPath.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);

    if (hDirectory == INVALID_HANDLE_VALUE) {
      std::wcerr << L"Failed to open log directory. Error Code: "
                 << GetLastError() << std::endl;
      return GetLastError();
    } else {
      std::wcout << L"Successfully opened log directory." << std::endl;

      auto *state = new WatchState{.overlapped = {},
                                   .hDirectory = hDirectory,
                                   .buffer = std::vector<BYTE>(4096),
                                   .directoryPath = LogPath};

      HANDLE hLogFile =
          CreateFileW(LogContentPath.c_str(), GENERIC_READ,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

      if (hLogFile != INVALID_HANDLE_VALUE) {
        DWORD fileSize = GetFileSize(hLogFile, NULL);
        if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
          std::vector<char> fileBuffer(fileSize + 1);
          DWORD bytesRead;

          if (ReadFile(hLogFile, fileBuffer.data(), fileSize, &bytesRead,
                       NULL)) {
            fileBuffer[bytesRead] = '\0';
            std::string content(fileBuffer.data());

            SteamAppState currentState = ParseSteamLogState(content);
            std::wcout << L"Current state: "
                       << StateToString(currentState).c_str() << std::endl;

            if (currentAppID != -1) {
              storedAppID = currentAppID;
              std::wcout << L"Current AppID: " << currentAppID << std::endl;
            }

            if (currentState == SteamAppState::Installed) {
              std::cout << "Installation already complete. Exiting..."
                        << std::endl;
              return 0;
            }

            lastState = currentState;
          }
        }
        CloseHandle(hLogFile);
      } else {
        std::wcout << L"Unable to open log file, exiting..." << std::endl;
        return 0;
      }

      BOOL result =
          ReadDirectoryChangesW(state->hDirectory, state->buffer.data(),
                                static_cast<DWORD>(state->buffer.size()), TRUE,
                                FILE_NOTIFY_CHANGE_LAST_WRITE, NULL,
                                &state->overlapped, ChangeCallback);

      if (!result) {
        std::wcerr << L"Failed to start watch. Error Code: " << GetLastError()
                   << std::endl;
        delete state;
        return GetLastError();
      }

      std::wcout << L"Waiting for changes..." << std::endl;

      while (true) {
        SleepEx(INFINITE, TRUE);
      }
    }

  } else {
    std::cout << "Failed to read registry key. Error Code: " << status
              << std::endl;
    return status;
  }
}