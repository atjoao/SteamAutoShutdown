#include <cstdio>
#include <errhandlingapi.h>
#include <fileapi.h>
#include <minwindef.h>
#include <windows.h>
#include <winnt.h>
#include <winreg.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>

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

// Helper to extract the AppID integer from a log line
int ExtractAppID(const std::string& line) {
    std::cout << "Extracting AppID from line: " << line << std::endl;
    std::string key = "AppID";
    size_t pos = line.find(key);
    if (pos != std::string::npos) {
        // Move position to end of "AppID" + 1 for space
        size_t start = pos + key.length() + 1;
        
        // Find the next space (or end of string) to isolate the number
        size_t end = line.find(' ', start);
        
        if (end != std::string::npos) {
            std::string idStr = line.substr(start, end - start);
            try {
                return std::stoi(idStr);
            } catch (...) {
                return -1; // Conversion failed
            }
        }
    }
    return -1; // Not found
}

void StartShutdown(bool abort) {
    if (abort == false && shutdownStarted == false) {
        shutdownStarted = true;
        std::cout << "System will shutdown in 1 minute..." << std::endl;
        BOOL result = InitiateSystemShutdownExW(
            NULL,
            NULL, 
            60,
            TRUE,
            FALSE,
            SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED
        );
        if (!result) {
            std::cerr << "Failed to initiate shutdown. Error Code: " << GetLastError() << std::endl;
        }
    } else if (abort == true) {
        shutdownStarted = false;
        AbortSystemShutdownW(NULL);
    }
}

std::string StateToString(SteamAppState state) {
    switch (state) {
        case SteamAppState::Suspended: return "SUSPENDED";
        case SteamAppState::Installed: return "INSTALLED";
        case SteamAppState::Installing: return "INSTALLING";
        case SteamAppState::Uninstalled: return "UNINSTALLED";
        default: return "UNKNOWN/PROCESSING";
    }
}

SteamAppState ParseSteamLogState(const std::string& logContent) {
    std::istringstream stream(logContent);
    std::string line;
    std::vector<std::string> lines;

    // 1. Split content into lines
    while (std::getline(stream, line)) {
        // Remove carriage returns if present (Windows format)
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    // 2. Iterate BACKWARDS to find the most recent relevant state
    for (auto it = lines.rbegin(); it != lines.rend(); ++it) {
        std::string& currentLine = *it;

        // 3. Filter Noise: Ignore lines that don't talk about AppID 
        // (This skips the HTTP, stats, and download rate lines)
        if (currentLine.find("AppID") == std::string::npos) {
            continue;
        }

        currentAppID = ExtractAppID(currentLine);

        // 4. Check for UNINSTALLED
        // Pattern: "finished uninstall (No Error)"
        if (currentLine.find("Uninstalled") != std::string::npos || 
            currentLine.find("removed from schedule (result Canceled, state 0x202)") != std::string::npos) {
            return SteamAppState::Uninstalled;
        }

        // 5. Check for SUSPENDED
        // Pattern: "result Suspended"
        if (currentLine.find("result Suspended") != std::string::npos) {
            return SteamAppState::Suspended;
        }

        // 6. Check for INSTALLED
        // Pattern: "scheduler finished" AND "result No Error"
        // Note: We prioritize "scheduler finished" as the final confirmation over "state changed"
        if (currentLine.find("scheduler finished") != std::string::npos && 
            currentLine.find("result No Error") != std::string::npos) {
            return SteamAppState::Installed;
        }

        if (currentLine.find("Running Update,Preallocating,") != std::string::npos) {
            return SteamAppState::Installing;
        }
    }

    return SteamAppState::Unknown;
}

void CALLBACK ChangeCallback(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped) {
    if (dwErrorCode == ERROR_SUCCESS) {
        
        WatchState* state = (WatchState*)lpOverlapped;

        FILE_NOTIFY_INFORMATION* pNotify;
        size_t offset = 0;
        do {
            pNotify = (FILE_NOTIFY_INFORMATION*)(state->buffer.data() + offset);
            if (pNotify->Action == FILE_ACTION_MODIFIED) {
                std::wstring fileName(pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR));
                
                if (fileName != L"content_log.txt") {
                    offset += pNotify->NextEntryOffset;
                    continue;
                }

                std::wstring fullPath = state->directoryPath + L"\\" + fileName;
                HANDLE hFile = CreateFileW(
                    fullPath.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL
                );

                if (hFile != INVALID_HANDLE_VALUE) {
                    const DWORD fileSize = GetFileSize(hFile, NULL);
                    std::vector<char> fileBuffer(fileSize + 1); 
                    DWORD bytesRead;
                    
                    if (ReadFile(hFile, fileBuffer.data(), fileSize, &bytesRead, NULL)) {
                        fileBuffer[bytesRead] = '\0';
                        
                        std::string content(fileBuffer.data());
                        
                        SteamAppState currentState = ParseSteamLogState(content);
                        
                        std::cout << "------------------------------------------------" << std::endl;
                        std::cout << "Log Parse Result: " << StateToString(currentState) << std::endl;
                        std::cout << "AppID: " << currentAppID << std::endl;
                        
                        if (lastState == SteamAppState::Uninstalled){
                            std::cout << "Detected uninstallation. Aborting any pending shutdown." << std::endl;
                            StartShutdown(true);
                            storedAppID = -1;
                            lastState = SteamAppState::Unknown;
                            offset += pNotify->NextEntryOffset;
                            CloseHandle(hFile);
                            continue;
                        }
                        

                        if (storedAppID != currentAppID) {
                            storedAppID = currentAppID;
                            shutdownStarted = false;
                            std::cout << "Detected new AppID." << std::endl;
                            StartShutdown(true);
                        }

                        if (currentState == SteamAppState::Installing) {
                            std::cout << "Installation in progress." << std::endl;
                            StartShutdown(true);
                        }

                        if (currentState == SteamAppState::Installed) {
                            std::cout << "Installation completed successfully." << std::endl;
                            std::cout << "If no changes are detected winhtin 60 seconds shutdown will start." << std::endl;
                            StartShutdown(false);
                        }
                        
                    } else {
                        std::wcerr << L"Failed to read content_log.txt. Error Code: " << GetLastError() << std::endl;
                    }
                    CloseHandle(hFile);
                } else {
                    std::wcerr << L"Failed to open content_log.txt. Error Code: " << GetLastError() << std::endl;
                }
            }
            offset += pNotify->NextEntryOffset;
        } while (pNotify->NextEntryOffset != 0);
        
        // Reset the watch
        ReadDirectoryChangesW(
            state->hDirectory,
            state->buffer.data(),
            state->buffer.size(),
            TRUE,
            FILE_NOTIFY_CHANGE_LAST_WRITE,
            NULL,
            &state->overlapped,
            ChangeCallback
        );

    } else {
        std::wcerr << L"Callback error: " << dwErrorCode << std::endl;
    }
}

int main(){
    std::wstring steamPath;
    steamPath.resize(MAX_PATH);

    // from https://www.daniweb.com/programming/software-development/threads/182433/how-to-shutdown-your-computer-using-c
    HANDLE tok{};
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &tok)) {
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
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\WOW6432Node\\Valve\\Steam",
            L"InstallPath",
            RRF_RT_REG_SZ,
            nullptr,
            &steamPath[0],
            &size);
            
    if (status == ERROR_SUCCESS) {
        steamPath.resize((size / sizeof(wchar_t)) - 1);
        std::wcout << L"Steam Install Path: " << &steamPath[0] << std::endl;

        std::wstring LogPath = steamPath + L"\\logs";
        std::wstring LogContentPath = steamPath + L"\\logs\\content_log.txt";
        std::wcout << L"Watching: " << LogContentPath << std::endl;

        HANDLE hDirectory = CreateFileW(
                LogPath.c_str(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                NULL
        );
        
        if (hDirectory == INVALID_HANDLE_VALUE) {
            std::wcerr << L"Failed to open log directory. Error Code: " << GetLastError() << std::endl;
            return GetLastError();
        } else {
            std::wcout << L"Successfully opened log directory." << std::endl;
            
            WatchState* state = new WatchState;
            state->hDirectory = hDirectory;
            state->directoryPath = LogPath;
            state->buffer.resize(4096);
            memset(&state->overlapped, 0, sizeof(OVERLAPPED));

            BOOL result = ReadDirectoryChangesW(
                hDirectory,
                state->buffer.data(),
                state->buffer.size(),
                TRUE,
                FILE_NOTIFY_CHANGE_LAST_WRITE,
                NULL,
                &state->overlapped,
                ChangeCallback
            );

            if (!result) {
                std::wcerr << L"Failed to start watch. Error Code: " << GetLastError() << std::endl;
                return GetLastError();
            }

            std::wcout << L"Waiting for changes..." << std::endl;

            while (true) {
                SleepEx(INFINITE, TRUE);
            }
        }
            
    } else {
        std::cout << "Failed to read registry key. Error Code: " << status << std::endl;
        return status;
    }
}