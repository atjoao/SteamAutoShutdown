#include <windows.h>
#include <winreg.h>

int main(){
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
    
    ExitWindowsEx(EWX_POWEROFF, 0);


    return 0;
}