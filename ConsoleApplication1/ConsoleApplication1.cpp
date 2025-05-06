#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <set>
#include <fstream>  // 추가: 파일 출력용
#include <algorithm>

#pragma comment(lib, "psapi.lib")

// 프로세스 이름으로 프로세스 ID 찾기
DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &pe32)) {
            do {
                if (wcscmp(pe32.szExeFile, processName) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }

    return pid;
}

// 장치 경로를 Windows 경로로 변환
std::string ConvertDevicePathToWindowsPath(const std::string& devicePath) {
    char deviceName[MAX_PATH];
    char driveLetter[3] = " :";

    // 각 드라이브 문자에 대해 시도
    for (char drive = 'A'; drive <= 'Z'; ++drive) {
        driveLetter[0] = drive;
        if (QueryDosDeviceA(driveLetter, deviceName, MAX_PATH) > 0) {
            size_t deviceNameLen = strlen(deviceName);
            if (devicePath.compare(0, deviceNameLen, deviceName) == 0) {
                return driveLetter + devicePath.substr(deviceNameLen);
            }
        }
    }
    
    return devicePath; // 변환 실패시 원래 경로 반환
}

// 메모리 페이지 정보 구조체
struct MemoryRegion {
    ULONG_PTR baseAddress;
    SIZE_T regionSize;
    std::string modulePath;
    bool isModule;
};

// 모듈 정보 구조체
struct ModuleInfo {
    std::string name;
    std::string path;
    ULONG_PTR baseAddress;
    SIZE_T size;
};

// 단일 메모리 영역 스캔하여 모듈 확인
bool ScanMemoryRegion(HANDLE hProcess, ULONG_PTR address, MemoryRegion& region) {
    MEMORY_BASIC_INFORMATION mbi;
    char pathBuffer[MAX_PATH] = {0};
    
    if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }
    
    // 페이지가 커밋된 상태이고 실행 속성을 가진 경우에만 확인
    if ((mbi.State & MEM_COMMIT) && 
        ((mbi.Protect & PAGE_EXECUTE) || 
         (mbi.Protect & PAGE_EXECUTE_READ) || 
         (mbi.Protect & PAGE_EXECUTE_READWRITE) || 
         (mbi.Protect & PAGE_EXECUTE_WRITECOPY))) {
        
        // 매핑된 파일 이름 가져오기
        memset(pathBuffer, 0, MAX_PATH);
        DWORD pathLen = GetMappedFileNameA(hProcess, (LPVOID)mbi.BaseAddress, pathBuffer, MAX_PATH);

        if (pathLen > 0) {
            region.baseAddress = (ULONG_PTR)mbi.BaseAddress;
            region.regionSize = mbi.RegionSize;
            region.modulePath = ConvertDevicePathToWindowsPath(pathBuffer);
            region.isModule = true;
            return true;
        }
    }
    
    return false;
}

// 파일 경로로부터 파일 크기 얻기
SIZE_T GetFileSizeFromPath(const std::string& filePath) {
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    
    if (GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
        ULARGE_INTEGER fileSize;
        fileSize.LowPart = fileInfo.nFileSizeLow;
        fileSize.HighPart = fileInfo.nFileSizeHigh;
        return static_cast<SIZE_T>(fileSize.QuadPart);
    }
    
    return 0; // 파일 정보를 얻지 못하면 0 반환
}

// PE 헤더에서 DLL 크기 정보 읽기
SIZE_T GetModuleSizeFromPEHeader(const std::string& filePath) {
    SIZE_T moduleSize = 0;
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        // DOS 헤더 읽기
        IMAGE_DOS_HEADER dosHeader;
        DWORD bytesRead = 0;
        
        if (ReadFile(hFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL) && bytesRead == sizeof(IMAGE_DOS_HEADER)) {
            // DOS 헤더 시그니처 확인 ("MZ")
            if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                // PE 헤더 위치로 이동
                if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
                    // PE 시그니처 읽기
                    DWORD peSignature = 0;
                    if (ReadFile(hFile, &peSignature, sizeof(DWORD), &bytesRead, NULL) && bytesRead == sizeof(DWORD)) {
                        // PE 시그니처 확인 ("PE\0\0")
                        if (peSignature == IMAGE_NT_SIGNATURE) {
                            // 파일 헤더 읽기
                            IMAGE_FILE_HEADER fileHeader;
                            if (ReadFile(hFile, &fileHeader, sizeof(IMAGE_FILE_HEADER), &bytesRead, NULL) && bytesRead == sizeof(IMAGE_FILE_HEADER)) {
                                // 선택적 헤더 읽기
                                if (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
                                    // 64비트 PE 파일
                                    IMAGE_OPTIONAL_HEADER64 optHeader;
                                    if (ReadFile(hFile, &optHeader, sizeof(IMAGE_OPTIONAL_HEADER64), &bytesRead, NULL) && bytesRead == sizeof(IMAGE_OPTIONAL_HEADER64)) {
                                        moduleSize = optHeader.SizeOfImage;
                                    }
                                } else {
                                    // 32비트 PE 파일
                                    IMAGE_OPTIONAL_HEADER32 optHeader;
                                    if (ReadFile(hFile, &optHeader, sizeof(IMAGE_OPTIONAL_HEADER32), &bytesRead, NULL) && bytesRead == sizeof(IMAGE_OPTIONAL_HEADER32)) {
                                        moduleSize = optHeader.SizeOfImage;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        CloseHandle(hFile);
    }
    
    return moduleSize;
}

// 메모리 스캔해서 모듈 찾기
std::vector<ModuleInfo> ScanProcessModules(HANDLE hProcess) {
    std::vector<MemoryRegion> memoryRegions;
    std::unordered_map<std::string, ULONG_PTR> foundModules; // 경로 -> 베이스 주소 매핑
    
    // Windows 64비트 환경에서 유저모드 주소 범위 설정
    ULONG_PTR startAddr = 0;
    ULONG_PTR endAddr = 0x00007FFFFFFFFFFF;  // 최대 유저모드 주소 공간
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    DWORD pageSize = sysInfo.dwPageSize;
    
    // 전체 메모리 영역을 브루트포싱
    ULONG_PTR addr = startAddr;
    while (addr < endAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T result = VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi));
        
        // VirtualQueryEx 호출 실패 시 처리
        if (result != sizeof(mbi)) {
            DWORD error = GetLastError();
            
            if (error == ERROR_INVALID_PARAMETER) {
                // 유효하지 않은 주소 영역, 큰 단위로 건너뛰기
                addr = (addr + 0x10000000) & ~(0xFFFFFFF);  // 256MB 간격으로 정렬
                if (addr < startAddr) break; // 오버플로우 체크
                continue;
            }
            
            // 다음 페이지로 이동
            addr = (addr + pageSize) & ~(pageSize - 1);
            if (addr < startAddr) break; // 오버플로우 체크
            continue;
        }
        
        // 할당되지 않은 공간은 빠르게 건너뛰기
        if (mbi.State == MEM_FREE) {
            if (mbi.RegionSize > 0) {
                addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
                if (addr < (ULONG_PTR)mbi.BaseAddress) break; // 오버플로우 체크
            } else {
                addr += pageSize;
            }
            continue;
        }
        
        // 커밋된 페이지가 실행 가능한 경우 모듈 확인
        if ((mbi.State & MEM_COMMIT) && 
            ((mbi.Protect & PAGE_EXECUTE) || 
             (mbi.Protect & PAGE_EXECUTE_READ) || 
             (mbi.Protect & PAGE_EXECUTE_READWRITE) || 
             (mbi.Protect & PAGE_EXECUTE_WRITECOPY) ||
             // 주요 데이터 섹션도 체크 (.data, .rdata 등)
             (mbi.Protect & PAGE_READONLY) ||
             (mbi.Protect & PAGE_READWRITE))) {
            
            char pathBuffer[MAX_PATH] = {0};
            DWORD pathLen = GetMappedFileNameA(hProcess, (LPVOID)mbi.AllocationBase, pathBuffer, MAX_PATH);
            
            if (pathLen > 0) {
                std::string modulePath = ConvertDevicePathToWindowsPath(pathBuffer);
                
                // 이미 발견된 모듈인지 확인
                if (foundModules.find(modulePath) == foundModules.end()) {
                    foundModules[modulePath] = (ULONG_PTR)mbi.AllocationBase;
                    
                    MemoryRegion region;
                    region.baseAddress = (ULONG_PTR)mbi.AllocationBase;
                    region.regionSize = 0;  // 나중에 계산
                    region.modulePath = modulePath;
                    region.isModule = true;
                    memoryRegions.push_back(region);
                }
            }
        }
        
        // 다음 영역으로 이동
        if (mbi.RegionSize > 0) {
            addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            if (addr < (ULONG_PTR)mbi.BaseAddress) break; // 오버플로우 체크
        } else {
            addr += pageSize;
        }
    }

    // 모듈 정보 생성
    std::vector<ModuleInfo> modules;
    
    for (const auto& region : memoryRegions) {
        ModuleInfo module;
        
        // 파일 이름 추출
        std::string path = region.modulePath;
        std::string name = path;
        size_t pos = path.find_last_of('\\');
        if (pos != std::string::npos) {
            name = path.substr(pos + 1);
        }
        
        module.name = name;
        // 백슬래시를 이중 백슬래시로 변환
        std::string escapedPath = path;
        size_t index = 0;
        while ((index = escapedPath.find('\\', index)) != std::string::npos) {
            escapedPath.replace(index, 1, "\\\\");
            index += 2; // 이중 백슬래시를 건너뛰기
        }
        module.path = escapedPath;
        module.baseAddress = region.baseAddress;
        
        // 파일 확장자 확인
        std::string extension;
        size_t extPos = name.find_last_of('.');
        if (extPos != std::string::npos) {
            extension = name.substr(extPos);
            std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
        }
        
        // 모듈 크기 가져오는 로직 개선
        // .dll, .exe 같은 Windows 실행 파일인 경우 PE 헤더 사용
        if (extension == ".dll" || extension == ".exe" || extension == ".sys") {
            // 1. PE 헤더에서 SizeOfImage 값 읽기 시도
            SIZE_T peSize = GetModuleSizeFromPEHeader(path);
            if (peSize > 0) {
                module.size = peSize;
            } else {
                // PE 헤더 읽기 실패 시 파일 크기 사용
                module.size = GetFileSizeFromPath(path);
            }
        } else {
            // 비 Win32 실행 파일은 파일 크기 사용
            module.size = GetFileSizeFromPath(path);
        }
        
        modules.push_back(module);
    }
    
    return modules;
}

int main() {
    // 프로세스 이름 입력 받기
    wchar_t processName[MAX_PATH];
    printf("프로세스 이름을 입력하세요 (예: notepad.exe): ");
    wscanf_s(L"%ls", processName, (unsigned)_countof(processName));

    // 프로세스 ID 구하기
    DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) {
        printf("프로세스를 찾을 수 없습니다.\n");
        return 1;
    }

    // PROCESS_QUERY_LIMITED_INFORMATION 권한만 사용하여 프로세스 핸들 획득
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("프로세스 핸들 획득 실패. 오류 코드: %d\n", GetLastError());
        return 1;
    }

    printf("프로세스 ID: %u\n\n", pid);
    printf("유저모드 메모리 영역 전체 스캔 중... 이 작업은 시간이 걸릴 수 있습니다.\n");
    
    // 프로세스에서 로드된 모듈 찾기
    std::vector<ModuleInfo> modules = ScanProcessModules(hProcess);

    printf("메모리 스캔 완료. %zu개의 모듈을 발견했습니다.\n", modules.size());

    if (modules.empty()) {
        printf("모듈을 찾을 수 없습니다.\n");
    } else {
        printf("\n총 %zu개의 모듈을 발견했습니다.\n\n", modules.size());

        // 모듈 정보 출력
        for (size_t i = 0; i < modules.size(); i++) {
            printf("모듈 #%zu\n", i + 1);
            printf("  모듈 이름: %s\n", modules[i].name.c_str());
            printf("  DLL 파일 경로: %s\n", modules[i].path.c_str());
            printf("  베이스주소: 0x%016llX\n", (unsigned long long)modules[i].baseAddress);
            printf("  모듈 크기: %zu 바이트 (%.2f MB)\n\n", 
                   modules[i].size, modules[i].size / (1024.0 * 1024.0));
        }

        // Lua 스크립트 파일 생성
        std::string luaFileName = "modules.lua";
        std::ofstream luaFile(luaFileName);
        
        if (luaFile.is_open()) {
            // Lua 스크립트 헤더 작성
            luaFile << "if symbols ~= nil then\n";
            luaFile << "\tsymbols.unregister();\n";
            luaFile << "end\n";
            luaFile << "symbols = createSymbolList();\n";
            luaFile << "symbols.register();\n\n";
            luaFile << "reinitializeSymbolhandler();\n\n";

            // 각 모듈에 대한 정보 추가
            for (const auto& module : modules) {
                luaFile << "symbols.addModule(\"" << module.name << "\", \"" << module.path 
                       << "\", 0x" << std::hex << module.baseAddress << std::dec 
                       << ", " << module.size << ");\n";
            }

            luaFile << "\nreinitializeSymbolhandler();\n";
            luaFile.close();
            
            printf("Lua 스크립트가 '%s' 파일로 저장되었습니다.\n", luaFileName.c_str());
        } else {
            printf("Lua 파일을 생성할 수 없습니다.\n");
        }
    }

    CloseHandle(hProcess);
    printf("프로그램을 종료하려면 아무 키나 누르세요...");
    getchar();
    getchar(); // 입력 버퍼에 남은 문자를 처리하기 위한 추가 호출
    return 0;
}
