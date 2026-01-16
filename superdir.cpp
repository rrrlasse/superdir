#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <winioctl.h>
#include <aclapi.h>
#include <fcntl.h>
#include <io.h>

#pragma comment(lib, "advapi32.lib")

using namespace std;

bool EnableBackupPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    bool success = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    return success;
}



unsigned long long physical(const std::wstring& wPath) {
    // 1. Open the file handle
    // Using 0 for access or FILE_READ_ATTRIBUTES is sufficient for querying ranges
    HANDLE hFile = CreateFileW(wPath.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        return 0;

    // 2. Define the query range (the whole file)
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return 0;
    }

    FILE_ALLOCATED_RANGE_BUFFER queryRange;
    queryRange.FileOffset.QuadPart = 0;
    queryRange.Length.QuadPart = fileSize.QuadPart;

    // 3. Query allocated ranges (Looping to handle fragmented files)
    std::vector<FILE_ALLOCATED_RANGE_BUFFER> results(1024);
    DWORD bytesReturned = 0;
    unsigned long long totalAllocated = 0;

    // We use a loop because extremely fragmented files may return ERROR_MORE_DATA
    while (true) {
        BOOL success = DeviceIoControl(hFile, FSCTL_QUERY_ALLOCATED_RANGES, &queryRange, sizeof(queryRange), results.data(), (DWORD)(results.size() * sizeof(FILE_ALLOCATED_RANGE_BUFFER)), &bytesReturned, NULL);

        DWORD lastError = GetLastError();
        if (!success && lastError != ERROR_MORE_DATA)
            break;

        int numRanges = bytesReturned / sizeof(FILE_ALLOCATED_RANGE_BUFFER);
        for (int i = 0; i < numRanges; ++i) {
            totalAllocated += results[i].Length.QuadPart;
        }

        if (success)
            break; // Finished all ranges

        // If ERROR_MORE_DATA, update offset to continue where we left off
        queryRange.FileOffset.QuadPart = results[numRanges - 1].FileOffset.QuadPart + results[numRanges - 1].Length.QuadPart;
        queryRange.Length.QuadPart = fileSize.QuadPart - queryRange.FileOffset.QuadPart;
    }

    CloseHandle(hFile);
    return totalAllocated;

}

bool isFullWidth(wchar_t c) {
    return (c >= 0x2e80 && c <= 0x9fff) || (c >= 0xac00 && c <= 0xd7a3) || (c >= 0xff00 && c <= 0xff60);
}

void PrintTruncatedAligned(const std::wstring& text, int maxWidth) {
    std::wstring result = L"";
    int currentWidth = 0;

    for (wchar_t c : text) {
        int charWidth = isFullWidth(c) ? 2 : 1;

        // Hvis tilføjelse af dette tegn overskrider maxWidth, stop her
        if (currentWidth + charWidth > maxWidth) {
            break;
        }

        result += c;
        currentWidth += charWidth;
    }

    // Print det trunkerede resultat
    wprintf(L"%ls", result.c_str());

    // Udfyld resten med mellemrum (Padding)
    for (int i = 0; i < (maxWidth - currentWidth); ++i) {
        putwchar(L' ');
    }
}


// Struktur til reparse point data (Symlinks/<JUNC>tions)
typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset; USHORT SubstituteNameLength;
            USHORT PrintNameOffset; USHORT PrintNameLength;
            ULONG  Flags; WCHAR PathBuffer;
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset; USHORT SubstituteNameLength;
            USHORT PrintNameOffset; USHORT PrintNameLength;
            WCHAR PathBuffer;
        } MountPointReparseBuffer;
    };
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

// 1. Formaterer fil-attributter til RHSA streng

std::wstring GetAttrStr(DWORD dw) {
    // Windows 'attrib' bruger 12 faste pladser før filstien.
    // Rækkefølgen følger bit-maskens typiske visning i CMD.
    std::string attr;

    if (dw & FILE_ATTRIBUTE_ARCHIVE)             attr += 'A';
    if (dw & FILE_ATTRIBUTE_SYSTEM)              attr += 'S';
    if (dw & FILE_ATTRIBUTE_HIDDEN)              attr += 'H';
    if (dw & FILE_ATTRIBUTE_READONLY)            attr += 'R';
    if (dw & FILE_ATTRIBUTE_OFFLINE)             attr += 'O';
    if (dw & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) attr += 'I';

    // Extended flag (Windows 8/10/11)
    if (dw & FILE_ATTRIBUTE_COMPRESSED)    attr += 'C';
    if (dw & FILE_ATTRIBUTE_INTEGRITY_STREAM)    attr += 'V';
    if (dw & FILE_ATTRIBUTE_NO_SCRUB_DATA)       attr += 'X';
    if (dw & FILE_ATTRIBUTE_PINNED)              attr += 'P';
    if (dw & FILE_ATTRIBUTE_UNPINNED)            attr += 'U';

    // Dine special-valg og Reparse points
    if (dw & FILE_ATTRIBUTE_SPARSE_FILE)         attr += 'Q';
    if (dw & FILE_ATTRIBUTE_REPARSE_POINT)       attr += 'L';
    if (dw & FILE_ATTRIBUTE_ENCRYPTED)           attr += 'E';
    if (dw & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) attr += 'M';

    
    return wstring(attr.begin(), attr.end());
}


#include <windows.h>
#include <iostream>
#include <string>

#include <windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>

std::wstring GetTimeAgo(LARGE_INTEGER inputTime, LARGE_INTEGER now) {
    // Beregn differens i sekunder (100ns enheder -> sekunder)
    long long diffSeconds = (now.QuadPart - inputTime.QuadPart) / 10000000LL;

    // Sikrer at vi aldrig returnerer 0 ved at tvinge minimum 1 sekund
    if (diffSeconds < 1) diffSeconds = 1;

    std::wstring val;
    wchar_t unit;

    // Tærskelværdier i sekunder
    const long long SEC_PER_YEAR = 31536000;
    const long long SEC_PER_DAY = 86400;
    const long long SEC_PER_HOUR = 3600;
    const long long SEC_PER_MIN = 60;

    if (diffSeconds >= SEC_PER_YEAR) {
        val = std::to_wstring(diffSeconds / SEC_PER_YEAR);
        unit = L'y';
    }
    else if (diffSeconds >= SEC_PER_DAY) {
        val = std::to_wstring(diffSeconds / SEC_PER_DAY);
        unit = L'd';
    }
    else if (diffSeconds >= SEC_PER_HOUR) {
        val = std::to_wstring(diffSeconds / SEC_PER_HOUR);
        unit = L'h';
    }
    else if (diffSeconds >= SEC_PER_MIN) {
        val = std::to_wstring(diffSeconds / SEC_PER_MIN);
        unit = L'm';
    }
    else {
        val = std::to_wstring(diffSeconds);
        unit = L's';
    }

    std::wstringstream wss;
    wss << std::setw(3) << std::right << val << unit;
    return wss.str();
}


#include <chrono>
#include <format>

std::wstring GetFormattedTime(const LARGE_INTEGER& li, int precision) {
    if (li.QuadPart <= 0 && precision == 2) {
        return L"0000-00-00 00:00:00";
    }

    // Windows FILETIME starter 1. jan 1601. 
    // Vi bruger offset 11644473600 sekunder for at ramme Unix Epoch (1970)
    using file_duration = std::chrono::duration<long long, std::ratio<1, 10000000>>;
    std::chrono::sys_time<file_duration> tp{ file_duration{li.QuadPart - 116444736000000000LL} };

    auto local_tp = std::chrono::current_zone()->to_local(tp);

    switch (precision) {
    case 0:  return std::format(L"{:%Y-%m-%d}", local_tp);
    case 1:  return std::format(L"{:%Y-%m-%d %H:%M}", local_tp);
    case 2:  return std::format(L"{:%Y-%m-%d %H:%M:%S}", std::chrono::floor<std::chrono::seconds>(local_tp));
    default: {
        // Vi tager de første 3 cifre af sub-sekunderne (millisekunder)
        auto ms = std::chrono::floor<std::chrono::milliseconds>(local_tp);
        return std::format(L"{:%Y-%m-%d %H:%M:%S}", ms);
    }
    }
}

#include <map>
#include <sddl.h>


std::wstring GetShortSidName(PSID pSid) {
    if (!pSid || !IsValidSid(pSid)) return L"UNKNOWN";

    static const std::map<std::wstring, std::wstring> sddlShortNames = {
        // --- Indbyggede Sikkerhedsprinciper (Sprog-uafhængige) ---
        { L"S-1-1-0",       L"WD" }, // Everyone
        { L"S-1-3-0",       L"CO" }, // Creator Owner
        { L"S-1-3-1",       L"CG" }, // Creator Group
        { L"S-1-5-1",       L"DI" }, // Dialup
        { L"S-1-5-2",       L"NU" }, // Network
        { L"S-1-5-3",       L"BA" }, // Batch
        { L"S-1-5-4",       L"IU" }, // Interactive
        { L"S-1-5-6",       L"SU" }, // Service
        { L"S-1-5-7",       L"AN" }, // Anonymous
        { L"S-1-5-11",      L"AU" }, // Authenticated Users
        { L"S-1-5-12",      L"RC" }, // Restricted Code
        { L"S-1-5-13",      L"WR" }, // Write Restricted
        { L"S-1-5-18",      L"SY" }, // Local System
        { L"S-1-5-19",      L"LS" }, // Local Service
        { L"S-1-5-20",      L"NS" }, // Network Service

        // --- Indbyggede Grupper (Built-in Aliases) ---
        { L"S-1-5-32-544", L"BA" }, // Administrators
        { L"S-1-5-32-545", L"BU" }, // Users
        { L"S-1-5-32-546", L"BG" }, // Guests
        { L"S-1-5-32-547", L"PU" }, // Power Users
        { L"S-1-5-32-548", L"BO" }, // Account Operators
        { L"S-1-5-32-549", L"SO" }, // Server Operators
        { L"S-1-5-32-550", L"PO" }, // Print Operators
        { L"S-1-5-32-551", L"BR" }, // Backup Operators
        { L"S-1-5-32-552", L"RE" }, // Replicators
        { L"S-1-5-32-554", L"BU" }, // Pre-Windows 2000 Compatible Access
        { L"S-1-5-32-555", L"RD" }, // Remote Desktop Users
        { L"S-1-5-32-558", L"NE" }, // Network Configuration Operators
        { L"S-1-5-32-559", L"IU" }, // Incoming Forest Trust Builders

        // --- App Containere (UWP / AppX) ---
        { L"S-1-15-2-1",    L"AC" }, // All Application Packages
        { L"S-1-15-2-2",    L"RC" }, // All Restricted Application Packages

        // --- Specielle Service Konti (Som ofte ses i System-filer) ---
        { L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", L"TI" }, // TrustedInstaller
        { L"S-1-5-80-0",    L"WA" }, // All Services

        // User Mode Driver Framework (UMDF)
        { L"S-1-5-80-3635958273-333157270-2051610403-1070562692-2350811566", L"UD" }

    };


    // 2. Konverter binær SID til streng-format (f.eks. S-1-5-32-544)
    LPWSTR stringSid = nullptr;
    if (ConvertSidToStringSidW(pSid, &stringSid)) {
        std::wstring sidStr(stringSid);
        LocalFree(stringSid); // Vigtigt: frigør hukommelse fra API'et

        // 3. Tjek om vi har en kort kode
        auto it = sddlShortNames.find(sidStr);
        if (it != sddlShortNames.end()) {
            return it->second;
        }

        // Hvis ingen kort kode findes, returner den fulde SID streng
        return L"";
    }

    return L"";
}

#include <tuple>

wstring PrintHumanACL(const std::wstring& filePath, bool all) {
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDacl = NULL;

    // 1. Hent DACL fra filstien
    DWORD result = GetNamedSecurityInfoW(
        filePath.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, &pDacl, NULL, &pSD
    );

    if (result != ERROR_SUCCESS) {
        return L"???";
    }

    wstring AU = L"-";
    wstring BU = L"-";

    std::map<std::wstring, DWORD> consolidated;

    for (WORD i = 0; i < pDacl->AceCount; i++) {
        LPVOID pAce;
        if (GetAce(pDacl, i, &pAce)) {
            PACE_HEADER pHeader = (PACE_HEADER)pAce;

            if (pHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE* pAllowed = (ACCESS_ALLOWED_ACE*)pAce;

                wchar_t name[256], domain[256];
                DWORD nLen = 256, dLen = 256;
                SID_NAME_USE use;

                // builtin = true;

                if (LookupAccountSidW(NULL, &pAllowed->SidStart, name, &nLen, domain, &dLen, &use)) {
                    std::wstring fullName = GetShortSidName(&pAllowed->SidStart);
                    if (!all) {
                        if (fullName.empty() || fullName == L"BU" || fullName == L"AU") {
                            if (fullName != L"BU" && fullName != L"AU") {
                                fullName = name;
                            }
                            consolidated[fullName] |= pAllowed->Mask;
                        }
                    }
                    else {
                        if (fullName.empty()) {
                            fullName = name;
                        }
                        consolidated[fullName] |= pAllowed->Mask;
                    }
                }
            }
        }
    }

    std::map<wstring, wstring> m;

    for (auto const& [user, mask] : consolidated) {
        std::wstring access = L"?";

        // Standard Windows masker (inkl. 0x100000 Synchronize)
        if ((mask & 0x1f01ff) == 0x1f01ff)      access = L"F";
        else if ((mask & 0x1301bf) == 0x1301bf) access = L"M";
        else if ((mask & 0x1200a9) == 0x1200a9) access = L"RX";
        else if ((mask & 0x1201bf) == 0x1201bf) access = L"RW";
        else if ((mask & 0x120089) == 0x120089) access = L"R";
        else {
            if (mask & 0x10000000) access = L"F*"; // GENERIC_ALL (Fuld adgang, ofte set i ACLs)
            if (mask & 0x20000000) access = L"X*"; // GENERIC_EXECUTE
            if (mask & 0x40000000) access = L"W*"; // GENERIC_WRITE
            if (mask & 0x80000000) access = L"R*"; // GENERIC_READ
        }

        if (all) {
            m[access] += (m[access] != L"" ? L"/" : L"") + user;
        }
        else {
			if (user == L"AU") {
                AU = access;
            }
            else if(user == L"BU") {
                BU = access;
            }
            else {
                m[access] += (m[access] != L"" ? L"/" : L"") + user;
            }
        }
    }

    wstring res;

    if (all) {
        for (auto& a : m) {
            res += a.second + L":" + a.first + L" ";
        }
    }
    else {
        // res += consolidated[L"BA"] + L" " + consolidated[L"AU"]; // haha
		res += BU + L" " + AU + L" ";
        for (auto& a : m) {
            res += a.second + L":" + a.first + L" ";
        }
    }

    if (pSD) LocalFree(pSD);

    if (!res.empty()) {
        res.pop_back();
    }
    return res;
}


std::vector<std::pair<wstring, uint64_t>> get_ads(const std::wstring& path) {
    std::vector<std::pair<wstring, uint64_t>> res;
    WIN32_FIND_STREAM_DATA sd;
    HANDLE hStream = FindFirstStreamW(path.c_str(), FindStreamInfoStandard, &sd, 0);
    bool found = false;
    wstring all;

    if (hStream != INVALID_HANDLE_VALUE) {
        while (FindNextStreamW(hStream, &sd)) {
            std::wstring suffix = L":$DATA";
            std::wstring sn = sd.cStreamName;
            if (sn.ends_with(suffix)) {
                sn.erase(sn.length() - suffix.length());
            }
            res.push_back({sn,  sd.StreamSize.QuadPart  });
            found = true;
        }
        FindClose(hStream);
    }
    return res;
}


#include <filesystem>


std::wstring GetLinkTarget2(const std::wstring& path) {
    return std::filesystem::read_symlink(path);


    HANDLE hFile = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

    if (hFile == INVALID_HANDLE_VALUE) return {};

    std::vector<BYTE> buffer(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    DWORD bytesReturned;
    if (!DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0, buffer.data(), (DWORD)buffer.size(), &bytesReturned, NULL)) {
        CloseHandle(hFile);
        return {};
    }
    CloseHandle(hFile);

    REPARSE_DATA_BUFFER* data = reinterpret_cast<REPARSE_DATA_BUFFER*>(buffer.data());
    std::wstring target = L"";
    BYTE* pathBufferStart = nullptr;
    USHORT offset = 0;
    USHORT lenBytes = 0;

    if (data->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
        pathBufferStart = (BYTE*)&data->MountPointReparseBuffer.PathBuffer;
        // Til <JUNC>tions er SubstituteName ofte mere pålidelig end PrintName
        offset = data->MountPointReparseBuffer.SubstituteNameOffset;
        lenBytes = data->MountPointReparseBuffer.SubstituteNameLength;
    }
    else if (data->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
        pathBufferStart = (BYTE*)&data->SymbolicLinkReparseBuffer.PathBuffer;
        offset = data->SymbolicLinkReparseBuffer.SubstituteNameOffset;
        lenBytes = data->SymbolicLinkReparseBuffer.SubstituteNameLength;
    }

    if (pathBufferStart && lenBytes > 0) {
        target = std::wstring((wchar_t*)(pathBufferStart + offset), lenBytes / sizeof(WCHAR));

        if (target.size() >= 4 && target.substr(0, 4) == L"\\??\\") {
            target = target.substr(4);
        }
    }

    return target;
}


std::vector<std::wstring> GetAllHardLinks(const std::wstring& inputPath) {
    std::vector<std::wstring> otherLinks;
    WCHAR lName[MAX_PATH];
    DWORD sz = MAX_PATH;

    std::wstring searchName = inputPath;
    size_t colonPos = searchName.find(L':');
    if (colonPos != std::wstring::npos) {
        searchName = searchName.substr(colonPos + 1);
    }

    wchar_t volumeRoot[MAX_PATH];
    if (!GetVolumePathNameW(inputPath.c_str(), volumeRoot, MAX_PATH)) {

    }

    std::wstring drive(volumeRoot);
    if (drive.back() == L'\\') drive.pop_back();
    HANDLE h = FindFirstFileNameW(inputPath.c_str(), 0, &sz, lName);

    if (h != INVALID_HANDLE_VALUE) {
        do {
            std::wstring foundPath(lName);

            if (_wcsicmp(foundPath.c_str(), searchName.c_str()) != 0) {
                otherLinks.push_back(drive + foundPath);
            }

            sz = MAX_PATH; 
        } while (FindNextFileNameW(h, &sz, lName));

        FindClose(h);
    }

    return otherLinks;
}


bool Isjunction(const std::wstring& path) {

    DWORD attributes = GetFileAttributesW(path.c_str());

    if (attributes == INVALID_FILE_ATTRIBUTES) return false;
    if (!(attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return false;

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(path.c_str(), &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
        return (findData.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT);
    }

    return false;
}

#include <locale>

std::wstring FormatFileSize(unsigned __int64 size) {
    std::wstringstream ss;
    ss.imbue(std::locale("US"));
    ss << std::fixed << size;
    std::wstring result = ss.str();
    return result;
}

unsigned long long filesize(const wstring& file, bool followlinks = false) {

    try {
        if (std::filesystem::is_symlink(file)) {
            if (followlinks) {
                return std::filesystem::file_size(std::filesystem::read_symlink(file));
            }
            else {
                return 0;
            }
        }
        return std::filesystem::file_size(file);
    }
    catch (std::exception&) {
        return 0;
    }
}

unsigned __int64 GetSizeOnDisk(const std::wstring& path) {
    DWORD highPart = 0;
    DWORD lowPart = GetCompressedFileSizeW(path.c_str(), &highPart);

    if (lowPart == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) {
        return 0;
    }

    unsigned __int64 sizeOnDisk = (static_cast<unsigned __int64>(highPart) << 32) | lowPart;

    return sizeOnDisk;
}

std::wstring GetDiskPercentageString(uint64_t logicalSize, uint64_t sizeOnDisk) {
    int percentage = 100;
    if (logicalSize > 0) {
        percentage = static_cast<int>((static_cast<double>(sizeOnDisk) / logicalSize) * 100.0);
    }
    std::wstringstream ss;
    ss << std::setw(3) << percentage << L"%";
    return ss.str();
}

WIN32_FIND_DATAW fd;


template <typename T>
T maximum(T a, T b) {
    return (a > b) ? a : b;
}

void print(const std::vector<std::vector<std::wstring>>& rows) {
    if (rows.empty()) return;

    size_t numCols = 0;
    for (const auto& row : rows) {
        numCols = maximum(numCols, row.size());
    }

    std::vector<int> colWidths(numCols, 0);
    for (const auto& row : rows) {
        for (size_t i = 0; i < row.size(); ++i) {
            colWidths[i] = maximum(colWidths[i], (int)row[i].length());
        }
    }

    for (const auto& row : rows) {
        std::wstring line;
        for (size_t i = 0; i < numCols; ++i) {
            std::wstring cell = (i < row.size()) ? row[i] : L"";
            if (i == 6) {
                line += std::format(L"{:>{}}  ", cell, colWidths[i]);
            }
            else {
                line += std::format(L"{:<{}}  ", cell, colWidths[i]);
            }
        }
        std::wcout << line << L"\n";
    }
}

#include <regex>

namespace fs = std::filesystem;
LARGE_INTEGER now;






std::vector<std::vector<std::wstring>> rows;

bool recursive = false;
bool permissions = false;




#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <regex>
#include <format>

namespace fs = std::filesystem;

// Hjælper til wildcard matching
std::wregex WildcardToRegex(const std::wstring& wildcard) {
    std::wstring pattern = wildcard;
    pattern = std::regex_replace(pattern, std::wregex(L"\\."), L"\\.");
    pattern = std::regex_replace(pattern, std::wregex(L"\\*"), L".*");
    pattern = std::regex_replace(pattern, std::wregex(L"\\?"), L".");
    return std::wregex(L"^" + pattern + L"$", std::regex_constants::icase);
}

void SearchRecursive(const fs::path& current_path, const std::wregex& pattern) {


    try {
        bool directory_announced = false;
        std::vector<fs::path> subheaders;

        // 1. Gennemgang af den aktuelle mappe
        for (const auto& entry : fs::directory_iterator(current_path, fs::directory_options::skip_permission_denied)) {
            const auto& path = entry.path();
            std::wstring filename = path.filename().wstring();


            // Hvis det matcher mønsteret, print det
            if (std::regex_match(filename, pattern)) {
                if (!directory_announced) {
                    std::wcout << std::format(L"\n Directory of {}\n\n", current_path.wstring());
                    directory_announced = true;
                }

                {
                    LARGE_INTEGER t1, t2, t3, t4;
                    BY_HANDLE_FILE_INFORMATION hi; FILE_BASIC_INFO bi;
                    WIN32_FIND_DATAW fd;

                    wstring written_;
                    wstring type_;
                    wstring size_;
                    wstring percent_;
                    wstring attributes_;
                    wstring dates_;
                    wstring permissions_;
                    wstring name_;
                    vector<pair<wstring, uint64_t>> ads_;
                    vector<wstring> links_;

                    wstring fullPath = std::filesystem::absolute(entry);
                    HANDLE hFind = FindFirstFileW(fullPath.c_str(), &fd);

                    if (hFind == INVALID_HANDLE_VALUE) {
                        //return 1;
                    }


                    name_ = fd.cFileName;

                    HANDLE hFile = CreateFileW(fullPath.c_str(), NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

                    if (hFile != INVALID_HANDLE_VALUE) {
                        GetFileInformationByHandle(hFile, &hi);
                        type_ = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                            ? (fd.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT ? L"<JUNC>" :
                                (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? L"<SYMD>" : L"<SYM>"))
                            : (hi.nNumberOfLinks > 1 ? L"<HARD>" :
                                (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? L"<DIR>" : L""));

                        if (type_ == L"<SYM>" || type_ == L"<SYMD>" || type_ == L"<JUNC>") {
                            links_.push_back(GetLinkTarget2(fullPath));
                        }
                        else {
                            links_ = GetAllHardLinks(fullPath);
                        }
                        GetFileInformationByHandleEx(hFile, FileBasicInfo, &bi, sizeof(bi));
                        t1 = bi.LastWriteTime;
                        t2 = bi.CreationTime;
                        t3 = bi.ChangeTime;
                        t4 = bi.LastAccessTime;
                        CloseHandle(hFile);
                    }
                    else {
                        // pagefile, hiberfil, etc can't be opened with CreateFileW
                        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                            type_ = L"<DIR>";
                        }
                        else {
                            type_ = L"";
                        }
                        t1.LowPart = fd.ftLastWriteTime.dwLowDateTime;
                        t1.HighPart = fd.ftLastWriteTime.dwHighDateTime;
                        t2.LowPart = fd.ftCreationTime.dwLowDateTime;
                        t2.HighPart = fd.ftCreationTime.dwHighDateTime;
                        t3.QuadPart = 0;
                        t4.LowPart = fd.ftLastAccessTime.dwLowDateTime;
                        t4.HighPart = fd.ftLastAccessTime.dwHighDateTime;
                    }

                    FindClose(hFind);

                    if (type_ == L"<SYM>" || type_ == L"<HARD>" || type_ == L"") {
                        auto size = filesize(fullPath, true);
                        size_ = FormatFileSize(size);
                        if (type_ != L"<SYM>") {
                            percent_ = GetDiskPercentageString(size, GetSizeOnDisk(fullPath));
                        }
                    }

                    written_ = GetTimeAgo(t1, now) + L" " + GetFormattedTime(t1, 2);

                    if (type_ == L"<SYM>" || type_ == L"<SYMD>" || type_ == L"<JUNC>") {
                        name_ += L" -> " + links_[0];
                    }

                    attributes_ = GetAttrStr(fd.dwFileAttributes);
                    dates_ = GetTimeAgo(t2, now) + L" " + GetTimeAgo(t3, now) + L" " + GetTimeAgo(t4, now);
                    permissions_ = PrintHumanACL(fullPath, permissions);
                    ads_ = get_ads(fullPath);

                    rows.push_back({ permissions_, dates_, percent_, attributes_, written_, type_, size_, name_ });

                    // Alternate Data Streams (hver sin linje)
                    for (const auto& [stream_name, stream_size] : ads_) {
                        rows.push_back({ L"", L"", L"", L"", L"",L"", std::to_wstring(stream_size), L"    " + stream_name });
                    }

                    if (type_ == L"<HARD>") {
                        for (const auto& link : links_) {
                            rows.push_back({ L"", L"", L"" ,L"", L"", L"", L"", L"    " + link });
                        }
                    }

                }

            }

            // Gem mapper til senere rekursion hvis -r er aktiv
            if (recursive && entry.is_directory()) {
                subheaders.push_back(path);
            }
        }

        print(rows);
        rows.clear();

        // 2. Manuel rekursion ind i undermapper
        for (const auto& sub_path : subheaders) {
            SearchRecursive(sub_path, pattern);
        }

    }
    catch (const fs::filesystem_error&) {
        // Ignorer adgang nægtet osv.
    }
}

void ProcessArgument(const std::wstring& input_arg) {
    fs::path p(input_arg);
    fs::path root;
    std::wstring pattern_str;

    if (fs::is_directory(p)) {
        root = p;
        pattern_str = L"*";
    }
    else {
        root = p.has_parent_path() ? p.parent_path() : fs::current_path();
        pattern_str = p.has_filename() ? p.filename().wstring() : L"*";
    }

    if (fs::exists(root)) {
        SearchRecursive(root, WildcardToRegex(pattern_str));
    }
}

int wmain3(int argc, wchar_t* argv[]) {
    std::vector<std::wstring> patterns;



    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];

        // Tjek om argumentet starter med - eller / og behandl det som flag
        if (arg.size() >= 2 && (arg[0] == L'-' || arg[0] == L'/')) {
            for (size_t j = 1; j < arg.size(); ++j) {
                if (arg[j] == L'r') recursive = true;
                else if (arg[j] == L'p') permissions = true;
            }
        }
        else {
            std::replace(arg.begin(), arg.end(), L'/', L'\\');
            patterns.push_back(arg);
        }
    }


    if (patterns.empty()) patterns.push_back(L".");

    for (const auto& p : patterns) {
        ProcessArgument(p);
    }

    return 0;
}








int wmain(int argc, wchar_t* argv[]) {
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    now.LowPart = ftNow.dwLowDateTime;
    now.HighPart = ftNow.dwHighDateTime;


    _setmode(_fileno(stdout), _O_U8TEXT);

    wmain3(argc, argv);
}
