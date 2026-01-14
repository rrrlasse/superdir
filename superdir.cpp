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

    // Højrejustering til 4 tegn (3 cifre/mellemrum + 1 enhed)
    std::wstringstream wss;
    wss << std::setw(3) << std::right << val << unit;
    return wss.str();
}


// 2. Formaterer tidsstempler
void PrintTime(const LARGE_INTEGER& li, int precision) {
    FILETIME ft;
    ft.dwLowDateTime = li.LowPart;
    ft.dwHighDateTime = li.HighPart;

    FILETIME localFt;
    SYSTEMTIME st;

    // 1. Konverter UTC til lokal filtid
    FileTimeToLocalFileTime(&ft, &localFt);
    FileTimeToSystemTime(&localFt, &st);
    if (precision == 0) {
        wprintf(L"%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
    }
    else if (precision == 1) {
        wprintf(L"%04d-%02d-%02d %02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    }
    else if (precision == 2) {
        if (li.QuadPart > 0) {
            wprintf(L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        }
        else {
            wprintf(L"0000-00-00 00:00:00");
        }
    }
    else {
        wprintf(L"%04d-%02d-%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    }
}



#include <windows.h>
#include <aclapi.h>
#include <iostream>
#include <string>
#include <map>

#include <windows.h>
#include <sddl.h>
#include <string>
#include <map>

std::wstring GetShortSidName(PSID pSid) {
    if (!pSid || !IsValidSid(pSid)) return L"UNKNOWN";

    static const std::map<std::wstring, std::wstring> sddlShortNames = {
        // --- CORE GROUPS ---
        { L"S-1-5-18", L"SY" }, // Local System
        { L"S-1-1-0",  L"WD" }, // Everyone (World)
        { L"S-1-5-11", L"AU" }, // Authenticated Users
        { L"S-1-3-0",  L"CO" }, // Creator Owner
        { L"S-1-3-1",  L"PS" }, // Principal Self

        // --- BUILT-IN GROUPS (S-1-5-32-xxx) ---
        { L"S-1-5-32-544", L"BA" }, // Built-in Administrators
        { L"S-1-5-32-545", L"BU" }, // Built-in Users
        { L"S-1-5-32-546", L"BG" }, // Built-in Guests
        { L"S-1-5-32-547", L"PU" }, // Power Users
        { L"S-1-5-32-548", L"AO" }, // Account Operators
        { L"S-1-5-32-549", L"SO" }, // Server Operators
        { L"S-1-5-32-550", L"PO" }, // Printer Operators
        { L"S-1-5-32-551", L"BO" }, // Backup Operators
        { L"S-1-5-32-552", L"RE" }, // Replicator

        // --- SERVICE ACCOUNTS & LOGIN TYPES ---
        { L"S-1-5-19", L"LS" }, // Local Service
        { L"S-1-5-20", L"NS" }, // Network Service
        { L"S-1-5-6",  L"SU" }, // Service (Service Logon)
        { L"S-1-5-4",  L"IU" }, // Interactive (Logged on locally)
        { L"S-1-5-7",  L"AN" }, // Anonymous
        { L"S-1-5-3",  L"BL" }, // Batch (Batch Logon)

        // --- APP PACKAGES (Windows 8+) ---
        { L"S-1-15-2-1", L"AC" }, // All Application Packages
        { L"S-1-15-2-2", L"RC" }, // All Restricted Application Packages

        // --- SPECIAL SYSTEM SIDS ---
        // TrustedInstaller (har ingen 2-bogstavs kode i SDDL, så vi bruger 'TI')
        { L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", L"TI" }
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

wstring PrintHumanACL(const std::wstring& filePath, bool builtin) {
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

    // 2. Map til konsolidering: <Navn, AccessMask>
    std::map<std::wstring, DWORD> consolidated;

    for (WORD i = 0; i < pDacl->AceCount; i++) {
        LPVOID pAce;
        if (GetAce(pDacl, i, &pAce)) {
            PACE_HEADER pHeader = (PACE_HEADER)pAce;

            // Vi fokuserer på ALLOWED typer
            if (pHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE* pAllowed = (ACCESS_ALLOWED_ACE*)pAce;

                wchar_t name[256], domain[256];
                DWORD nLen = 256, dLen = 256;
                SID_NAME_USE use;

                // builtin = true;

                if (LookupAccountSidW(NULL, &pAllowed->SidStart, name, &nLen, domain, &dLen, &use)) {
                    std::wstring fullName = GetShortSidName(&pAllowed->SidStart);
                    if (!builtin) {
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

    // 3. Print resultaterne

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

        if (builtin) {
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

    if (builtin) {
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


    // Husk at frigøre hukommelse allokeret af GetNamedSecurityInfo
    if (pSD) LocalFree(pSD);

    if (!res.empty()) {
        res.pop_back();
    }
    return res;
}


// 4. Finder og lister ADS
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


#include <windows.h>
#include <winioctl.h>
#include <string>
#include <vector>


#include <windows.h>
#include <winioctl.h>
#include <string>
#include <vector>





std::wstring GetLinkTarget2(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

    if (hFile == INVALID_HANDLE_VALUE) return L"";

    std::vector<BYTE> buffer(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    DWORD bytesReturned;
    if (!DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0, buffer.data(), (DWORD)buffer.size(), &bytesReturned, NULL)) {
        CloseHandle(hFile);
        return L"";
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

        // RENSNING: Fjern NT-objekt præfiks "\??\" hvis det findes
        // Dette gør "\??\C:\Target" til "C:\Target"
        if (target.size() >= 4 && target.substr(0, 4) == L"\\??\\") {
            target = target.substr(4);
        }
    }

    return target;
}


#include <algorithm>

std::vector<std::wstring> GetAllHardLinks(const std::wstring& inputPath) {
    std::vector<std::wstring> otherLinks;
    WCHAR lName[MAX_PATH];
    DWORD sz = MAX_PATH;

    // 1. Find det volumen-relative navn for inputPath (fjerner f.ex. "C:")
    // Vi bruger dette til at sammenligne med resultaterne fra FindFirstFileNameW
    std::wstring searchName = inputPath;
    size_t colonPos = searchName.find(L':');
    if (colonPos != std::wstring::npos) {
        searchName = searchName.substr(colonPos + 1);
    }

    wchar_t volumeRoot[MAX_PATH];
    if (!GetVolumePathNameW(inputPath.c_str(), volumeRoot, MAX_PATH)) {
        // Fejlhåndtering
    }
    // Fjern den afsluttende backslash fra "C:\", så vi ikke får dobbelt slash
    std::wstring drive(volumeRoot);
    if (drive.back() == L'\\') drive.pop_back();

    // 2. Start søgning
    HANDLE h = FindFirstFileNameW(inputPath.c_str(), 0, &sz, lName);

    if (h != INVALID_HANDLE_VALUE) {
        do {
            std::wstring foundPath(lName);

            // 3. Ekskluder hvis det er den samme som vores input (uden drevbogstav)
            // Vi bruger case-insensitive sammenligning, da Windows er ligeglad med store/små bogstaver
            if (_wcsicmp(foundPath.c_str(), searchName.c_str()) != 0) {
                otherLinks.push_back(drive + foundPath);
            }

            sz = MAX_PATH; // Nulstil buffer-størrelse til næste kald
        } while (FindNextFileNameW(h, &sz, lName));

        FindClose(h);
    }

    return otherLinks;
}


bool Isjunction(const std::wstring& path) {
    // 1. Hent fil-attributter uden at åbne filen (hurtigt)
    DWORD attributes = GetFileAttributesW(path.c_str());

    if (attributes == INVALID_FILE_ATTRIBUTES) return false;

    // Tjek om det overhovedet er et reparse point (Symlink, <JUNC>tion, osv.)
    if (!(attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return false;

    // 2. Vi skal bruge ReparseTag for at vide om det er en <JUNC>tion
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(path.c_str(), &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
        // IO_REPARSE_TAG_MOUNT_POINT er det tekniske navn for en <JUNC>tion
        return (findData.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT);
    }

    return false;
}


// 5. Finder Target for Soft- og Hardlinks
std::wstring GetLinkTarget(const std::wstring& path, DWORD attr, DWORD numLinks) {

    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
        HANDLE hFile = CreateFileW(path.c_str(), 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BYTE buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
            DWORD bytes;
            if (DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0, buffer, sizeof(buffer), &bytes, NULL)) {
                auto rb = (PREPARSE_DATA_BUFFER)buffer;
                std::wstring t = std::wstring(rb->SymbolicLinkReparseBuffer.PathBuffer + rb->SymbolicLinkReparseBuffer.PrintNameOffset / 2, rb->SymbolicLinkReparseBuffer.PrintNameLength / 2)    ;
                CloseHandle(hFile);
                return t;
            }
            CloseHandle(hFile);
        }
    }
    else if (numLinks > 1) {
        wstring res;
        vector<wstring> v = GetAllHardLinks(path);
        for (auto &a : v) {
            res += L"                                                                                                            • " + a + L"\n";
        }
        if (!res.empty()) {
           // res.pop_back();
        }
		
        return res;
    }
    return L"";
}


void set_privilege(const std::vector<std::wstring>& priv, bool enable) {
    for (auto& p : priv) {
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            continue;
        if (!LookupPrivilegeValueW(NULL, p.c_str(), &luid))
            continue;

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        CloseHandle(hToken);
    }
}

#include <filesystem>

#include <iostream>
#include <string>
#include <iomanip>
#include <locale>
#include <sstream>

// Formaterer størrelsen med fast bredde og dansk tegnsæt (punktum/komma)
std::wstring FormatFileSize(unsigned __int64 size, int width) {
    // Vi bruger en dansk locale for at få de rigtige separatorer
    // Hvis "Danish" ikke er installeret, kan man lave en manuel erstatning
    std::wstringstream ss;
    ss.imbue(std::locale("US"));

    ss << std::fixed << size;
    std::wstring result = ss.str();

    // Hvis resultatet er kortere end width, tilføjer vi padding i starten (højrestillet)
    if (result.length() < (size_t)width) {
        result.insert(0, width - result.length(), L' ');
    }

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
    // GetCompressedFileSize returnerer den lave 32-bit del af størrelsen
    DWORD lowPart = GetCompressedFileSizeW(path.c_str(), &highPart);

    if (lowPart == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) {
        // Fejlhåndtering (f.eks. hvis filen ikke findes)
        return 0;
    }

    // Kombiner high og low til en samlet 64-bit integer
    unsigned __int64 sizeOnDisk = (static_cast<unsigned __int64>(highPart) << 32) | lowPart;

    return sizeOnDisk;
}

std::wstring GetDiskPercentageString(unsigned __int64 logicalSize, unsigned __int64 sizeOnDisk) {
    int percentage = 100;

    if (logicalSize > 0) {
        // Beregn procent (fysisk / logisk)
        // Vi bruger double for at sikre præcision før afrunding til int
        percentage = static_cast<int>((static_cast<double>(sizeOnDisk) / logicalSize) * 100.0);

        // Sikr at vi ikke runder over 100% (kan ske pga. cluster-afrunding på små filer)
    }

    std::wstringstream ss;
    // Højrejustering i et felt på 3 tegn (så " 5%" og "100%" flugter)
    ss << std::setw(3) << percentage << L"%";

    return ss.str();
}

WIN32_FIND_DATAW fd;


int wmain(int argc, wchar_t* argv[]) {
    std::wstring targets;
    std::wstring type;
    LARGE_INTEGER t1, t2, t3, t4;

    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);

    // Convert FILETIME to 64-bit integer
    LARGE_INTEGER now;
    now.LowPart = ftNow.dwLowDateTime;
    now.HighPart = ftNow.dwHighDateTime;

    BY_HANDLE_FILE_INFORMATION hi; FILE_BASIC_INFO bi;
    WIN32_FIND_DATAW fd;
    std::wstring inputPath = (argc > 1) ? argv[1] : L".";
    std::wstring searchPattern;

    // 1. Hent attributter for at se om det er en mappe (virker med ".." og ".")
    DWORD attrs = GetFileAttributesW(inputPath.c_str());

    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        // Det er en mappe - tilføj backslash hvis den mangler, og derefter *
        searchPattern = inputPath;
        if (searchPattern.back() != L'\\' && searchPattern.back() != L'/') {
            searchPattern += L"\\";
        }
        searchPattern += L"*";
    }
    else {
        // Det er enten en fil eller en søgestreng med wildcards (f.eks. *.txt)
        searchPattern = inputPath;
    }

    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &fd);

    if (hFind == INVALID_HANDLE_VALUE) {
        // Hvis vi stadig fejler, er stien nok ugyldig
        wprintf(L"Fejl: Kunne ikke tilgå '%ls' (ErrorCode: %lu)\n", inputPath.c_str(), GetLastError());
        return 1;
    }

    _setmode(_fileno(stdout), _O_U8TEXT);

    if (hFind == INVALID_HANDLE_VALUE) return 1;

    // Tabel Overskrift
//    wprintf(L"Name                                    Size  Atributes       Type      Link target                 Creation          Last write        Last change       Last access        DAC                    ACL\n");
//    wprintf(L"-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

    do {
        // Spring over "." og ".."
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        std::wstring name = fd.cFileName;

        // 1. Konstruer den relative sti (mappe + filnavn)
        // inputPath er den mappe, du modtog som parameter (f.eks. "..")
        std::wstring relativePath = inputPath;
        if (relativePath.back() != L'\\' && relativePath.back() != L'/') {
            relativePath += L"\\";
        }
        relativePath += fd.cFileName;

        // 2. Konverter til fuld absolut sti
        wchar_t fullPath[MAX_PATH];
        GetFullPathNameW(relativePath.c_str(), MAX_PATH, fullPath, NULL);

        //WIN32_FIND_DATAW fd;
        //HANDLE hFile = FindFirstFileW(fullPath, &fd);

        HANDLE hFile = CreateFileW(fullPath, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,  NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

        if (hFile != INVALID_HANDLE_VALUE) {

            GetFileInformationByHandle(hFile, &hi);

            // Type og Target


            type = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                ? (fd.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT ? L"<JUNC>" :
                    (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? L"<SYMD>" : L"<SYM>"))
                : (hi.nNumberOfLinks > 1 ? L"<HARD>" :
                    (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? L"<DIR>" : L""));

            if (type == L"<SYM>" || type == L"<SYMD>" || type == L"<JUNC>") {
                targets = GetLinkTarget2(fullPath);
            }
            else {
                targets = GetLinkTarget(fullPath, fd.dwFileAttributes, hi.nNumberOfLinks);
            }


            GetFileInformationByHandleEx(hFile, FileBasicInfo, &bi, sizeof(bi));
			t1 = bi.LastWriteTime;
			t2 = bi.CreationTime;
			t3 = bi.ChangeTime;
			t4 = bi.LastAccessTime;
        }
        else {
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                type = L"<DIR>";
            }
            else {
                type = L"";
            }
            t1.LowPart = fd.ftLastWriteTime.dwLowDateTime;
            t1.HighPart = fd.ftLastWriteTime.dwHighDateTime;
            t2.LowPart = fd.ftCreationTime.dwLowDateTime;
            t2.HighPart = fd.ftCreationTime.dwHighDateTime;
            t3.QuadPart = 0;
            t4.LowPart = fd.ftLastAccessTime.dwLowDateTime;
            t4.HighPart = fd.ftLastAccessTime.dwHighDateTime;
        }

               

        auto siz = filesize(fullPath, true);
        auto fs = FormatFileSize(siz, 17);
            

		auto percent = GetDiskPercentageString(siz, GetSizeOnDisk(fullPath));

        PrintTime(t1, 2);
        wprintf(L" ");
        wcout << GetTimeAgo(t1, now);
        wprintf(L" ");

        bool has_size = type == L"<SYM>" || type == L"<HARD>" || type == L"";

        wprintf(L" %-10ls ", type.c_str());
        wprintf(L"%-17ls ", has_size ? fs.c_str() : L"");



		if (type == L"<SYM>" || type == L"<SYMD>" || type == L"<JUNC>") {
            name += L" -> " + targets;
        }



        wprintf(L" %-4ls ", has_size ? percent.c_str() : L"");

        // Print Navn og Attributter
        wprintf(L" %-8ls", GetAttrStr(fd.dwFileAttributes).c_str());


        //wprintf(L"  %-20ls  ", lt.c_str());


        wcout << GetTimeAgo(t2, now);
//        PrintTime(t2, 1);
        wprintf(L" ");
        wcout << GetTimeAgo(t3, now);
        //        PrintTime(t3, 1);
        wprintf(L" ");
        wcout << GetTimeAgo(t4, now);

//        PrintTime(t4, 1);

            
            wprintf(L"  ");




            // ACL og ADS                      
           // fseek(stdout, -15, SEEK_CUR);
            auto acl = PrintHumanACL(fullPath, false);
			PrintTruncatedAligned(acl, 20);

            PrintTruncatedAligned(name, 100);

            auto a = get_ads(fullPath);
            if (!a.empty()) {
                for (auto& ad : a) {
                    auto s = FormatFileSize(ad.second, 18);
                    wprintf(L"\n                                    ");
                    wprintf(L"%-60ls           ", s.c_str());
                    wstring add = L" • " + ad.first;
                    PrintTruncatedAligned(add, 82);
                }
            }

            CloseHandle(hFile);
            wprintf(L"\n");

            if (type == L"<HARD>") {
                wcout << targets;
            }


      //  wprintf(L"\n");
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return 0;
}


