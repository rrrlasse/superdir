#include <locale>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <winioctl.h>
#include <aclapi.h>
#include <fcntl.h>
#include <io.h>
#include <regex>
#include <filesystem>
#include <sddl.h>
#include <map>

std::wstring legend = LR"(Superdir version 0.0001 prototype. MIT license.

Flags:
    -r: Recurse into sub directories
    -p: Show all permisssions
    -d: Show millisecond dates (will hide a few other columns)

    They can be combined like -rd or -rdp. You can also use slash (/) instead of dash (-)

Columns:
    Permissions
    -----------
    Without -p flag:
    Shows permissions for "Authenticated Users" and "Users" followed by any non-built-in users
    and groups
  
    With -p flag:
    Shows all permissions for all users and groups. Following are translated to short form:
  
    WD: Everyone      CO: Creator Owner  CG: Creator Group  DI: Dialup         NU: Network       
    BT: Batch         IU: Interactive    SU: Service        AN: Anonymous      AU: Auth. Users   
    RC: Restricted    WR: Write Restr.   SY: Local System   LS: Local Service  NS: Netw. Service 
    BA: Admin         BU: Users          BG: Guests         PU: Power Users    BO: Account Ops   
    SO: Server Ops    PO: Print Ops      BR: Backup Ops     RE: Replicators    RD: Remote Desktop
    NE: Netw. Config  AC: App Packages   TI: TrustInst.     WA: All Services   UD: UMDF Drivers  

    File dates printed as relative time
    -----------------------------------
    Created
    Changed
    Accessed
  
    Size on disk
    ------------
    Can be less than 100% for sparse, compressed and offline files

    Attributes
    ----------
    A: ARCHIVE        S: SYSTEM               H: HIDDEN                 R: READONLY                   
    O: OFFLINE        I: NOT_CONTENT_INDEXED  C: COMPRESSED             V: INTEGRITY_STREAM           
    X: NO_SCRUB_DATA  P: PINNED               U: UNPINNED               Q: SPARSE_FILE                
    L: REPARSE_POINT  E: ENCRYPTED            M: RECALL_ON_DATA_ACCESS      

    Last Write date
    ---------------

    Type
    ----
    <DIR> <SYM> <SYMD> <HARD> <JUNC>
  
    File size
    ---------
  
    Name
    ----
    This may be followed by a list of:
    Hardlink targets
    Alternate Data Streams
	)";

namespace fs = std::filesystem;
LARGE_INTEGER now;

std::vector<std::vector<std::wstring>> rows;
std::vector<fs::path> allsubs;

bool recursive = false;
bool permissions = false;
bool millidate = false;

using namespace std;

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


std::wstring GetAttrStr(DWORD dw) {
    std::string attr;

    if (dw & FILE_ATTRIBUTE_ARCHIVE)             attr += 'A';
    if (dw & FILE_ATTRIBUTE_SYSTEM)              attr += 'S';
    if (dw & FILE_ATTRIBUTE_HIDDEN)              attr += 'H';
    if (dw & FILE_ATTRIBUTE_READONLY)            attr += 'R';
    if (dw & FILE_ATTRIBUTE_OFFLINE)             attr += 'O';
    if (dw & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) attr += 'I';

    if (dw & FILE_ATTRIBUTE_COMPRESSED)    attr += 'C';
    if (dw & FILE_ATTRIBUTE_INTEGRITY_STREAM)    attr += 'V';
    if (dw & FILE_ATTRIBUTE_NO_SCRUB_DATA)       attr += 'X';
    if (dw & FILE_ATTRIBUTE_PINNED)              attr += 'P';
    if (dw & FILE_ATTRIBUTE_UNPINNED)            attr += 'U';

    if (dw & FILE_ATTRIBUTE_SPARSE_FILE)         attr += 'Q';
    if (dw & FILE_ATTRIBUTE_REPARSE_POINT)       attr += 'L';
    if (dw & FILE_ATTRIBUTE_ENCRYPTED)           attr += 'E';
    if (dw & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) attr += 'M';

    return wstring(attr.begin(), attr.end());
}


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

    return std::format(L"{:>3}{}", val, unit);
}

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

std::wstring GetShortSidName(PSID pSid) {
    if (!pSid || !IsValidSid(pSid)) return L"UNKNOWN";

    static const std::map<std::wstring, std::wstring> sddlShortNames = {
        // --- Indbyggede Sikkerhedsprinciper (Sprog-uafhængige) ---
        { L"S-1-1-0",       L"WD" }, // Everyone
        { L"S-1-3-0",       L"CO" }, // Creator Owner
        { L"S-1-3-1",       L"CG" }, // Creator Group
        { L"S-1-5-1",       L"DI" }, // Dialup
        { L"S-1-5-2",       L"NU" }, // Network
        { L"S-1-5-3",       L"BT" }, // Batch
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

    for (WORD i = 0; pDacl && i < pDacl->AceCount; i++) {
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

        // De prædefinerede grupper (højniveau)
        if ((mask & 0x1f01ff) == 0x1f01ff)      access = L"F";
        else if ((mask & 0x1301bf) == 0x1301bf) access = L"M";
        else if ((mask & 0x1201bf) == 0x1201bf) access = L"RW";
        else if ((mask & 0x1200a9) == 0x1200a9) access = L"RX";
        else if ((mask & 0x120089) == 0x120089) access = L"R";
        else {
            // Individuelle/Specifikke rettigheder
            std::wstring bits;
            if (mask & 0x10000)    bits += L"DE"; // DELETE
            if (mask & 0x20000)    bits += L"RC"; // READ_CONTROL
            if (mask & 0x40000)    bits += L"WD"; // WRITE_DAC (Change permissions)
            if (mask & 0x80000)    bits += L"WO"; // WRITE_OWNER
            if (mask & 0x100000)   bits += L"SY"; // SYNCHRONIZE

            // Generiske rettigheder (ofte set på mapper/objekter)
            if (mask & 0x10000000) bits += L"F*"; // GENERIC_ALL
            if (mask & 0x20000000) bits += L"X*"; // GENERIC_EXECUTE
            if (mask & 0x40000000) bits += L"W*"; // GENERIC_WRITE
            if (mask & 0x80000000) bits += L"R*"; // GENERIC_READ

            access = bits.empty() ? L"?" : bits;
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
		res += AU + L" " + BU + L" ";
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
    return std::format(L"{:>3}%", percentage);
}

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
            if (colWidths[i] == 0) {
                continue;
            }
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

std::wregex WildcardToRegex(const std::wstring& wildcard) {
    std::wstring pattern = wildcard;
    pattern = std::regex_replace(pattern, std::wregex(L"\\."), L"\\.");
    pattern = std::regex_replace(pattern, std::wregex(L"\\*"), L".*");
    pattern = std::regex_replace(pattern, std::wregex(L"\\?"), L".");
    return std::wregex(L"^" + pattern + L"$", std::regex_constants::icase);
}

fs::path GetAbsoluteSymlinkTarget(const fs::path& linkPath) {
    std::error_code ec;
    fs::path target = fs::read_symlink(linkPath, ec);
    if (ec) return {};

    if (target.is_relative()) {
        target = linkPath.parent_path() / target;
    }

    return fs::absolute(target, ec);
}

void SearchRecursive(const fs::path& current_path, const std::wregex& pattern) {
    for (auto& d : allsubs) {
        if (fs::equivalent(d, current_path)) {
            return;
        }
    }
    allsubs.push_back(current_path);

    std::wcout << std::format(L"\n Directory of {}\n\n", current_path.wstring());

    try {
        std::vector<fs::path> subheaders;

        for (const auto& entry : fs::directory_iterator(current_path, fs::directory_options::skip_permission_denied)) {
            const auto& path = entry.path();
            std::wstring filename = path.filename().wstring();

            wstring type_;
            wstring written_;
            wstring size_;
            wstring percent_;
            wstring attributes_;
            wstring dates_;
            wstring permissions_;
            wstring name_;
            vector<pair<wstring, uint64_t>> ads_;
            vector<wstring> hardlinks_;
            wstring softlink_;

            if (std::regex_match(filename, pattern)) {                
                LARGE_INTEGER t1, t2, t3, t4;
                BY_HANDLE_FILE_INFORMATION hi; FILE_BASIC_INFO bi;
                WIN32_FIND_DATAW fd;

                wstring fullPath = std::filesystem::absolute(entry);
                HANDLE hFind = FindFirstFileW(fullPath.c_str(), &fd);
                if (hFind == INVALID_HANDLE_VALUE) {
                    rows.push_back({ L"", L"", L"" ,L"", L"", L"???", L"", filename });
                    continue;
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
                        softlink_ = std::filesystem::read_symlink(path);
                    }
                    else {
                        hardlinks_ = GetAllHardLinks(fullPath);
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
                    size_ = std::format(std::locale("en_US.UTF-8"), L"{:L}", size);
                    if (type_ != L"<SYM>") {
                        percent_ = GetDiskPercentageString(size, GetSizeOnDisk(fullPath));
                    }
                }


                if (type_ == L"<SYM>" || type_ == L"<SYMD>" || type_ == L"<JUNC>") {
                    name_ += L" -> " + softlink_;
                }
                permissions_ = PrintHumanACL(fullPath, permissions);
                ads_ = get_ads(fullPath);

                attributes_ = GetAttrStr(fd.dwFileAttributes);

                if(millidate) {
                    dates_ = GetFormattedTime(t1, 3) + L"  " + GetFormattedTime(t2, 3) + L"  " + GetFormattedTime(t3, 3);
                    written_ = GetFormattedTime(t1, 3);
                }
                else {
                    dates_ = GetTimeAgo(t2, now) + L" " + GetTimeAgo(t3, now) + L" " + GetTimeAgo(t4, now);
                    written_ = GetTimeAgo(t1, now) + L" " + GetFormattedTime(t1, 2);
                }

                rows.push_back({ permissions_, dates_, percent_, attributes_, written_, type_, size_, name_ });

                // Alternate Data Streams
                for (const auto& [stream_name, stream_size] : ads_) {
                    rows.push_back({ L"", L"", L"", L"", L"",L"", std::to_wstring(stream_size), L"    " + stream_name });
                }

                if (type_ == L"<HARD>") {
                    for (const auto& link : hardlinks_) {
                        rows.push_back({ L"", L"", L"" ,L"", L"", L"", L"", L"    " + link });
                    }
                }
                
            }

            if (recursive) {
                if (type_ == L"<DIR>") {
                    subheaders.push_back(path);
                }
                else if (type_ == L"<JUNC>") {
                    subheaders.push_back(GetAbsoluteSymlinkTarget(path));
                }
                else if (type_ == L"<SYMD>") {
                    subheaders.push_back(GetAbsoluteSymlinkTarget(path));
                }
            }

        }

        print(rows);
        rows.clear();

        for (const auto& sub_path : subheaders) {
            SearchRecursive(sub_path, pattern);
        }

    }
    catch (const fs::filesystem_error&) {
        wcout << "???\n";
    }
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

int wmain(int argc, wchar_t* argv[]) {
    // Needed for some files in C:\ProgramData\Packages\ where you would otherwise get permission denied even as admin
    set_privilege({ SE_BACKUP_NAME, SE_RESTORE_NAME, SE_SECURITY_NAME }, true);

    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    now.LowPart = ftNow.dwLowDateTime;
    now.HighPart = ftNow.dwHighDateTime;

    _setmode(_fileno(stdout), _O_U8TEXT);

    std::vector<std::wstring> patterns;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];

        if (arg.size() == 2 && (arg == L"-?" || arg == L"/?")) {
            wcerr << legend;
            exit(1);
        }

        if (arg.size() >= 2 && (arg[0] == L'-' || arg[0] == L'/')) {
            for (size_t j = 1; j < arg.size(); ++j) {
                if (arg[j] == L'r') recursive = true;
                else if (arg[j] == L'p') permissions = true;
                else if (arg[j] == L'd') millidate = true;
            }
        }
        else {
            std::replace(arg.begin(), arg.end(), L'/', L'\\');
            patterns.push_back(arg);
        }
    }


    if (patterns.empty()) patterns.push_back(L".");

    for (const auto& pa : patterns) {
        fs::path p(pa);
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

    return 0;
}
