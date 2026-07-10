#include "dumper_internal.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace ipd {
namespace {

constexpr SIZE_T kMaxSectionSize = 100 * 1024 * 1024;

struct PatternByte {
    bool wildcard = false;
    BYTE value = 0;
};

struct KeyPattern {
    const char* signature = nullptr;
    std::array<SIZE_T, 8> dwordOffsets{};
};

struct AesKeyCandidate {
    std::string keyHex;
    const BYTE* address = nullptr;
    std::wstring sectionName;
    double entropy = 0.0;
};

struct TargetSection {
    std::wstring name;
    const BYTE* base = nullptr;
    DWORD size = 0;
};

constexpr KeyPattern kKeyPatterns[] = {
    {
        "C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ??",
        {3, 10, 17, 24, 35, 42, 49, 56},
    },
    {
        "C7 ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ??",
        {2, 9, 16, 23, 30, 37, 44, 51},
    },
    {
        "C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ??",
        {3, 10, 21, 28, 35, 42, 49, 56},
    },
    {
        "C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? C3",
        {51, 45, 38, 31, 24, 17, 10, 3},
    },
};

constexpr const char* kFalsePositives[] = {
    "FFD9FFD9FFD9FFD9FFD9FFD9FFD9FFD9FFD9FFD9FFD9FFD9FFD9FFD9FFD9FFD9",
    "67E6096A85AE67BB72F36E3C3AF54FA57F520E518C68059BABD9831F19CDE05B",
    "D89E05C107D57C3617DD703039590EF7310BC0FF11155868A78FF964A44FFABE",
    "9A99593F9A99593F0AD7633F52B8BE3FE17A543FCDCC4C3D4260E53BAE47A13F",
    "6F168073B9B21449D742241700068ADABC306FA9AA3831164DEE8DE34E0EFBB0",
    "0AD7633FCDCC4C3DCDCCCC3D52B8BE3F9A99593F9A99593FC9767E3FE17A543F",
    "168073C7B21449C7430C00064310BC304314AA3843184DEE431C4E0E83C4205B",
    "E6096AC7AE67BBC7430C3AF543107F5243148C684318ABD9431C19CD436C2000",
    "9E05C1C7D57C36C7430C39594310310B431411154318A78F431CA44F436C1C00",
    "9E05C1C7D57C36C7DD7030C7590EF7C70BC0FFC7155868C78FF964C7A44FFABE",
    "168073C7B21449C7422417C7068ADAC7306FA9C7383116C7EE8DE3C74E0EFBB0",
    "0AD7633FCDCC4C3D00C742143DC742183FC7421C3FC742203FC742247E3FC742",
    "0000803F0AD7A33E0AD7633F52B8BE3FE17A543FCDCC4C3D4260E53B54AE47A1",
    "0AD7A33E0AD7633F52B8BE3FE17A543FCDCC4C3D4260E53BAE47A13F58583934",
    "0AD7A33E0AD7633F52B8BE3FE17A543FCDCC4C3D4260E53BAE47A13F38583934",
    "0000803F0AD7A33E0AD7633F52B8BE3FE17A543FCDCC4C3D4260E53B34AE47A1",
    "0000803F0000803F0AD7A33E0AD7633F52B8BE3FE17A543FCDCC4C3D4260E5",
    "0AD7633F52B8BE3FE17A543FCDCC4C3D4260E53BAE47A13F5839343C4CC9767E",
    "0AD7633F52B8BE3FE17A543FCDCC4C3D4260E53BAE47A13F5839343C4CC9767E",
    "07D57C3617DD703039590EF7310BC0FF11155868A78FF964A44FFABE6C1C0000",
    "85AE67BB72F36E3C3AF54FA57F520E518C68059BABD9831F19CDE05B6C200000",
    "E6096AC7AE67BBC7F36E3CC7F54FA5C7520E51C768059BC7D9831FC719CDE05B",
    "0AD7A33E0AD7633F52B8BE3FE17A543FCDCC4C3D4260E53BAE47A13F3C583934",
    "E4D6E74FE4D667500044AC47926595380080DC43000A9B46000080BF000080BF",
    "D04C8F7D71ECC047D8A60970FBA31C9E9EC1250BBBF6459AC480947212E1DB8C",
};

int HexNibble(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + ch - 'A';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + ch - 'a';
    }
    return -1;
}

std::vector<PatternByte> ParsePattern(const char* signature) {
    std::vector<PatternByte> pattern;
    const char* cursor = signature;
    while (*cursor != '\0') {
        while (*cursor == ' ') {
            ++cursor;
        }
        if (*cursor == '\0') {
            break;
        }

        if (cursor[0] == '?' && cursor[1] == '?') {
            pattern.push_back({true, 0});
        } else {
            int high = HexNibble(cursor[0]);
            int low = HexNibble(cursor[1]);
            pattern.push_back({false, static_cast<BYTE>((high << 4) | low)});
        }

        while (*cursor != '\0' && *cursor != ' ') {
            ++cursor;
        }
    }

    return pattern;
}

std::wstring SectionName(const IMAGE_SECTION_HEADER& section) {
    char name[IMAGE_SIZEOF_SHORT_NAME + 1]{};
    std::memcpy(name, section.Name, IMAGE_SIZEOF_SHORT_NAME);

    int required = MultiByteToWideChar(CP_ACP, 0, name, -1, nullptr, 0);
    if (required <= 1) {
        return L"<noname>";
    }

    std::wstring wide(static_cast<size_t>(required - 1), L'\0');
    MultiByteToWideChar(CP_ACP, 0, name, -1, wide.data(), required);
    return wide;
}

std::string WideToUtf8Local(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }

    std::string utf8(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), utf8.data(), required, nullptr, nullptr);
    return utf8;
}

std::wstring Utf8ToWideLocal(const std::string& value) {
    if (value.empty()) {
        return {};
    }

    int required = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0) {
        return {};
    }

    std::wstring wide(static_cast<size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), wide.data(), required);
    return wide;
}

std::string EscapeJsonString(const std::string& value) {
    std::string escaped;
    for (char ch : value) {
        switch (ch) {
            case '"':
                escaped += "\\\"";
                break;
            case '\\':
                escaped += "\\\\";
                break;
            case '\b':
                escaped += "\\b";
                break;
            case '\f':
                escaped += "\\f";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                escaped += "\\r";
                break;
            case '\t':
                escaped += "\\t";
                break;
            default:
                escaped.push_back(ch);
                break;
        }
    }
    return escaped;
}

std::wstring FormatAddress(const void* value) {
    wchar_t buffer[32]{};
    swprintf_s(buffer, L"0x%p", value);
    return buffer;
}

std::string FormatEntropy(double entropy) {
    char buffer[64]{};
    sprintf_s(buffer, "%.6f", entropy);
    return buffer;
}

bool IsFalsePositive(const std::string& keyHex) {
    for (const char* falsePositive : kFalsePositives) {
        if (keyHex == falsePositive) {
            return true;
        }
    }
    return false;
}

double CalculateEntropy(const std::string& keyHex) {
    if (keyHex.empty()) {
        return 0.0;
    }

    std::array<size_t, 256> frequencies{};
    for (unsigned char ch : keyHex) {
        ++frequencies[ch];
    }

    double entropy = 0.0;
    double length = static_cast<double>(keyHex.size());
    for (size_t count : frequencies) {
        if (count == 0) {
            continue;
        }

        double frequency = static_cast<double>(count) / length;
        entropy -= frequency * (std::log(frequency) / std::log(2.0));
    }

    return entropy;
}

std::string ExtractKeyHex(const BYTE* data, SIZE_T dataSize, SIZE_T patternOffset, const KeyPattern& keyPattern) {
    static constexpr char kHex[] = "0123456789ABCDEF";

    std::string keyHex;
    keyHex.reserve(64);
    for (SIZE_T offset : keyPattern.dwordOffsets) {
        SIZE_T absoluteOffset = patternOffset + offset;
        if (absoluteOffset + 4 > dataSize) {
            return {};
        }

        for (SIZE_T i = 0; i < 4; ++i) {
            BYTE byte = data[absoluteOffset + i];
            keyHex.push_back(kHex[byte >> 4]);
            keyHex.push_back(kHex[byte & 0x0f]);
        }
    }

    return keyHex;
}

void ScanSectionForKeys(
    const TargetSection& section,
    const std::vector<BYTE>& data,
    double minimumEntropy,
    std::vector<AesKeyCandidate>* keys) {
    for (const KeyPattern& keyPattern : kKeyPatterns) {
        std::vector<PatternByte> pattern = ParsePattern(keyPattern.signature);
        if (pattern.empty() || data.size() < pattern.size()) {
            continue;
        }

        for (SIZE_T offset = 0; offset + pattern.size() <= data.size(); ++offset) {
            bool matched = true;
            for (SIZE_T i = 0; i < pattern.size(); ++i) {
                if (!pattern[i].wildcard && data[offset + i] != pattern[i].value) {
                    matched = false;
                    break;
                }
            }
            if (!matched) {
                continue;
            }

            std::string keyHex = ExtractKeyHex(data.data(), data.size(), offset, keyPattern);
            if ((keyHex.size() != 32 && keyHex.size() != 64) || IsFalsePositive(keyHex)) {
                continue;
            }

            double entropy = CalculateEntropy(keyHex);
            if (entropy < minimumEntropy) {
                continue;
            }

            keys->push_back({keyHex, section.base + offset, section.name, entropy});
        }
    }
}

bool GetMainModuleTargetSections(std::vector<TargetSection>* sections, std::wstring* errorMessage) {
    const auto* base = reinterpret_cast<const BYTE*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        *errorMessage = L"GetModuleHandleW(nullptr) failed.";
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000) {
        *errorMessage = L"Main module has invalid DOS header.";
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.NumberOfSections == 0 || nt->FileHeader.NumberOfSections > 96) {
        *errorMessage = L"Main module has invalid NT header.";
        return false;
    }

    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        std::wstring name = SectionName(*section);
        if (name != L".text" && name != L".rdata") {
            continue;
        }

        DWORD size = section->Misc.VirtualSize;
        if (section->SizeOfRawData > 0 && section->SizeOfRawData < size) {
            size = section->SizeOfRawData;
        }
        if (size == 0) {
            continue;
        }

        SIZE_T cappedSize = std::min<SIZE_T>(size, kMaxSectionSize);
        sections->push_back({name, base + section->VirtualAddress, static_cast<DWORD>(cappedSize)});
    }

    if (sections->empty()) {
        *errorMessage = L"No .text or .rdata sections found in main module.";
        return false;
    }

    return true;
}

bool ReadSectionBytes(const TargetSection& section, bool aggressiveRead, std::vector<BYTE>* data, DWORD* error) {
    data->assign(section.size, 0);
    SIZE_T bytesRead = 0;
    if (!ReadMemoryBlock(section.base, data->data(), section.size, aggressiveRead, &bytesRead)) {
        *error = GetLastError();
        data->clear();
        return false;
    }

    data->resize(bytesRead);
    *error = ERROR_SUCCESS;
    return true;
}

bool WriteKeysJson(
    const std::wstring& outputPath,
    const std::vector<AesKeyCandidate>& keys,
    const std::wstring& logPath,
    DWORD* error) {
    std::string json;
    json += "{\r\n";
    json += "  \"process_name\": \"" + EscapeJsonString(WideToUtf8Local(GetProcessName())) + "\",\r\n";
    json += "  \"keys\": [\r\n";

    for (size_t i = 0; i < keys.size(); ++i) {
        const AesKeyCandidate& key = keys[i];
        json += "    {\r\n";
        json += "      \"key\": \"0x" + key.keyHex + "\",\r\n";
        json += "      \"key_size\": " + std::to_string(static_cast<unsigned long long>(key.keyHex.size() * 4)) + ",\r\n";
        json += "      \"address\": \"" + EscapeJsonString(WideToUtf8Local(FormatAddress(key.address))) + "\",\r\n";
        json += "      \"region\": \"" + EscapeJsonString(WideToUtf8Local(key.sectionName)) + "\",\r\n";
        json += "      \"entropy\": " + FormatEntropy(key.entropy) + "\r\n";
        json += "    }";
        json += i + 1 == keys.size() ? "\r\n" : ",\r\n";
    }

    json += "  ]\r\n";
    json += "}\r\n";

    HANDLE file = CreateFileW(
        outputPath.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        *error = GetLastError();
        return false;
    }

    DWORD written = 0;
    bool ok = WriteFile(file, json.data(), static_cast<DWORD>(json.size()), &written, nullptr) == TRUE &&
              written == json.size();
    *error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);

    if (!ok) {
        Log(logPath, L"unreal_aes failed_write_json path=" + outputPath + L" error=" + std::to_wstring(*error));
    }

    return ok;
}

}  // namespace

DWORD DumpUnrealAesKeys(const std::wstring& dumpPath, const std::wstring& logPath, bool aggressiveRead) {
    std::wstring outputDir = BuildSidecarDirectory(dumpPath, L".aes_keys");
    if (!CreateDirectoryW(outputDir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        Log(logPath, L"Failed to create Unreal AES key directory. error=" + std::to_wstring(GetLastError()) + L" path=" + outputDir);
        return 0;
    }

    std::vector<TargetSection> sections;
    std::wstring errorMessage;
    double minimumEntropy = ParseAesKeyMinimumEntropy();
    Log(logPath, L"Unreal AES key scan begin. dir=" + outputDir + L" min_entropy=" + Utf8ToWideLocal(FormatEntropy(minimumEntropy)));
    if (!GetMainModuleTargetSections(&sections, &errorMessage)) {
        Log(logPath, L"Unreal AES key scan failed. " + errorMessage);
        return 0;
    }

    std::vector<AesKeyCandidate> keys;
    ULONGLONG scannedBytes = 0;
    for (const TargetSection& section : sections) {
        Log(
            logPath,
            L"unreal_aes scanning section=" + section.name +
                L" base=" + FormatHexPtr(section.base) +
                L" size=" + std::to_wstring(section.size));

        std::vector<BYTE> data;
        DWORD error = ERROR_SUCCESS;
        if (!ReadSectionBytes(section, aggressiveRead, &data, &error)) {
            Log(
                logPath,
                L"unreal_aes failed_read section=" + section.name +
                    L" base=" + FormatHexPtr(section.base) +
                    L" error=" + std::to_wstring(error) +
                    L" " + FormatWin32Error(error));
            continue;
        }

        scannedBytes += data.size();
        ScanSectionForKeys(section, data, minimumEntropy, &keys);
    }

    for (size_t i = 0; i < keys.size(); ++i) {
        const AesKeyCandidate& key = keys[i];
        Log(
            logPath,
            L"unreal_aes key index=" + std::to_wstring(i) +
                L" key=0x" + Utf8ToWideLocal(key.keyHex) +
                L" bits=" + std::to_wstring(key.keyHex.size() * 4) +
                L" address=" + FormatHexPtr(key.address) +
                L" section=" + key.sectionName +
                L" entropy=" + Utf8ToWideLocal(FormatEntropy(key.entropy)));
    }

    if (!keys.empty()) {
        DWORD error = ERROR_SUCCESS;
        std::wstring outputPath = BuildUniqueFilePath(outputDir, L"aes_keys.json");
        if (WriteKeysJson(outputPath, keys, logPath, &error)) {
            Log(logPath, L"unreal_aes json_path=" + outputPath);
        }
    }

    Log(
        logPath,
        L"Unreal AES key scan end. count=" + std::to_wstring(keys.size()) +
            L" sections=" + std::to_wstring(sections.size()) +
            L" scanned_bytes=" + std::to_wstring(scannedBytes));
    return static_cast<DWORD>(keys.size());
}

}  // namespace ipd
