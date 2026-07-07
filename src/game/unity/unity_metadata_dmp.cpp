#include "dumper_internal.h"

#include <dbghelp.h>

#include <algorithm>
#include <string>
#include <vector>

namespace ipd {
namespace {

constexpr DWORD kUnityMetadataMagic = 0xFAB11BAF;
constexpr DWORD kMaxMetadataSize = 512 * 1024 * 1024;

struct MappedFile {
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
    const BYTE* data = nullptr;
    ULONGLONG size = 0;
};

struct DumpMemoryRange {
    ULONGLONG va = 0;
    ULONGLONG size = 0;
    ULONGLONG fileOffset = 0;
};

struct MetadataCandidate {
    ULONGLONG fileOffset = 0;
    ULONGLONG va = 0;
    DWORD size = 0;
    DWORD version = 0;
    bool repairMagic = false;
};

DWORD ReadLe32Mapped(const BYTE* data) {
    return static_cast<DWORD>(data[0]) |
           (static_cast<DWORD>(data[1]) << 8) |
           (static_cast<DWORD>(data[2]) << 16) |
           (static_cast<DWORD>(data[3]) << 24);
}

std::wstring FormatHex64(ULONGLONG value) {
    wchar_t buffer[32]{};
    swprintf_s(buffer, L"0x%llX", value);
    return buffer;
}

bool AddOffset(ULONGLONG base, ULONGLONG add, ULONGLONG* result) {
    if (base > MAXULONGLONG - add) {
        return false;
    }

    *result = base + add;
    return true;
}

bool IsRangeInsideFile(const MappedFile& mapped, ULONGLONG offset, ULONGLONG size) {
    ULONGLONG end = 0;
    return AddOffset(offset, size, &end) && end <= mapped.size;
}

bool MapReadOnlyFile(const std::wstring& path, MappedFile* mapped, DWORD* error) {
    mapped->file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (mapped->file == INVALID_HANDLE_VALUE) {
        *error = GetLastError();
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(mapped->file, &size) || size.QuadPart <= 0) {
        *error = GetLastError();
        CloseHandle(mapped->file);
        mapped->file = INVALID_HANDLE_VALUE;
        return false;
    }

    mapped->size = static_cast<ULONGLONG>(size.QuadPart);
    mapped->mapping = CreateFileMappingW(mapped->file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (mapped->mapping == nullptr) {
        *error = GetLastError();
        CloseHandle(mapped->file);
        mapped->file = INVALID_HANDLE_VALUE;
        return false;
    }

    mapped->data = static_cast<const BYTE*>(MapViewOfFile(mapped->mapping, FILE_MAP_READ, 0, 0, 0));
    if (mapped->data == nullptr) {
        *error = GetLastError();
        CloseHandle(mapped->mapping);
        CloseHandle(mapped->file);
        mapped->mapping = nullptr;
        mapped->file = INVALID_HANDLE_VALUE;
        return false;
    }

    *error = ERROR_SUCCESS;
    return true;
}

void UnmapFile(MappedFile* mapped) {
    if (mapped->data != nullptr) {
        UnmapViewOfFile(mapped->data);
    }
    if (mapped->mapping != nullptr) {
        CloseHandle(mapped->mapping);
    }
    if (mapped->file != INVALID_HANDLE_VALUE) {
        CloseHandle(mapped->file);
    }

    *mapped = {};
}

bool TryGetMetadataSizeFromMappedBytes(
    const BYTE* candidate,
    ULONGLONG maxSize,
    DWORD* metadataSize,
    DWORD* version,
    bool* repairMagic) {
    if (maxSize < 0x100 || maxSize > MAXDWORD) {
        return false;
    }

    DWORD magic = ReadLe32Mapped(candidate);
    if (magic != kUnityMetadataMagic && magic != 0) {
        return false;
    }

    DWORD metadataVersion = ReadLe32Mapped(candidate + 4);
    if (metadataVersion < 16 || metadataVersion > 31) {
        return false;
    }

    DWORD firstOffset = ReadLe32Mapped(candidate + 8);
    if (firstOffset < 0x20 || firstOffset > maxSize || firstOffset > 4096 || (firstOffset % 4) != 0) {
        return false;
    }

    DWORD pairBytes = firstOffset - 8;
    if ((pairBytes % 8) != 0 || pairBytes < 8 * 4) {
        return false;
    }

    DWORD pairCount = pairBytes / 8;
    DWORD maxEnd = firstOffset;
    DWORD nonEmptyPairs = 0;
    for (DWORD i = 0; i < pairCount; ++i) {
        const BYTE* pair = candidate + 8 + (i * 8);
        DWORD offset = ReadLe32Mapped(pair);
        DWORD size = ReadLe32Mapped(pair + 4);
        if (size == 0) {
            continue;
        }

        if (offset < firstOffset || offset > kMaxMetadataSize || size > kMaxMetadataSize - offset) {
            return false;
        }

        ++nonEmptyPairs;
        DWORD end = offset + size;
        if (end > maxEnd) {
            maxEnd = end;
        }
    }

    if (nonEmptyPairs < 4 || maxEnd < 0x100 || maxEnd > maxSize) {
        return false;
    }

    if (magic == 0 && maxEnd < 1024 * 1024) {
        return false;
    }

    *metadataSize = maxEnd;
    *version = metadataVersion;
    *repairMagic = magic == 0;
    return true;
}

bool ParseMemory64Ranges(const MappedFile& mapped, std::vector<DumpMemoryRange>* ranges) {
    if (!IsRangeInsideFile(mapped, 0, sizeof(MINIDUMP_HEADER))) {
        return false;
    }

    auto* header = reinterpret_cast<const MINIDUMP_HEADER*>(mapped.data);
    if (header->Signature != MINIDUMP_SIGNATURE) {
        return false;
    }

    ULONGLONG directorySize = static_cast<ULONGLONG>(header->NumberOfStreams) * sizeof(MINIDUMP_DIRECTORY);
    if (!IsRangeInsideFile(mapped, header->StreamDirectoryRva, directorySize)) {
        return false;
    }

    auto* directories = reinterpret_cast<const MINIDUMP_DIRECTORY*>(mapped.data + header->StreamDirectoryRva);
    for (ULONG i = 0; i < header->NumberOfStreams; ++i) {
        if (directories[i].StreamType != Memory64ListStream) {
            continue;
        }

        RVA rva = directories[i].Location.Rva;
        if (!IsRangeInsideFile(mapped, rva, sizeof(ULONG64) * 2)) {
            return false;
        }

        auto* memoryList = reinterpret_cast<const MINIDUMP_MEMORY64_LIST*>(mapped.data + rva);
        ULONGLONG descriptorSize = memoryList->NumberOfMemoryRanges * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64);
        ULONGLONG descriptorOffset = static_cast<ULONGLONG>(rva) + offsetof(MINIDUMP_MEMORY64_LIST, MemoryRanges);
        if (!IsRangeInsideFile(mapped, descriptorOffset, descriptorSize)) {
            return false;
        }

        ULONGLONG fileOffset = memoryList->BaseRva;
        for (ULONG64 rangeIndex = 0; rangeIndex < memoryList->NumberOfMemoryRanges; ++rangeIndex) {
            const MINIDUMP_MEMORY_DESCRIPTOR64& descriptor = memoryList->MemoryRanges[rangeIndex];
            if (descriptor.DataSize != 0 && IsRangeInsideFile(mapped, fileOffset, descriptor.DataSize)) {
                ranges->push_back({descriptor.StartOfMemoryRange, descriptor.DataSize, fileOffset});
            }

            if (!AddOffset(fileOffset, descriptor.DataSize, &fileOffset)) {
                return false;
            }
        }

        return true;
    }

    return false;
}

void AddCandidateIfValid(
    const MappedFile& mapped,
    const DumpMemoryRange& range,
    ULONGLONG rangeOffset,
    std::vector<MetadataCandidate>* candidates) {
    ULONGLONG fileOffset = range.fileOffset + rangeOffset;
    ULONGLONG va = range.va + rangeOffset;
    ULONGLONG remaining = range.size - rangeOffset;
    if (!IsRangeInsideFile(mapped, fileOffset, 0x100)) {
        return;
    }

    DWORD metadataSize = 0;
    DWORD version = 0;
    bool repairMagic = false;
    if (!TryGetMetadataSizeFromMappedBytes(mapped.data + fileOffset, remaining, &metadataSize, &version, &repairMagic)) {
        return;
    }

    for (const auto& existing : *candidates) {
        if (existing.fileOffset == fileOffset || existing.va == va) {
            return;
        }
    }

    candidates->push_back({fileOffset, va, metadataSize, version, repairMagic});
}

void ScanRangeForMetadata(
    const MappedFile& mapped,
    const DumpMemoryRange& range,
    std::vector<MetadataCandidate>* candidates,
    ULONGLONG* rawMagicCandidates,
    ULONGLONG* zeroMagicCandidates) {
    if (range.size < 0x100 || range.size > MAXDWORD) {
        return;
    }

    const BYTE* rangeData = mapped.data + range.fileOffset;
    DWORD rangeSize = static_cast<DWORD>(range.size);

    for (DWORD offset = 0; offset + 0x100 <= rangeSize; offset += 4) {
        DWORD magic = ReadLe32Mapped(rangeData + offset);
        if (magic == kUnityMetadataMagic) {
            ++(*rawMagicCandidates);
            AddCandidateIfValid(mapped, range, offset, candidates);
            continue;
        }

        if (magic != 0) {
            continue;
        }

        DWORD version = ReadLe32Mapped(rangeData + offset + 4);
        DWORD firstOffset = ReadLe32Mapped(rangeData + offset + 8);
        if (version < 16 || version > 31 || firstOffset < 0x20 || firstOffset > 4096 || (firstOffset % 4) != 0) {
            continue;
        }

        ++(*zeroMagicCandidates);
        AddCandidateIfValid(mapped, range, offset, candidates);
    }
}

bool WriteCandidate(
    const MappedFile& mapped,
    const MetadataCandidate& candidate,
    const std::wstring& outputPath,
    DWORD* error) {
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
    bool ok = WriteFile(file, mapped.data + candidate.fileOffset, candidate.size, &written, nullptr) == TRUE &&
              written == candidate.size;
    if (!ok) {
        *error = GetLastError();
    }

    if (ok && candidate.repairMagic) {
        LARGE_INTEGER zero{};
        SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
        ok = WriteFile(file, &kUnityMetadataMagic, sizeof(kUnityMetadataMagic), &written, nullptr) == TRUE &&
             written == sizeof(kUnityMetadataMagic);
        if (!ok) {
            *error = GetLastError();
        }
    }

    CloseHandle(file);
    if (ok) {
        *error = ERROR_SUCCESS;
    }
    return ok;
}

}  // namespace

DWORD DumpUnityMetadataFromDmp(const std::wstring& dumpPath, const std::wstring& logPath) {
    Log(logPath, L"Unity metadata DMP extraction begin. dump_path=" + dumpPath);

    DWORD error = ERROR_SUCCESS;
    MappedFile mapped{};
    if (!MapReadOnlyFile(dumpPath, &mapped, &error)) {
        Log(logPath, L"Unity metadata DMP extraction failed to map dump. error=" + std::to_wstring(error));
        return 0;
    }

    std::vector<DumpMemoryRange> ranges;
    if (!ParseMemory64Ranges(mapped, &ranges)) {
        Log(logPath, L"Unity metadata DMP extraction failed: Memory64ListStream was not found or invalid.");
        UnmapFile(&mapped);
        return 0;
    }

    std::vector<MetadataCandidate> candidates;
    ULONGLONG rawMagicCandidates = 0;
    ULONGLONG zeroMagicCandidates = 0;
    for (const auto& range : ranges) {
        ScanRangeForMetadata(mapped, range, &candidates, &rawMagicCandidates, &zeroMagicCandidates);
    }

    std::wstring outputDir = BuildSidecarDirectory(dumpPath, L".unity_metadata");
    CreateDirectoryW(outputDir.c_str(), nullptr);

    DWORD dumped = 0;
    for (const auto& candidate : candidates) {
        std::wstring fileName = dumped == 0 ?
            L"global-metadata_dmp.dat" :
            AddSuffixBeforeExtension(L"global-metadata_dmp.dat", L"_" + std::to_wstring(dumped));
        std::wstring outputPath = BuildUniqueFilePath(outputDir, fileName);

        if (WriteCandidate(mapped, candidate, outputPath, &error)) {
            ++dumped;
            Log(
                logPath,
                L"unity_metadata_dmp path=" + outputPath +
                    L" dmp_offset=" + FormatHex64(candidate.fileOffset) +
                    L" va=" + FormatHex64(candidate.va) +
                    L" size=" + std::to_wstring(candidate.size) +
                    L" version=" + std::to_wstring(candidate.version) +
                    L" repaired_magic=" + std::to_wstring(candidate.repairMagic ? 1 : 0));
        } else {
            Log(
                logPath,
                L"unity_metadata_dmp failed_write dmp_offset=" + FormatHex64(candidate.fileOffset) +
                    L" error=" + std::to_wstring(error));
        }
    }

    Log(
        logPath,
        L"Unity metadata DMP extraction end. count=" + std::to_wstring(dumped) +
            L" ranges=" + std::to_wstring(ranges.size()) +
            L" raw_magic_candidates=" + std::to_wstring(rawMagicCandidates) +
            L" zero_magic_candidates=" + std::to_wstring(zeroMagicCandidates));

    UnmapFile(&mapped);
    return dumped;
}

}  // namespace ipd
