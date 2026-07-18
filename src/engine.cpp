// Copyright (C) 2026 First Person
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <QString>
#include <QStringList>
#include <variant>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <map>
#include <cstring>
#include <algorithm>
#include <elf.h>
#include <fcntl.h>
#include <libelf.h>
#include <capstone/capstone.h>
#include <engine.h>

#if defined(__linux__) || defined(__linux) || defined(LINUX)
    #include <sys/uio.h>
    #include <unistd.h>
    #include <signal.h>
#elif defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#endif

struct MemRegion {
    uintptr_t start;
    uintptr_t end;
    std::string perms;
    uintptr_t offset;
    std::string file;
};

enum DwarfTypeResult { TYPE_UNKNOWN, TYPE_SHORT, TYPE_INT, TYPE_LONG, TYPE_DOUBLE, TYPE_PTR };

static bool readProcMem(int pid, uintptr_t addr, void* buf, size_t size);
static std::vector<MemRegion> parseMaps(int pid);

// DWARF constants
namespace Dwarf {
    enum Tag : uint32_t {
        DW_TAG_base_type      = 0x24,
        DW_TAG_pointer_type   = 0x15,
        DW_TAG_const_type     = 0x26,
        DW_TAG_volatile_type  = 0x35,
        DW_TAG_typedef        = 0x16,
        DW_TAG_variable       = 0x34,
        DW_TAG_array_type     = 0x01,
        DW_TAG_structure_type = 0x13,
        DW_TAG_subprogram     = 0x2e,
        DW_TAG_enumeration_type = 0x04,
    };
    enum Attr : uint32_t {
        DW_AT_name            = 0x03,
        DW_AT_type            = 0x49,
        DW_AT_encoding        = 0x3e,
        DW_AT_byte_size       = 0x0b,
        DW_AT_decl_line       = 0x3b,
    };
    enum Form : uint32_t {
        DW_FORM_addr    = 0x01,
        DW_FORM_block2  = 0x03,
        DW_FORM_block4  = 0x04,
        DW_FORM_data2   = 0x05,
        DW_FORM_data4   = 0x06,
        DW_FORM_data8   = 0x07,
        DW_FORM_string  = 0x08,
        DW_FORM_block   = 0x09,
        DW_FORM_block1  = 0x0a,
        DW_FORM_data1   = 0x0b,
        DW_FORM_flag    = 0x0c,
        DW_FORM_sdata   = 0x0d,
        DW_FORM_strp    = 0x0e,
        DW_FORM_udata   = 0x0f,
        DW_FORM_ref1    = 0x11,
        DW_FORM_ref2    = 0x12,
        DW_FORM_ref4    = 0x13,
        DW_FORM_ref8    = 0x14,
        DW_FORM_ref_udata = 0x15,
        DW_FORM_sec_offset = 0x17,
        DW_FORM_exprloc = 0x18,
        DW_FORM_flag_present = 0x19,
        DW_FORM_str8    = 0x21,
    };
    enum ATE : uint8_t {
        DW_ATE_address      = 0x01,
        DW_ATE_boolean      = 0x02,
        DW_ATE_float        = 0x04,
        DW_ATE_signed       = 0x05,
        DW_ATE_signed_char  = 0x06,
        DW_ATE_unsigned     = 0x07,
        DW_ATE_unsigned_char = 0x08,
    };
}

static uint64_t readLEB128(const unsigned char*& data) {
    uint64_t result = 0;
    int shift = 0;
    while (true) {
        uint8_t byte = *data++;
        result |= static_cast<uint64_t>(byte & 0x7f) << shift;
        if (!(byte & 0x80)) break;
        shift += 7;
    }
    return result;
}

struct DwarfSection {
    std::vector<unsigned char> info;
    std::vector<unsigned char> abbrev;
    std::vector<unsigned char> str;
    uintptr_t infoAddr = 0;
    uintptr_t abbrevAddr = 0;
    uintptr_t strAddr = 0;
};

static DwarfSection readDwarfSections(int pid, uintptr_t moduleBase, uintptr_t loadBias) {
    DwarfSection sec;
    Elf64_Ehdr ehdr;
    if (!readProcMem(pid, moduleBase, &ehdr, sizeof(ehdr))) return sec;
    if (std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return sec;

    size_t shdrSize = static_cast<size_t>(ehdr.e_shentsize) * ehdr.e_shnum;
    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    if (!readProcMem(pid, moduleBase + ehdr.e_shoff, shdrs.data(), shdrSize)) return sec;

    if (ehdr.e_shstrndx >= ehdr.e_shnum) return sec;
    std::vector<char> shstrtab(shdrs[ehdr.e_shstrndx].sh_size);
    if (!readProcMem(pid, moduleBase + shdrs[ehdr.e_shstrndx].sh_offset, shstrtab.data(), shdrs[ehdr.e_shstrndx].sh_size)) return sec;

    for (size_t i = 0; i < ehdr.e_shnum; i++) {
        const char* name = shstrtab.data() + shdrs[i].sh_name;
        if (!std::strcmp(name, ".debug_info")) {
            sec.info.resize(shdrs[i].sh_size);
            readProcMem(pid, moduleBase + shdrs[i].sh_offset, sec.info.data(), shdrs[i].sh_size);
            sec.infoAddr = shdrs[i].sh_addr ? loadBias + shdrs[i].sh_addr : 0;
        } else if (!std::strcmp(name, ".debug_abbrev")) {
            sec.abbrev.resize(shdrs[i].sh_size);
            readProcMem(pid, moduleBase + shdrs[i].sh_offset, sec.abbrev.data(), shdrs[i].sh_size);
            sec.abbrevAddr = shdrs[i].sh_addr ? loadBias + shdrs[i].sh_addr : 0;
        } else if (!std::strcmp(name, ".debug_str")) {
            sec.str.resize(shdrs[i].sh_size);
            readProcMem(pid, moduleBase + shdrs[i].sh_offset, sec.str.data(), shdrs[i].sh_size);
            sec.strAddr = shdrs[i].sh_addr ? loadBias + shdrs[i].sh_addr : 0;
        }
    }
    return sec;
}

static DwarfTypeResult resolveTypeEncoding(int pid, const DwarfSection& sec, uint64_t typeOffset,
    const std::vector<unsigned char>& debugInfo, uint64_t debugInfoOffset,
    const std::vector<unsigned char>& debugAbbrev, uint64_t debugAbbrevOffset,
    int depth = 0);

static DwarfTypeResult getVarTypeFromDwarf(int pid, uintptr_t moduleBase, uintptr_t loadBias,
    const std::string& varName) {
    DwarfSection sec = readDwarfSections(pid, moduleBase, loadBias);
    if (sec.info.empty()) return TYPE_UNKNOWN;

    const unsigned char* p = sec.info.data();
    const unsigned char* end = p + sec.info.size();

    while (p < end) {
        uint32_t unitLen = 0;
        uint16_t version = 0;
        uint32_t debugAbbrevOffset = 0;
        uint8_t addressSize = 0;

        if (end - p < 11) break;

        // 32-bit DWARF only
        uint32_t len = 0;
        std::memcpy(&len, p, 4); p += 4;
        if (len == 0xffffffff) break; // 64-bit DWARF not supported
        unitLen = len;
        const unsigned char* unitEnd = p + unitLen;

        std::memcpy(&version, p, 2); p += 2;
        std::memcpy(&debugAbbrevOffset, p, 4); p += 4;
        std::memcpy(&addressSize, p, 1); p += 1;

        const unsigned char* unitDIEs = p;

        // Walk DIEs in this unit
        while (p < unitEnd) {
            uint64_t abbrevCode = readLEB128(p);
            if (abbrevCode == 0) break;

            // Read abbreviation from .debug_abbrev
            uint64_t abbrevOff = debugAbbrevOffset;
            const unsigned char* ap = sec.abbrev.data() + abbrevOff;
            uint64_t code = 0;
            while (true) {
                code = readLEB128(ap);
                if (code == 0) break;
                if (code == abbrevCode) break;
                uint64_t tag = readLEB128(ap);
                (void)tag;
                uint8_t ch = *ap++;
                while (true) {
                    uint64_t attr = readLEB128(ap);
                    uint64_t form = readLEB128(ap);
                    if (attr == 0 && form == 0) break;
                }
            }
            if (code == 0) break;

            uint64_t tag = readLEB128(ap);
            uint8_t hasChildren = *ap++;

            // Read attributes
            uint64_t attrName = 0, attrForm = 0;
            bool isVariable = (tag == Dwarf::DW_TAG_variable);
            bool found = false;
            uint64_t typeOffset = 0;

            std::vector<std::pair<uint64_t, uint64_t>> abbrevAttrs;
            while (true) {
                uint64_t a = readLEB128(ap);
                uint64_t f = readLEB128(ap);
                if (a == 0 && f == 0) break;
                abbrevAttrs.push_back({a, f});
            }

            for (auto& af : abbrevAttrs) {
                attrName = af.first;
                attrForm = af.second;

                if (isVariable && attrName == Dwarf::DW_AT_name) {
                    std::string name;
                    if (attrForm == Dwarf::DW_FORM_strp) {
                        uint32_t strOff = 0;
                        std::memcpy(&strOff, p, 4); p += 4;
                        if (strOff < sec.str.size())
                            name = reinterpret_cast<const char*>(sec.str.data() + strOff);
                    } else if (attrForm == Dwarf::DW_FORM_str8) {
                        uint64_t strOff = 0;
                        std::memcpy(&strOff, p, 8); p += 8;
                        if (strOff < sec.str.size())
                            name = reinterpret_cast<const char*>(sec.str.data() + strOff);
                    } else {
                        // inline string (null-terminated)
                        name = reinterpret_cast<const char*>(p);
                        p += name.size() + 1;
                    }
                    if (name == varName) found = true;
                } else if (isVariable && attrName == Dwarf::DW_AT_type) {
                    switch (attrForm) {
                        case Dwarf::DW_FORM_ref1: typeOffset = *p++; break;
                        case Dwarf::DW_FORM_ref2: { uint16_t v; std::memcpy(&v, p, 2); typeOffset = v; p += 2; break; }
                        case Dwarf::DW_FORM_ref4: { uint32_t v; std::memcpy(&v, p, 4); typeOffset = v; p += 4; break; }
                        case Dwarf::DW_FORM_ref8: { uint64_t v; std::memcpy(&v, p, 8); typeOffset = v; p += 8; break; }
                        case Dwarf::DW_FORM_ref_udata: typeOffset = readLEB128(p); break;
                        default: break;
                    }
                } else {
                    // Skip the attribute value
                    switch (attrForm) {
                        case Dwarf::DW_FORM_addr: p += addressSize; break;
                        case Dwarf::DW_FORM_data1: p += 1; break;
                        case Dwarf::DW_FORM_data2: p += 2; break;
                        case Dwarf::DW_FORM_data4: p += 4; break;
                        case Dwarf::DW_FORM_data8: p += 8; break;
                        case Dwarf::DW_FORM_sdata: readLEB128(p); break;
                        case Dwarf::DW_FORM_udata: readLEB128(p); break;
                        case Dwarf::DW_FORM_flag: p += 1; break;
                        case Dwarf::DW_FORM_flag_present: break;
                        case Dwarf::DW_FORM_sec_offset: p += 4; break;
                        case Dwarf::DW_FORM_strp: p += 4; break;
                        case Dwarf::DW_FORM_str8: p += 8; break;
                        case Dwarf::DW_FORM_exprloc: { uint64_t len = readLEB128(p); p += len; break; }
                        case Dwarf::DW_FORM_block1: { uint8_t len = *p++; p += len; break; }
                        case Dwarf::DW_FORM_block2: { uint16_t len; std::memcpy(&len, p, 2); p += 2; p += len; break; }
                        case Dwarf::DW_FORM_block4: { uint32_t len; std::memcpy(&len, p, 4); p += 4; p += len; break; }
                        case Dwarf::DW_FORM_ref1: p += 1; break;
                        case Dwarf::DW_FORM_ref2: p += 2; break;
                        case Dwarf::DW_FORM_ref4: p += 4; break;
                        case Dwarf::DW_FORM_ref8: p += 8; break;
                        case Dwarf::DW_FORM_ref_udata: readLEB128(p); break;
                        default: break;
                    }
                }
            }

            if (found && typeOffset) {
                DwarfTypeResult res = resolveTypeEncoding(pid, sec, typeOffset, sec.info, 0, sec.abbrev, 0);
                if (res != TYPE_UNKNOWN) return res;
            }

            // Skip children if present
            if (hasChildren) {
                int nestDepth = 1;
                while (p < unitEnd && nestDepth > 0) {
                    uint64_t childCode = readLEB128(p);
                    if (childCode == 0) { nestDepth--; continue; }
                    // Skip child attributes
                    const unsigned char* ap2 = sec.abbrev.data() + debugAbbrevOffset;
                    while (true) {
                        uint64_t c = readLEB128(ap2);
                        if (c == 0) break;
                        if (c == childCode) {
                            uint64_t t = readLEB128(ap2);
                            (void)t;
                            uint8_t ch = *ap2++;
                            if (ch) nestDepth++;
                            while (true) {
                                uint64_t a = readLEB128(ap2);
                                uint64_t f = readLEB128(ap2);
                                if (a == 0 && f == 0) break;
                            }
                            break;
                        }
                        uint64_t t = readLEB128(ap2);
                        (void)t;
                        *ap2++; // has_children
                        while (true) {
                            uint64_t a = readLEB128(ap2);
                            uint64_t f = readLEB128(ap2);
                            if (a == 0 && f == 0) break;
                        }
                    }
                    // Skip attributes of child
                    const unsigned char* ap3 = sec.abbrev.data() + debugAbbrevOffset;
                    while (true) {
                        uint64_t c2 = readLEB128(ap3);
                        if (c2 == 0) break;
                        if (c2 == childCode) {
                            uint64_t t = readLEB128(ap3);
                            (void)t;
                            *ap3++;
                            while (true) {
                                uint64_t a = readLEB128(ap3);
                                uint64_t f = readLEB128(ap3);
                                if (a == 0 && f == 0) break;
                                switch (f) {
                                    case Dwarf::DW_FORM_addr: p += addressSize; break;
                                    case Dwarf::DW_FORM_data1: p += 1; break;
                                    case Dwarf::DW_FORM_data2: p += 2; break;
                                    case Dwarf::DW_FORM_data4: p += 4; break;
                                    case Dwarf::DW_FORM_data8: p += 8; break;
                                    case Dwarf::DW_FORM_sdata: readLEB128(p); break;
                                    case Dwarf::DW_FORM_udata: readLEB128(p); break;
                                    case Dwarf::DW_FORM_flag: p += 1; break;
                                    case Dwarf::DW_FORM_flag_present: break;
                                    case Dwarf::DW_FORM_sec_offset: p += 4; break;
                                    case Dwarf::DW_FORM_strp: p += 4; break;
                                    case Dwarf::DW_FORM_str8: p += 8; break;
                                    case Dwarf::DW_FORM_exprloc: { uint64_t len = readLEB128(p); p += len; break; }
                                    case Dwarf::DW_FORM_block1: { uint8_t len = *p++; p += len; break; }
                                    case Dwarf::DW_FORM_block2: { uint16_t len; std::memcpy(&len, p, 2); p += 2; p += len; break; }
                                    case Dwarf::DW_FORM_block4: { uint32_t len; std::memcpy(&len, p, 4); p += 4; p += len; break; }
                                    case Dwarf::DW_FORM_ref1: p += 1; break;
                                    case Dwarf::DW_FORM_ref2: p += 2; break;
                                    case Dwarf::DW_FORM_ref4: p += 4; break;
                                    case Dwarf::DW_FORM_ref8: p += 8; break;
                                    case Dwarf::DW_FORM_ref_udata: readLEB128(p); break;
                                    default: break;
                                }
                            }
                            break;
                        }
                        uint64_t t = readLEB128(ap3);
                        (void)t;
                        *ap3++;
                        while (true) {
                            uint64_t a = readLEB128(ap3);
                            uint64_t f = readLEB128(ap3);
                            if (a == 0 && f == 0) break;
                        }
                    }
                }
            }
        }
        p = unitEnd;
    }
    return TYPE_UNKNOWN;
}

static DwarfTypeResult resolveTypeEncoding(int pid, const DwarfSection& sec, uint64_t typeOffset,
    const std::vector<unsigned char>& debugInfo, uint64_t debugInfoOffset,
    const std::vector<unsigned char>& debugAbbrev, uint64_t debugAbbrevOffset,
    int depth) {
    if (depth > 10) return TYPE_UNKNOWN;
    if (typeOffset >= debugInfo.size()) return TYPE_UNKNOWN;

    const unsigned char* p = debugInfo.data() + typeOffset;
    uint64_t abbrevCode = readLEB128(p);
    if (abbrevCode == 0) return TYPE_UNKNOWN;

    const unsigned char* ap = debugAbbrev.data() + debugAbbrevOffset;
    while (true) {
        uint64_t code = readLEB128(ap);
        if (code == 0) break;
        uint64_t tag = readLEB128(ap);
        uint8_t hasChildren = *ap++;

        std::vector<std::pair<uint64_t, uint64_t>> attrs;
        while (true) {
            uint64_t a = readLEB128(ap);
            uint64_t f = readLEB128(ap);
            if (a == 0 && f == 0) break;
            attrs.push_back({a, f});
        }

        if (code != abbrevCode) continue;

        if (tag == Dwarf::DW_TAG_base_type) {
            uint64_t encoding = 0;
            uint64_t byteSize = 0;
            const unsigned char* attrPtr = p;
            for (auto& af : attrs) {
                uint64_t attrName = af.first;
                uint64_t attrForm = af.second;
                if (attrName == Dwarf::DW_AT_encoding) {
                    if (attrForm == Dwarf::DW_FORM_data1) encoding = *attrPtr;
                    else if (attrForm == Dwarf::DW_FORM_udata) encoding = readLEB128(attrPtr);
                } else if (attrName == Dwarf::DW_AT_byte_size) {
                    if (attrForm == Dwarf::DW_FORM_data1) byteSize = *attrPtr;
                    else if (attrForm == Dwarf::DW_FORM_udata) byteSize = readLEB128(attrPtr);
                    else if (attrForm == Dwarf::DW_FORM_data2) { uint16_t v; std::memcpy(&v, attrPtr, 2); byteSize = v; }
                    else if (attrForm == Dwarf::DW_FORM_data4) { uint32_t v; std::memcpy(&v, attrPtr, 4); byteSize = v; }
                    else if (attrForm == Dwarf::DW_FORM_data8) { uint64_t v; std::memcpy(&v, attrPtr, 8); byteSize = v; }
                }
                // Skip attr value
                switch (attrForm) {
                    case Dwarf::DW_FORM_addr: attrPtr += 8; break;
                    case Dwarf::DW_FORM_data1: attrPtr += 1; break;
                    case Dwarf::DW_FORM_data2: attrPtr += 2; break;
                    case Dwarf::DW_FORM_data4: attrPtr += 4; break;
                    case Dwarf::DW_FORM_data8: attrPtr += 8; break;
                    case Dwarf::DW_FORM_sdata: readLEB128(attrPtr); break;
                    case Dwarf::DW_FORM_udata: readLEB128(attrPtr); break;
                    case Dwarf::DW_FORM_flag: attrPtr += 1; break;
                    case Dwarf::DW_FORM_flag_present: break;
                    case Dwarf::DW_FORM_sec_offset: attrPtr += 4; break;
                    case Dwarf::DW_FORM_strp: attrPtr += 4; break;
                    case Dwarf::DW_FORM_str8: attrPtr += 8; break;
                    case Dwarf::DW_FORM_ref1: attrPtr += 1; break;
                    case Dwarf::DW_FORM_ref2: attrPtr += 2; break;
                    case Dwarf::DW_FORM_ref4: attrPtr += 4; break;
                    case Dwarf::DW_FORM_ref8: attrPtr += 8; break;
                    case Dwarf::DW_FORM_ref_udata: readLEB128(attrPtr); break;
                    case Dwarf::DW_FORM_exprloc: { uint64_t len = readLEB128(attrPtr); attrPtr += len; break; }
                    case Dwarf::DW_FORM_block1: { uint8_t len = *attrPtr++; attrPtr += len; break; }
                    case Dwarf::DW_FORM_block2: { uint16_t len; std::memcpy(&len, attrPtr, 2); attrPtr += 2; attrPtr += len; break; }
                    case Dwarf::DW_FORM_block4: { uint32_t len; std::memcpy(&len, attrPtr, 4); attrPtr += 4; attrPtr += len; break; }
                    default: break;
                }
            }

            switch (encoding) {
                case Dwarf::DW_ATE_float:
                    return (byteSize == 8) ? TYPE_DOUBLE : TYPE_UNKNOWN;
                case Dwarf::DW_ATE_signed:
                case Dwarf::DW_ATE_unsigned:
                    if (byteSize <= 2) return TYPE_SHORT;
                    if (byteSize == 4) return TYPE_INT;
                    if (byteSize >= 8) return TYPE_LONG;
                    return TYPE_UNKNOWN;
                case Dwarf::DW_ATE_signed_char:
                case Dwarf::DW_ATE_unsigned_char:
                case Dwarf::DW_ATE_boolean:
                    return TYPE_SHORT;
                case Dwarf::DW_ATE_address:
                    return TYPE_PTR;
                default:
                    if (byteSize <= 2) return TYPE_SHORT;
                    if (byteSize == 4) return TYPE_INT;
                    return TYPE_LONG;
            }
        }

        if (tag == Dwarf::DW_TAG_pointer_type) {
            return TYPE_PTR;
        }

        if (tag == Dwarf::DW_TAG_const_type || tag == Dwarf::DW_TAG_volatile_type || tag == Dwarf::DW_TAG_typedef) {
            // Follow DW_AT_type
            const unsigned char* attrPtr = p;
            uint64_t nextTypeOffset = 0;
            for (auto& af : attrs) {
                uint64_t attrName = af.first;
                uint64_t attrForm = af.second;
                if (attrName == Dwarf::DW_AT_type) {
                    switch (attrForm) {
                        case Dwarf::DW_FORM_ref1: nextTypeOffset = *attrPtr; break;
                        case Dwarf::DW_FORM_ref2: { uint16_t v; std::memcpy(&v, attrPtr, 2); nextTypeOffset = v; break; }
                        case Dwarf::DW_FORM_ref4: { uint32_t v; std::memcpy(&v, attrPtr, 4); nextTypeOffset = v; break; }
                        case Dwarf::DW_FORM_ref8: { uint64_t v; std::memcpy(&v, attrPtr, 8); nextTypeOffset = v; break; }
                        case Dwarf::DW_FORM_ref_udata: nextTypeOffset = readLEB128(attrPtr); break;
                        default: break;
                    }
                    break;
                }
                switch (attrForm) {
                    case Dwarf::DW_FORM_addr: attrPtr += 8; break;
                    case Dwarf::DW_FORM_data1: attrPtr += 1; break;
                    case Dwarf::DW_FORM_data2: attrPtr += 2; break;
                    case Dwarf::DW_FORM_data4: attrPtr += 4; break;
                    case Dwarf::DW_FORM_data8: attrPtr += 8; break;
                    case Dwarf::DW_FORM_sdata: readLEB128(attrPtr); break;
                    case Dwarf::DW_FORM_udata: readLEB128(attrPtr); break;
                    case Dwarf::DW_FORM_flag: attrPtr += 1; break;
                    case Dwarf::DW_FORM_flag_present: break;
                    case Dwarf::DW_FORM_sec_offset: attrPtr += 4; break;
                    case Dwarf::DW_FORM_strp: attrPtr += 4; break;
                    case Dwarf::DW_FORM_str8: attrPtr += 8; break;
                    case Dwarf::DW_FORM_ref1: attrPtr += 1; break;
                    case Dwarf::DW_FORM_ref2: attrPtr += 2; break;
                    case Dwarf::DW_FORM_ref4: attrPtr += 4; break;
                    case Dwarf::DW_FORM_ref8: attrPtr += 8; break;
                    case Dwarf::DW_FORM_ref_udata: readLEB128(attrPtr); break;
                    case Dwarf::DW_FORM_exprloc: { uint64_t len = readLEB128(attrPtr); attrPtr += len; break; }
                    case Dwarf::DW_FORM_block1: { uint8_t len = *attrPtr++; attrPtr += len; break; }
                    case Dwarf::DW_FORM_block2: { uint16_t len; std::memcpy(&len, attrPtr, 2); attrPtr += 2; attrPtr += len; break; }
                    case Dwarf::DW_FORM_block4: { uint32_t len; std::memcpy(&len, attrPtr, 4); attrPtr += 4; attrPtr += len; break; }
                    default: break;
                }
            }
            if (nextTypeOffset)
                return resolveTypeEncoding(pid, sec, nextTypeOffset, debugInfo, 0, debugAbbrev, 0, depth + 1);
        }

        break;
    }
    return TYPE_UNKNOWN;
}

typedef enum {
    MODE_RUNNING = 0,
    MODE_PAUSED  = 1
} ProgressMode;

inline void setProgressMode(int pid, ProgressMode mode) {
    if (mode == MODE_RUNNING) {
#if defined(__linux__) || defined(__linux) || defined(LINUX)
        if (kill(pid, SIGCONT) != 0)
            throw std::runtime_error("Unable To Freeze Progress");
#else
#error "setProgressMode not implemented of Targeted Platform"
#endif
    } else if (mode == MODE_PAUSED) {
#if defined(__linux__) || defined(__linux) || defined(LINUX)
        if (kill(pid, SIGSTOP) != 0)
            throw std::runtime_error("Unable To Unfreeze Progress");
#else
#error "setProgressMode not implemented of Targeted Platform"
#endif
    }
}

static bool readProcMem(int pid, uintptr_t addr, void* buf, size_t size) {
#if defined(__linux__) || defined(__linux) || defined(LINUX)
    struct iovec local = { buf, size };
    struct iovec remote = { reinterpret_cast<void*>(addr), size };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0) == static_cast<ssize_t>(size);
#else
#error "readProcMem not implemented of Targeted Platform"
#endif
}

static bool writeProcMem(int pid, uintptr_t addr, const void* buf, size_t size) {
#if defined(__linux__) || defined(__linux) || defined(LINUX)
    struct iovec local = { const_cast<void*>(buf), size };
    struct iovec remote = { reinterpret_cast<void*>(addr), size };
    return process_vm_writev(pid, &local, 1, &remote, 1, 0) == static_cast<ssize_t>(size);
#else
#error "writeProcMem not implemented of Targeted Platform"
#endif
}

static std::vector<MemRegion> parseMaps(int pid) {
    std::vector<MemRegion> regions;
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    while (std::getline(maps, line)) {
        MemRegion r{};
        std::istringstream ss(line);
        std::string addrRange, perms, offsetStr, dev, inodeStr;
        ss >> addrRange >> perms >> offsetStr >> dev >> inodeStr;
        std::string path;
        ss >> std::ws;
        std::getline(ss, path);
        std::replace(addrRange.begin(), addrRange.end(), '-', ' ');
        std::istringstream addrStream(addrRange);
        addrStream >> std::hex >> r.start >> r.end;
        r.perms = perms;
        std::istringstream(offsetStr) >> std::hex >> r.offset;
        r.file = path;
        regions.push_back(r);
    }
    return regions;
}

static DwarfTypeResult getDwarfTypeForVar(int pid, const std::string& varName) {
    auto regions = parseMaps(pid);
    std::map<std::string, bool> seen;
    for (const auto& r : regions) {
        if (r.file.empty() || seen.count(r.file)) continue;
        seen[r.file] = true;
        uintptr_t loadBias = r.start - r.offset;
        DwarfTypeResult res = getVarTypeFromDwarf(pid, r.start, loadBias, varName);
        if (res != TYPE_UNKNOWN) return res;
    }
    return TYPE_UNKNOWN;
}

static uintptr_t resolveSymbol(int pid, const MemRegion& region, const std::string& name, size_t* outSize = nullptr) {
    if (region.file.empty()) return 0;

    Elf64_Ehdr ehdr;
    if (!readProcMem(pid, region.start, &ehdr, sizeof(ehdr))) return 0;
    if (std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return 0;

    uintptr_t loadBias = region.start - region.offset;

    size_t shdrSize = static_cast<size_t>(ehdr.e_shentsize) * ehdr.e_shnum;
    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    if (!readProcMem(pid, region.start + ehdr.e_shoff, shdrs.data(), shdrSize)) return 0;

    if (ehdr.e_shstrndx >= ehdr.e_shnum) return 0;
    Elf64_Shdr& shstrtabHdr = shdrs[ehdr.e_shstrndx];
    std::vector<char> shstrtab(shstrtabHdr.sh_size);
    if (!readProcMem(pid, region.start + shstrtabHdr.sh_offset, shstrtab.data(), shstrtabHdr.sh_size)) return 0;

    Elf64_Shdr *sym = nullptr, *str = nullptr;
    for (size_t i = 0; i < ehdr.e_shnum; i++) {
        const char* secName = shstrtab.data() + shdrs[i].sh_name;
        if (!std::strcmp(secName, ".symtab") || !std::strcmp(secName, ".dynsym")) sym = &shdrs[i];
        if (!std::strcmp(secName, ".strtab") || !std::strcmp(secName, ".dynstr")) str = &shdrs[i];
    }
    if (!sym || !str) return 0;

    size_t symCount = sym->sh_size / sym->sh_entsize;
    std::vector<Elf64_Sym> symbols(symCount);
    if (!readProcMem(pid, region.start + sym->sh_offset, symbols.data(), sym->sh_size)) return 0;

    std::vector<char> strtab(str->sh_size);
    if (!readProcMem(pid, region.start + str->sh_offset, strtab.data(), str->sh_size)) return 0;

    for (size_t i = 0; i < symCount; i++) {
        if (symbols[i].st_shndx != SHN_UNDEF && symbols[i].st_value != 0 &&
            symbols[i].st_name < str->sh_size) {
            if (name == strtab.data() + symbols[i].st_name) {
                if (outSize) *outSize = symbols[i].st_size;
                return loadBias + symbols[i].st_value;
            }
        }
    }
    return 0;
}

static std::vector<std::string> listFunctionsInModule(int pid, const MemRegion& region) {
    std::vector<std::string> result;
    if (region.file.empty()) return result;

    Elf64_Ehdr ehdr;
    if (!readProcMem(pid, region.start, &ehdr, sizeof(ehdr))) return result;
    if (std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return result;

    size_t shdrSize = static_cast<size_t>(ehdr.e_shentsize) * ehdr.e_shnum;
    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    if (!readProcMem(pid, region.start + ehdr.e_shoff, shdrs.data(), shdrSize)) return result;

    if (ehdr.e_shstrndx >= ehdr.e_shnum) return result;
    Elf64_Shdr& shstrtabHdr = shdrs[ehdr.e_shstrndx];
    std::vector<char> shstrtab(shstrtabHdr.sh_size);
    if (!readProcMem(pid, region.start + shstrtabHdr.sh_offset, shstrtab.data(), shstrtabHdr.sh_size)) return result;

    Elf64_Shdr *sym = nullptr, *str = nullptr;
    for (size_t i = 0; i < ehdr.e_shnum; i++) {
        const char* secName = shstrtab.data() + shdrs[i].sh_name;
        if (!std::strcmp(secName, ".symtab") || !std::strcmp(secName, ".dynsym")) sym = &shdrs[i];
        if (!std::strcmp(secName, ".strtab") || !std::strcmp(secName, ".dynstr")) str = &shdrs[i];
    }
    if (!sym || !str) return result;

    size_t symCount = sym->sh_size / sym->sh_entsize;
    std::vector<Elf64_Sym> symbols(symCount);
    if (!readProcMem(pid, region.start + sym->sh_offset, symbols.data(), sym->sh_size)) return result;

    std::vector<char> strtab(str->sh_size);
    if (!readProcMem(pid, region.start + str->sh_offset, strtab.data(), str->sh_size)) return result;

    for (size_t i = 0; i < symCount; i++) {
        if (symbols[i].st_shndx != SHN_UNDEF && symbols[i].st_value != 0 &&
            symbols[i].st_name < str->sh_size &&
            ELF64_ST_TYPE(symbols[i].st_info) == STT_FUNC) {
            result.emplace_back(strtab.data() + symbols[i].st_name);
        }
    }
    return result;
}

QStringList listFunctions(int pid) {
#if defined(__linux__) || defined(__linux) || defined(LINUX)
    QStringList functions;
    auto regions = parseMaps(pid);
    std::map<std::string, bool> seen;
    for (const auto& region : regions) {
        if (seen.count(region.file)) continue;
        seen[region.file] = true;
        auto names = listFunctionsInModule(pid, region);
        for (const auto& name : names)
            functions.append(QString::fromStdString(name));
    }
    return functions;
#else
    (void)pid;
    throw std::runtime_error("listFunctions not implemented on this platform");
#endif
}

uintptr_t getAddressByName(int pid, QString name, size_t* outSize = nullptr) {
#if defined(__linux__) || defined(__linux) || defined(LINUX)
    std::string target = name.toStdString();
    auto regions = parseMaps(pid);

    std::map<std::string, uintptr_t> seen;
    for (const auto& region : regions) {
        if (seen.count(region.file)) continue;
        uintptr_t addr = resolveSymbol(pid, region, target, outSize);
        if (addr) {
            seen[region.file] = addr;
            return addr;
        }
        seen[region.file] = 0;
    }
    return 0;
#else
    (void)pid; (void)name; (void)outSize;
    throw std::runtime_error("getAddressByName not implemented on this platform");
#endif
}

DataRegion getRegionOfObject(int pid, QString objectPath) {
    if (objectPath == "")
        throw std::runtime_error("Variable Path Cannot Be Empty");

    QStringList data = objectPath.split('/');
    if (data.count() > 1) {
        DataRegion tmp{};
        for (int i = 0; i < data.count(); i++) {
            uintptr_t addr = getAddressByName(pid, data[i]);
            if (!addr)
                throw std::runtime_error(data[i].toStdString() + " Named Object Not Found.");

            auto regions = parseMaps(pid);
            bool found = false;
            for (const auto& r : regions) {
                if (addr >= r.start && addr < r.end) {
                    if (tmp.startAddr > 0 || tmp.endAddr > 0) {
                        if (addr >= tmp.startAddr && addr < tmp.endAddr) {
                            tmp.startAddr = static_cast<unsigned int>(r.start);
                            tmp.endAddr = static_cast<unsigned int>(r.end);
                            tmp.permissions = r.perms;
                            tmp.backing_file = r.file;
                            found = true;
                            break;
                        }
                    } else {
                        tmp.startAddr = static_cast<unsigned int>(r.start);
                        tmp.endAddr = static_cast<unsigned int>(r.end);
                        tmp.permissions = r.perms;
                        tmp.backing_file = r.file;
                        found = true;
                        break;
                    }
                }
            }
            if (!found)
                throw std::runtime_error(data[i].toStdString() + " Named Object Not Found.");
        }
        return tmp;
    } else {
        uintptr_t addr = getAddressByName(pid, data[0]);
        if (!addr)
            throw std::runtime_error(data[0].toStdString() + " Named Object Not Found.");

        QStringList functions = listFunctions(pid);
        QList<DataRegion> funcRegions;
        for (const QString& fn : functions)
            funcRegions.push_back(getRegionOfObject(pid, fn));

        auto regions = parseMaps(pid);
        for (const auto& r : regions) {
            if (!(addr >= r.start && addr < r.end)) continue;
            bool insideFunc = false;
            for (const auto& fr : funcRegions) {
                if (addr >= fr.startAddr && addr < fr.endAddr) {
                    insideFunc = true;
                    break;
                }
            }
            if (!insideFunc) {
                DataRegion result{};
                result.startAddr = static_cast<unsigned int>(r.start);
                result.endAddr = static_cast<unsigned int>(r.end);
                result.permissions = r.perms;
                result.backing_file = r.file;
                return result;
            }
        }
        throw std::runtime_error(data[0].toStdString() + " Named Object Not Found Outside Of Function.");
    }
}

std::variant<char*, int, double, short, long> getValueOfVariable(int pid, QString objectPath) {
    setProgressMode(pid, MODE_PAUSED);
    try {
        DataRegion vregion = getRegionOfObject(pid, objectPath);
        if (!(vregion.startAddr && vregion.endAddr))
            throw std::runtime_error("Variable Not Found.");

        unsigned char buf[8] = {};
        if (!readProcMem(pid, vregion.startAddr, buf,
            static_cast<int>(vregion.endAddr - vregion.startAddr)))
            throw std::runtime_error("Failed To Read Variable Value.");

        DwarfTypeResult dtype = getDwarfTypeForVar(pid, objectPath.toStdString());

        setProgressMode(pid, MODE_RUNNING);

        switch (dtype) {
            case TYPE_SHORT: {
                short v; std::memcpy(&v, buf,
                    static_cast<int>(vregion.endAddr - vregion.startAddr) <= SHRT_MAX ? static_cast<int>(vregion.endAddr - vregion.startAddr) : SHRT_MAX); return v;
            }

            case TYPE_INT: {
                int v; std::memcpy(&v, buf,
                    static_cast<int>(vregion.endAddr - vregion.startAddr) <= sizeof(int) ? static_cast<int>(vregion.endAddr - vregion.startAddr) : sizeof(int));
                return v;
            }

            case TYPE_LONG: {
                long v;
                std::memcpy(&v, buf, static_cast<int>(vregion.endAddr - vregion.startAddr) <= LONG_MAX ? static_cast<int>(vregion.endAddr - vregion.startAddr) : LONG_MAX);
                return v;
            }

            case TYPE_DOUBLE: {
                double v;
                std::memcpy(&v, buf, static_cast<int>(vregion.endAddr - vregion.startAddr) <= sizeof(double) ? static_cast<int>(vregion.endAddr - vregion.startAddr) : sizeof(double));
                return v;
            }

            case TYPE_PTR: {
                long* v;
                std::memcpy(&v, buf, static_cast<int>(vregion.endAddr - vregion.startAddr) <= sizeof(long*) ? static_cast<int>(vregion.endAddr - vregion.startAddr) : sizeof(long*));
                return *v;
            }

            default: {
                long v;
                std::memcpy(&v, buf, static_cast<int>(vregion.endAddr - vregion.startAddr) <= LONG_MAX ? static_cast<int>(vregion.endAddr - vregion.startAddr) : LONG_MAX);
                return v;
            }
        }
    } catch (...) {
        setProgressMode(pid, MODE_RUNNING);
        throw;
    }
}

void setValueOfVariable(int progressIds[], int progressIdsCount, QString objectPath, std::variant<char*, int, double, short, long> value) {
    for (int i = 0; i < progressIdsCount; i++) {
        int pid = progressIds[i];
        setProgressMode(pid, MODE_PAUSED);
        try {
            DataRegion vregion = getRegionOfObject(pid, objectPath);
            if (!(vregion.startAddr && vregion.endAddr))
                throw std::runtime_error("Variable Not Found.");

            size_t varSize = vregion.endAddr - vregion.startAddr;
            size_t bufSize = varSize > 8 ? 8 : varSize; // Limit to 8 bytes max
            std::vector<unsigned char> buf(bufSize);
            if (!readProcMem(pid, vregion.startAddr, buf.data(), static_cast<int>(bufSize)))
                throw std::runtime_error("Failed To Read Variable Value.");

            DwarfTypeResult dtype = getDwarfTypeForVar(pid, objectPath.toStdString());

            switch (dtype) {
                case TYPE_SHORT: {
                    short v = std::get<short>(value);
                    size_t writeSize = sizeof(short) < bufSize ? sizeof(short) : bufSize;
                    std::memcpy(buf.data(), &v, writeSize);
                    break;
                }

                case TYPE_INT: {
                    int v = std::get<int>(value);
                    size_t writeSize = sizeof(int) < bufSize ? sizeof(int) : bufSize;
                    std::memcpy(buf.data(), &v, writeSize);
                    break;
                }

                case TYPE_LONG: {
                    long v = std::get<long>(value);
                    size_t writeSize = sizeof(long) < bufSize ? sizeof(long) : bufSize;
                    std::memcpy(buf.data(), &v, writeSize);
                    break;
                }

                case TYPE_DOUBLE: {
                    double v = std::get<double>(value);
                    size_t writeSize = sizeof(double) < bufSize ? sizeof(double) : bufSize;
                    std::memcpy(buf.data(), &v, writeSize);
                    break;
                }

                case TYPE_PTR: {
                    long v = std::get<long>(value);
                    size_t writeSize = sizeof(long*) < bufSize ? sizeof(long*) : bufSize;
                    std::memcpy(buf.data(), &v, writeSize);
                    break;
                }

                default: {
                    if (std::holds_alternative<int>(value)) {
                        int v = std::get<int>(value);
                        size_t writeSize = sizeof(int) < bufSize ? sizeof(int) : bufSize;
                        std::memcpy(buf.data(), &v, writeSize);
                    } else if (std::holds_alternative<long>(value)) {
                        long v = std::get<long>(value);
                        size_t writeSize = sizeof(long) < bufSize ? sizeof(long) : bufSize;
                        std::memcpy(buf.data(), &v, writeSize);
                    } else if (std::holds_alternative<double>(value)) {
                        double v = std::get<double>(value);
                        size_t writeSize = sizeof(double) < bufSize ? sizeof(double) : bufSize;
                        std::memcpy(buf.data(), &v, writeSize);
                    } else if (std::holds_alternative<short>(value)) {
                        short v = std::get<short>(value);
                        size_t writeSize = sizeof(short) < bufSize ? sizeof(short) : bufSize;
                        std::memcpy(buf.data(), &v, writeSize);
                    }
                    break;
                }
            }

            // Write the value to process memory
            if (!writeProcMem(pid, vregion.startAddr, buf.data(), static_cast<int>(bufSize)))
                throw std::runtime_error("Failed To Write Variable Value.");

            setProgressMode(pid, MODE_RUNNING);
        } catch (...) {
            setProgressMode(pid, MODE_RUNNING);
            throw;
        }
    }
}

int addFunctionCallback(int progressIds[], int progressIdsCount, QString destination, ExecutionTiming timing, void*(callback)()) {
    for (int i = 0; i < progressIdsCount; i++) {
        int pid = progressIds[i];
        setProgressMode(pid, MODE_PAUSED);
        try {
            // Parse destination format: "function_name:callback_id"
            QStringList parts = destination.split(':');
            if (parts.size() < 2)
                throw std::runtime_error("Invalid destination format. Expected: 'function_name:callback_id'");
            
            QString funcName = parts[0];
            int callbackId = parts[1].toInt();
            
            // Find the function address
            DataRegion funcRegion = getRegionOfObject(pid, funcName);
            if (!(funcRegion.startAddr && funcRegion.endAddr))
                throw std::runtime_error("Function not found: " + funcName.toStdString());

            // Implement to find address
            
            setProgressMode(pid, MODE_RUNNING);
            return callbackId;
        } catch (...) {
            setProgressMode(pid, MODE_RUNNING);
            throw;
        }
    }
    return 0;
}

void removeStatement(int progressIds[], int progressIdsCount, QString source) {
    for (int i = 0; i < progressIdsCount; i++) {
        int pid = progressIds[i];
        setProgressMode(pid, MODE_PAUSED);
        try {
            // Parse source format: "function_name" or "function_name:callback_id"
            QStringList parts = source.split(':');
            QString funcName = parts[0];
            
            // Find the function address
            DataRegion funcRegion = getRegionOfObject(pid, funcName);
            if (!(funcRegion.startAddr && funcRegion.endAddr))
                throw std::runtime_error("Function not found: " + funcName.toStdString());
            
            // For now, this is a placeholder for removing callbacks
            // In a real implementation, you would:
            // 1. Restore original instructions at function start
            // 2. Remove the callback from tracking
            
            setProgressMode(pid, MODE_RUNNING);
        } catch (...) {
            setProgressMode(pid, MODE_RUNNING);
            throw;
        }
    }
}