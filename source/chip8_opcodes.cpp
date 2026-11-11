#include "chip8_opcodes.hpp"

#include <fmt/format.h>

#include <bit>
#include <cstring>
#include <iterator>
#include <string_view>

namespace hex::plugin::chip8 {

    namespace {

        using enum Flow;
        using enum Effect;

        constexpr VariantMask Chip8     = u8(ChipVariant::Chip8);
        constexpr VariantMask SuperChip = u8(ChipVariant::SuperChip);
        constexpr VariantMask XOChip    = u8(ChipVariant::XOChip);
        constexpr VariantMask All       = Chip8 | SuperChip | XOChip;

        // the first matching row wins, so rows must be ordered by decreasing mask specificity
        // (00E0 before 0nnn). Rows with the same pattern may differ in variants (Bnnn and Bxnn).
        constexpr OpcodeDef Opcodes[] = {
            // pattern  mask    variants              size flow          effect      octo {mnemonic, operands}                  chipper {mnemonic, operands}
            { 0x00E0, 0xFFFF, All,                  2, Next,         None, { "clear", "" },                               { "cls", "" } },
            { 0x00EE, 0xFFFF, All,                  2, Return,       None, { "return", "" },                              { "ret", "" } }, // return from subroutine
            { 0x00FB, 0xFFFF, SuperChip | XOChip,   2, Next,         None, { "scroll-right", "" },                        { "scr", "" } },
            { 0x00FC, 0xFFFF, SuperChip | XOChip,   2, Next,         None, { "scroll-left", "" },                         { "scl", "" } },
            { 0x00FD, 0xFFFF, SuperChip | XOChip,   2, Halt,         None, { "exit", "" },                                { "exit", "" } }, // exit interpreter
            { 0x00FE, 0xFFFF, SuperChip | XOChip,   2, Next,         None, { "lores", "" },                               { "low", "" } },
            { 0x00FF, 0xFFFF, SuperChip | XOChip,   2, Next,         None, { "hires", "" },                               { "high", "" } },
            { 0xF000, 0xFFFF, XOChip,               4, Next,     SetILong, { "", "i := long {nnnn}" },                    { "dw", "#F000,{nnnn}" } }, // i := long NNNN
            { 0xF002, 0xFFFF, XOChip,               2, Next,    LoadAudio, { "audio", "" },                               { "dw", "#F002" } }, // load 16 bytes audio pattern at i

            { 0x00C0, 0xFFF0, SuperChip | XOChip,   2, Next,         None, { "scroll-down", "{n}" },                      { "scd", "{n}" } },
            { 0x00D0, 0xFFF0, XOChip,               2, Next,         None, { "scroll-up", "{n}" },                        { "scu", "{n}" } },

            { 0xE09E, 0xF0FF, All,                  2, Skip,         None, { "", "if v{x} -key then" },                   { "skp", "v{x}" } },
            { 0xE0A1, 0xF0FF, All,                  2, Skip,         None, { "", "if v{x} key then" },                    { "sknp", "v{x}" } },
            { 0xF001, 0xF0FF, XOChip,               2, Next,         None, { "plane", "{xd}" },                           { "dw", "#F{x}01" } }, // select bit planes to draw on
            { 0xF007, 0xF0FF, All,                  2, Next,         None, { "", "v{x} := delay" },                       { "ld", "v{x},dt" } },
            { 0xF00A, 0xF0FF, All,                  2, Next,         None, { "", "v{x} := key" },                         { "ld", "v{x},k" } },
            { 0xF015, 0xF0FF, All,                  2, Next,         None, { "", "delay := v{x}" },                       { "ld", "dt,v{x}" } },
            { 0xF018, 0xF0FF, All,                  2, Next,         None, { "", "buzzer := v{x}" },                      { "ld", "st,v{x}" } },
            { 0xF01E, 0xF0FF, All,                  2, Next,         None, { "", "i += v{x}" },                           { "add", "i,v{x}" } },
            { 0xF029, 0xF0FF, All,                  2, Next,         None, { "", "i := hex v{x}" },                       { "ld", "lf,v{x}" } },
            { 0xF030, 0xF0FF, SuperChip | XOChip,   2, Next,         None, { "", "i := bighex v{x}" },                    { "ld", "hf,v{x}" } },
            { 0xF033, 0xF0FF, All,                  2, Next,         None, { "bcd", "v{x}" },                             { "ld", "b,v{x}" } },
            { 0xF03A, 0xF0FF, XOChip,               2, Next,         None, { "", "pitch := v{x}" },                       { "dw", "#F{x}3A" } },
            { 0xF055, 0xF0FF, All,                  2, Next,         None, { "save", "v{x}" },                            { "ld", "[i],v{x}" } },
            { 0xF065, 0xF0FF, All,                  2, Next,         None, { "load", "v{x}" },                            { "ld", "v{x},[i]" } },
            { 0xF075, 0xF0FF, SuperChip | XOChip,   2, Next,         None, { "saveflags", "v{x}" },                       { "ld", "r,v{x}" } },
            { 0xF085, 0xF0FF, SuperChip | XOChip,   2, Next,         None, { "loadflags", "v{x}" },                       { "ld", "v{x},r" } },

            { 0x5000, 0xF00F, All,                  2, Skip,         None, { "", "if v{x} != v{y} then" },                { "se", "v{x},v{y}" } }, // skip if vX == vY
            { 0x5002, 0xF00F, XOChip,               2, Next,         None, { "save", "v{x} - v{y}" },                     { "ld", "[i],v{x}-v{y}" } }, // write registers vX to vY at i
            { 0x5003, 0xF00F, XOChip,               2, Next,         None, { "load", "v{x} - v{y}" },                     { "ld", "v{x}-v{y},[i]" } }, // read registers vX to vY from i
            { 0x8000, 0xF00F, All,                  2, Next,         None, { "", "v{x} := v{y}" },                        { "ld", "v{x},v{y}" } },
            { 0x8001, 0xF00F, All,                  2, Next,         None, { "", "v{x} |= v{y}" },                        { "or", "v{x},v{y}" } },
            { 0x8002, 0xF00F, All,                  2, Next,         None, { "", "v{x} &= v{y}" },                        { "and", "v{x},v{y}" } },
            { 0x8003, 0xF00F, All,                  2, Next,         None, { "", "v{x} ^= v{y}" },                        { "xor", "v{x},v{y}" } },
            { 0x8004, 0xF00F, All,                  2, Next,         None, { "", "v{x} += v{y}" },                        { "add", "v{x},v{y}" } },
            { 0x8005, 0xF00F, All,                  2, Next,         None, { "", "v{x} -= v{y}" },                        { "sub", "v{x},v{y}" } },
            { 0x8006, 0xF00F, All,                  2, Next,         None, { "", "v{x} >>= v{y}" },                       { "shr", "v{x},v{y}" } },
            { 0x8007, 0xF00F, All,                  2, Next,         None, { "", "v{x} =- v{y}" },                        { "subn", "v{x},v{y}" } },
            { 0x800E, 0xF00F, All,                  2, Next,         None, { "", "v{x} <<= v{y}" },                       { "shl", "v{x},v{y}" } },
            { 0x9000, 0xF00F, All,                  2, Skip,         None, { "", "if v{x} == v{y} then" },                { "sne", "v{x},v{y}" } }, // skip if vX != vY
            { 0xD000, 0xF00F, SuperChip | XOChip,   2, Next,    DrawBigSprite, { "sprite", "v{x} v{y} {n}" },                { "drw", "v{x},v{y},{n}" } }, // Dxy0, sprite vX vY 0

            { 0x1000, 0xF000, All,                  2, Jump,         None, { "jump", "{addr}" },                          { "jp", "{addr}" } }, // jump to NNN
            { 0x2000, 0xF000, All,                  2, Call,         None, { ":call", "{addr}" },                         { "call", "{addr}" } }, // call NNN
            { 0x3000, 0xF000, All,                  2, Skip,         None, { "", "if v{x} != 0x{nn} then" },              { "se", "v{x},#{nn}" } }, // skip if vX == NN
            { 0x4000, 0xF000, All,                  2, Skip,         None, { "", "if v{x} == 0x{nn} then" },              { "sne", "v{x},#{nn}" } }, // skip if vX != NN
            { 0x6000, 0xF000, All,                  2, Next,         None, { "", "v{x} := 0x{nn}" },                     { "ld", "v{x},#{nn}" } },
            { 0x7000, 0xF000, All,                  2, Next,         None, { "", "v{x} += 0x{nn}" },                     { "add", "v{x},#{nn}" } },
            { 0xA000, 0xF000, All,                  2, Next,         SetI, { "", "i := {addr}" },                        { "ld", "i,{addr}" } }, // i := NNN
            { 0xB000, 0xF000, Chip8 | XOChip,       2, IndirectJump, None, { "jump0", "{addr}" },                         { "jp", "v0,{addr}" } }, // jump to NNN + v0
            { 0xB000, 0xF000, SuperChip,            2, IndirectJump, None, { "jump0", "{addr} v{x}" },                   { "jp", "v{x},{addr}" } }, // jump to XNN + vX
            { 0xC000, 0xF000, All,                  2, Next,         None, { "", "v{x} := random 0x{nn}" },              { "rnd", "v{x},#{nn}" } },
            { 0xD000, 0xF000, All,                  2, Next,   DrawSprite, { "sprite", "v{x} v{y} {n}" },                { "drw", "v{x},v{y},{n}" } }, // Dxyn, sprite vX vY N
        };

        constexpr bool isSortedBySpecificity() {
            for (size_t i = 1; i < std::size(Opcodes); ++i) {
                if (std::popcount(Opcodes[i].mask) > std::popcount(Opcodes[i - 1].mask))
                    return false;
            }
            return true;
        }

        static_assert(isSortedBySpecificity(), "Opcodes must be ordered by decreasing mask specificity");

    }

    const OpcodeDef* decodeOpcode(u16 opcode, ChipVariant variant) {
        for (const auto& def : Opcodes) {
            if ((def.variants & u8(variant)) != 0 && (opcode & def.mask) == def.pattern)
                return &def;
        }

        return nullptr;
    }

    std::string formatOperands(const char* operandTemplate, u16 opcode, const std::function<std::string(u16)>& resolveAddress, u16 immediate) {
        const OpcodeFields fields = splitOpcode(opcode);

        std::string result;
        for (const char* p = operandTemplate; *p != '\0'; ++p) {
            const char* end = (*p == '{') ? std::strchr(p, '}') : nullptr;
            if (end == nullptr) {
                result += *p;
                continue;
            }

            const std::string_view key(p + 1, end - (p + 1));
            if (key == "x")         result += fmt::format("{:X}", fields.x);
            else if (key == "y")    result += fmt::format("{:X}", fields.y);
            else if (key == "xd")   result += fmt::format("{}", fields.x);
            else if (key == "n")    result += fmt::format("{}", fields.n);
            else if (key == "nn")   result += fmt::format("{:02X}", fields.nn);
            else if (key == "addr") result += resolveAddress(fields.nnn);
            else if (key == "nnnn") result += resolveAddress(immediate);
            else {
                result += *p;
                continue;
            }

            p = end;
        }

        return result;
    }
}
