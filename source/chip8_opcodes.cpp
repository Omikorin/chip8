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
            // pattern  mask    variants              size flow          effect
            { 0x00E0, 0xFFFF, All,                  2, Next,         None, { "clear", "" } },
            { 0x00EE, 0xFFFF, All,                  2, Return,       None, { "return", "" } }, // return from subroutine
            { 0x00FB, 0xFFFF, SuperChip | XOChip,   2, Next,         None, { "scroll-right", "" } },
            { 0x00FC, 0xFFFF, SuperChip | XOChip,   2, Next,         None, { "scroll-left", "" } },
            { 0x00FD, 0xFFFF, SuperChip | XOChip,   2, Halt,         None, { "exit", "" } }, // exit interpreter
            { 0x00FE, 0xFFFF, SuperChip | XOChip,   2, Next,         None, { "lores", "" } },
            { 0x00FF, 0xFFFF, SuperChip | XOChip,   2, Next,         None, { "hires", "" } },

            { 0x00C0, 0xFFF0, SuperChip | XOChip,   2, Next,         None, { "scroll-down", "{n}" } },

            { 0xE09E, 0xF0FF, All,                  2, Skip,         None, { "", "if v{x} -key then" } },
            { 0xE0A1, 0xF0FF, All,                  2, Skip,         None, { "", "if v{x} key then" } },
            { 0xF007, 0xF0FF, All,                  2, Next,         None, { "", "v{x} := delay" } },
            { 0xF00A, 0xF0FF, All,                  2, Next,         None, { "", "v{x} := key" } },
            { 0xF015, 0xF0FF, All,                  2, Next,         None, { "", "delay := v{x}" } },
            { 0xF018, 0xF0FF, All,                  2, Next,         None, { "", "buzzer := v{x}" } },
            { 0xF01E, 0xF0FF, All,                  2, Next,         None, { "", "i += v{x}" } },
            { 0xF029, 0xF0FF, All,                  2, Next,         None, { "", "i := hex v{x}" } },
            { 0xF030, 0xF0FF, SuperChip | XOChip,   2, Next,         None, { "", "i := bighex v{x}" } },
            { 0xF033, 0xF0FF, All,                  2, Next,         None, { "bcd", "v{x}" } },
            { 0xF055, 0xF0FF, All,                  2, Next,         None, { "save", "v{x}" } },
            { 0xF065, 0xF0FF, All,                  2, Next,         None, { "load", "v{x}" } },
            { 0xF075, 0xF0FF, SuperChip | XOChip,   2, Next,         None, { "saveflags", "v{x}" } },
            { 0xF085, 0xF0FF, SuperChip | XOChip,   2, Next,         None, { "loadflags", "v{x}" } },

            { 0x5000, 0xF00F, All,                  2, Skip,         None, { "", "if v{x} != v{y} then" } }, // skip if vX == vY
            { 0x8000, 0xF00F, All,                  2, Next,         None, { "", "v{x} := v{y}" } },
            { 0x8001, 0xF00F, All,                  2, Next,         None, { "", "v{x} |= v{y}" } },
            { 0x8002, 0xF00F, All,                  2, Next,         None, { "", "v{x} &= v{y}" } },
            { 0x8003, 0xF00F, All,                  2, Next,         None, { "", "v{x} ^= v{y}" } },
            { 0x8004, 0xF00F, All,                  2, Next,         None, { "", "v{x} += v{y}" } },
            { 0x8005, 0xF00F, All,                  2, Next,         None, { "", "v{x} -= v{y}" } },
            { 0x8006, 0xF00F, All,                  2, Next,         None, { "", "v{x} >>= v{y}" } },
            { 0x8007, 0xF00F, All,                  2, Next,         None, { "", "v{x} =- v{y}" } },
            { 0x800E, 0xF00F, All,                  2, Next,         None, { "", "v{x} <<= v{y}" } },
            { 0x9000, 0xF00F, All,                  2, Skip,         None, { "", "if v{x} == v{y} then" } }, // skip if vX != vY
            { 0xD000, 0xF00F, SuperChip | XOChip,   2, Next,    DrawBigSprite, { "sprite", "v{x} v{y} {n}" } }, // Dxy0, sprite vX vY 0

            { 0x1000, 0xF000, All,                  2, Jump,         None, { "jump", "{addr}" } }, // jump to NNN
            { 0x2000, 0xF000, All,                  2, Call,         None, { ":call", "{addr}" } }, // call NNN
            { 0x3000, 0xF000, All,                  2, Skip,         None, { "", "if v{x} != 0x{nn} then" } }, // skip if vX == NN
            { 0x4000, 0xF000, All,                  2, Skip,         None, { "", "if v{x} == 0x{nn} then" } }, // skip if vX != NN
            { 0x6000, 0xF000, All,                  2, Next,         None, { "", "v{x} := 0x{nn}" } },
            { 0x7000, 0xF000, All,                  2, Next,         None, { "", "v{x} += 0x{nn}" } },
            { 0xA000, 0xF000, All,                  2, Next,         SetI, { "", "i := {addr}" } }, // i := NNN
            { 0xB000, 0xF000, Chip8 | XOChip,       2, IndirectJump, None, { "jump0", "{addr}" } }, // jump to NNN + v0
            { 0xB000, 0xF000, SuperChip,            2, IndirectJump, None, { "jump0", "{addr} v{x}" } }, // jump to XNN + vX
            { 0xC000, 0xF000, All,                  2, Next,         None, { "", "v{x} := random 0x{nn}" } },
            { 0xD000, 0xF000, All,                  2, Next,   DrawSprite, { "sprite", "v{x} v{y} {n}" } }, // Dxyn, sprite vX vY N
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

    std::string formatOperands(const char* operandTemplate, u16 opcode, const std::function<std::string(u16)>& resolveAddress) {
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
            else if (key == "n")    result += fmt::format("{}", fields.n);
            else if (key == "nn")   result += fmt::format("{:02X}", fields.nn);
            else if (key == "addr") result += resolveAddress(fields.nnn);
            else {
                result += *p;
                continue;
            }

            p = end;
        }

        return result;
    }
}
