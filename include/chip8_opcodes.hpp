#pragma once

#include <hex/helpers/types.hpp>

#include <functional>
#include <string>

namespace hex::plugin::chip8 {

    // values are bits so that an opcode can declare the set of variants it exists in
    enum class ChipVariant : u8 {
        Chip8     = 1 << 0,
        SuperChip = 1 << 1,
        XOChip    = 1 << 2
    };

    using VariantMask = u8;

    enum class Syntax {
        Octo,
        Chipper
    };

    enum class Flow : u8 {
        Next,         // continues with the following instruction
        Skip,         // the following instruction may be skipped
        Jump,         // unconditional jump to NNN
        Call,         // call NNN, execution resumes after the call once it returns
        Return,       // return from subroutine
        Halt,         // stops the interpreter
        IndirectJump  // target depends on a register, so tracing stops
    };

    enum class Effect : u8 {
        None,
        SetI,          // i := NNN
        SetILong,      // i := the 16 bit word following the opcode
        DrawSprite,    // N bytes at i
        DrawBigSprite, // 16x16 pixels (32 bytes) at i
        LoadAudio      // 16 bytes audio pattern at i
    };

    // operands is a template: {x} {y} register digit, {xd} X in decimal, {n} decimal, {nn} two hex digits,
    // {addr} label or address of NNN, {nnnn} label or address of the word following a 4-byte opcode
    struct OpcodeText {
        const char *mnemonic = "";
        const char *operands = "";
    };

    struct OpcodeDef {
        u16 pattern;
        u16 mask;
        VariantMask variants;
        u8 size;
        Flow flow;
        Effect effect;
        OpcodeText octo;
        OpcodeText chipper;

        const OpcodeText& text(Syntax syntax) const { return syntax == Syntax::Octo ? octo : chipper; }
    };

    struct OpcodeFields {
        u8 x, y, n, nn;
        u16 nnn;
    };

    constexpr OpcodeFields splitOpcode(u16 opcode) {
        return {
            u8((opcode & 0x0F00) >> 8),
            u8((opcode & 0x00F0) >> 4),
            u8(opcode & 0x000F),
            u8(opcode & 0x00FF),
            u16(opcode & 0x0FFF)
        };
    }

    // returns nullptr for opcodes that are not valid in the given variant
    const OpcodeDef* decodeOpcode(u16 opcode, ChipVariant variant);

    std::string formatOperands(const char* operandTemplate, u16 opcode, const std::function<std::string(u16)>& resolveAddress, u16 immediate = 0);
}
