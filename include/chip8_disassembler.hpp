#pragma once

#include <hex/api/content_registry/disassemblers.hpp>

using hex::ContentRegistry::Disassemblers::Architecture;
using hex::ContentRegistry::Disassemblers::Instruction;

namespace hex::plugin::chip8 {

    class CHIP8Disassembler : public Architecture {
    public:
        explicit CHIP8Disassembler();
        ~CHIP8Disassembler() override;

        bool start() override;
        void end() override;

        std::optional<Instruction> disassemble(u64 imageBaseAddress, u64 instructionLoadAddress, u64 instructionDataAddress, std::span<const u8> code) override;
        void drawSettings() override;

    private:
    };
}
