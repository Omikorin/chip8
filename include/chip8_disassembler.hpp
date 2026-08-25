#pragma once

#include <hex/api/content_registry/disassemblers.hpp>

using hex::ContentRegistry::Disassemblers::Architecture;
using hex::ContentRegistry::Disassemblers::Instruction;

#include <map>
#include <string>

namespace hex::plugin::chip8 {

    enum class AddressType {
        Unknown,
        Code,
        Data,
        Sprite
    };

    enum class ChipVariant {
        Chip8,
        SuperChip,
        XOChip
    };

    class CHIP8Disassembler : public Architecture {
    public:
        explicit CHIP8Disassembler();
        ~CHIP8Disassembler() override;

        bool start() override;
        void end() override;

        std::optional<Instruction> disassemble(u64 imageBaseAddress, u64 instructionLoadAddress, u64 instructionDataAddress, std::span<const u8> code) override;
        void drawSettings() override;
        // TODO: enable when ImHex 1.39.0 is available
        std::string getFormattedPatternLanguageType(u64 imageBaseAddress, u64 instructionLoadAddress); //override;

    private:
        std::map<u64, AddressType> m_addressTypes;
        std::map<u64, std::string> m_labels;
        std::map<u64, size_t> m_dataLengths;

        int m_variantIndex = 0;
        ChipVariant m_variant = ChipVariant::Chip8;

        void analyzeControlFlow(u64 entryAddress);
    };
}
