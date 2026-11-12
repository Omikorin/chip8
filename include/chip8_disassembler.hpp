#pragma once

#include "chip8_opcodes.hpp"

#include <hex/api/content_registry/disassemblers.hpp>

using hex::ContentRegistry::Disassemblers::Architecture;
using hex::ContentRegistry::Disassemblers::Instruction;

#include <map>
#include <optional>
#include <set>
#include <string>

namespace hex::plugin::chip8 {

    enum class AddressType {
        Unknown,
        Code,
        Data,
        Sprite,
        Audio
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
        std::map<u64, size_t> m_dataLengths; // known sizes of drawn sprites and audio patterns
        std::map<u64, size_t> m_dataRows; // listing rows of all data, filled by groupData()

        std::set<u64> m_codeStarts;

        std::map<u16, std::set<u64>> m_jumpSources; // file offsets of the jumps to a virtual address
        std::set<u16> m_callTargets;
        std::set<u64> m_whileJumps; // file offsets of loop exit jumps that Octo writes as while
        std::set<u64> m_beginJumps; // file offsets of jumps that Octo writes as if begin
        std::set<u64> m_elseJumps; // file offsets of jumps that Octo writes as else
        std::map<u64, int> m_endCounts; // number of blocks that end at a virtual address
        std::set<u64> m_hiddenLabels; // virtual addresses of labels that only structured jumps reach

        using RoutineKey = std::pair<u64, std::optional<u16>>; // file offset and i on entry, nullopt if unknown
        std::map<RoutineKey, std::optional<u16>> m_routineSummaries; // i on return
        std::set<RoutineKey> m_activeRoutines;

        int m_variantIndex = 0;
        ChipVariant m_variant = ChipVariant::Chip8;
        Syntax m_syntax = Syntax::Octo;
        bool m_decimalBytes = false;
        bool m_guessPreprocessor = false;

        void analyzeControlFlow();
        void groupData(u64 fileSize);
        void findStructure();
        size_t guardSize(u64 jumpOffset) const;
        bool hasVisibleLabel(u64 virtualAddress) const;
        std::optional<u16> traceRoutine(u64 entryFileOffset, std::optional<u16> entryI);
        const char* hexPrefix() const;
        std::string formatByte(u8 value) const;
        bool isLoopHead(u16 virtualAddress) const;
        std::string guessComparison(u64 dataAddress, std::span<const u8> code, bool negate) const;
        std::string skipCondition(u16 opcode, bool negate) const;
        std::string labelPrefix(const std::string& label, const std::string& mnemonic) const;
    };
}
