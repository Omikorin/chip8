#include "chip8_disassembler.hpp"
#include "chip8_opcodes.hpp"

#include <hex/api/imhex_api/provider.hpp>
#include <hex/providers/provider.hpp>

#include <fmt/format.h>
#include <imgui.h>

#include <queue>
namespace hex::plugin::chip8 {

    CHIP8Disassembler::CHIP8Disassembler() : Architecture("CHIP-8") {}

    CHIP8Disassembler::~CHIP8Disassembler() {}

    bool CHIP8Disassembler::start() {
        m_addressTypes.clear();
        m_labels.clear();
        m_dataLengths.clear();

        // CHIP-8 virtual machine programs started historically at 0x200 but the file is not offseted
        u64 vmEntrypoint = 0x200;
        m_labels[vmEntrypoint] = "main";

        u64 fileOffset = 0x0;
        analyzeControlFlow(fileOffset);

        return true;
    }

    void CHIP8Disassembler::analyzeControlFlow(u64 startFileOffset) {
        auto provider = ImHexApi::Provider::get();
        if (provider == nullptr || !provider->isReadable() || provider->getActualSize() == 0)
            return;

        struct TraceState {
            u64 fileOffset;
            u16 i_reg;
        };

        std::queue<TraceState> worklist;
        worklist.push({startFileOffset, 0});

        u64 fileSize = provider->getActualSize();

        while (!worklist.empty()) {
            TraceState state = worklist.front();
            worklist.pop();

            u64 offset = state.fileOffset;
            u16 current_i = state.i_reg;

            // prevent infinite loops if we hit already analyzed code
            if (m_addressTypes.contains(offset)) continue;
            if (offset + 1 >= fileSize) continue;

            u8 bytes[2] = {0};
            provider->read(offset, bytes, 2);
            u16 opcode = (bytes[0] << 8) | bytes[1];

            const OpcodeDef* def = decodeOpcode(opcode, m_variant);
            const u8 size = def != nullptr ? def->size : 2;
            if (offset + size > fileSize) continue;

            // second word of 4-byte instructions such as F000 NNNN
            u16 immediate = 0;
            if (size == 4) {
                u8 extra[2] = {0};
                provider->read(offset + 2, extra, 2);
                immediate = (extra[0] << 8) | extra[1];
            }

            for (u8 i = 0; i < size; i++) {
                m_addressTypes[offset + i] = AddressType::Code;
            }

            const OpcodeFields fields = splitOpcode(opcode);
            u16 nnn = fields.nnn;
            u8 n = fields.n; // for Dxyn

            bool fallsThrough = true; // does execution continue with the next instruction?

            auto virtualAddressToFileOffset = [](u16 virtAddr) -> std::optional<u64> {
                if (virtAddr >= 0x200) return virtAddr - 0x200;
                return std::nullopt; // addresses below 0x200 point to the interpreter
            };

            // unknown opcodes are treated as plain instructions
            switch (def != nullptr ? def->flow : Flow::Next) {
                case Flow::Return: // return from subroutine
                case Flow::Halt: // exit interpreter
                    fallsThrough = false;
                    break;
                case Flow::Jump: // jump to NNN
                case Flow::Call: { // call NNN
                    auto targetOffset = virtualAddressToFileOffset(nnn);
                    if (targetOffset && targetOffset.value() < fileSize) {
                        worklist.push({targetOffset.value(), current_i});

                        // create a label only if it is not a jump-to-self
                        u16 currentVirtualAddress = offset + 0x200; // loop again
                        if (nnn != currentVirtualAddress && !m_labels.contains(nnn)) {
                            m_labels[nnn] = fmt::format("label_{:03X}", nnn);
                        }
                    }

                    // a jump discards anything after it
                    if (def->flow == Flow::Jump) fallsThrough = false;

                    // calls eventually return (00EE), so the instruction after the call is executed later
                    break;
                }
                case Flow::Skip: { // skip if vX == NN, vX != NN, vX == vY, vX != vY
                    u64 nextOffset = offset + size;
                    if (nextOffset + 1 < fileSize) {
                        // the skipped instruction can be 4 bytes long (F000 NNNN)
                        u8 nextBytes[2] = {0};
                        provider->read(nextOffset, nextBytes, 2);
                        const OpcodeDef* nextDef = decodeOpcode((nextBytes[0] << 8) | nextBytes[1], m_variant);

                        // execution can branch past the next instruction if the condition is met
                        worklist.push({nextOffset + (nextDef != nullptr ? nextDef->size : 2), current_i});
                    }
                    break;
                }
                case Flow::IndirectJump: // jump to NNN + v0
                    // jump to XNN + vX for SUPER-CHIP
                    // v0 is dynamic, so we stop tracing this specific branch
                    fallsThrough = false;
                    break;
                case Flow::Next:
                    break;
            }

            switch (def != nullptr ? def->effect : Effect::None) {
                case Effect::SetI: // i := NNN
                    current_i = nnn;
                    break;
                case Effect::SetILong: // i := long NNNN
                    current_i = immediate;
                    break;
                case Effect::DrawSprite: // sprite vX vY N
                case Effect::DrawBigSprite: // sprite vX vY 0 for SUPER-CHIP and later: 16x16 pixels = 32 bytes
                    if (current_i >= 0x200) {
                        // label using the virtual address
                        m_labels[current_i] = fmt::format("sprite_{:03X}", current_i);

                        auto spriteOffset = virtualAddressToFileOffset(current_i);
                        if (spriteOffset) {
                            u64 offsetVal = spriteOffset.value();

                            size_t spriteBytes = (def->effect == Effect::DrawBigSprite) ? 32 : n;

                            // use max() in case different instructions draw the same sprite with different heights
                            m_dataLengths[offsetVal] = std::max<size_t>(m_dataLengths[offsetVal], spriteBytes);

                            for (size_t idx = 0; idx < spriteBytes; idx++) {
                                if (offsetVal + idx < fileSize) {
                                    m_addressTypes[offsetVal + idx] = AddressType::Sprite;
                                }
                            }
                        }
                    }
                    break;
                case Effect::LoadAudio: // audio, 16 bytes audio pattern at i
                    if (current_i >= 0x200) {
                        m_labels[current_i] = fmt::format("sound_{:03X}", current_i);

                        auto audioOffset = virtualAddressToFileOffset(current_i);
                        if (audioOffset) {
                            u64 offsetVal = audioOffset.value();

                            constexpr size_t audioPatternBytes = 16;
                            m_dataLengths[offsetVal] = std::max<size_t>(m_dataLengths[offsetVal], audioPatternBytes);

                            for (size_t idx = 0; idx < audioPatternBytes; idx++) {
                                if (offsetVal + idx < fileSize) {
                                    m_addressTypes[offsetVal + idx] = AddressType::Audio;
                                }
                            }
                        }
                    }
                    break;
                case Effect::None:
                    break;
            }

            // add the next instruction to the queue if the flow allows it
            if (fallsThrough && offset + size + 1 < fileSize) {
                worklist.push({offset + size, current_i});
            }
        }
    }

    void CHIP8Disassembler::end() {}

    std::optional<Instruction> CHIP8Disassembler::disassemble(u64 imageBaseAddress, u64 instructionLoadAddress, u64 instructionDataAddress, std::span<const u8> code) {
        if (code.empty()) return std::nullopt;

        Instruction inst;
        inst.address = instructionLoadAddress;
        inst.offset = instructionLoadAddress - imageBaseAddress;

        u64 virtualAddress = instructionDataAddress + 0x200;
        auto type = m_addressTypes.contains(instructionDataAddress) ? m_addressTypes[instructionDataAddress] : AddressType::Unknown;

        if (type == AddressType::Code && code.size() >= 2) {
            u16 opcode = (code[0] << 8) | code[1];
            u16 nnn = opcode & 0x0FFF;

            auto getTarget = [&](u16 targetAddr) -> std::string {
                if (m_labels.contains(targetAddr)) return m_labels[targetAddr];
                return fmt::format("0x{:03X}", targetAddr);
            };

            const OpcodeDef* def = decodeOpcode(opcode, m_variant);
            size_t size = def != nullptr ? def->size : 2;

            // a truncated 4-byte instruction at the end of the file is invalid
            if (size > code.size()) {
                size = 2;
                def = nullptr;
            }

            inst.size = size;
            inst.bytes = "";
            for (size_t i = 0; i < size; ++i) {
                if (i > 0) inst.bytes += ' ';
                inst.bytes += fmt::format("{:02X}", code[i]);
            }

            u16 immediate = size == 4 ? u16((code[2] << 8) | code[3]) : 0;

            if (def == nullptr) {
                inst.mnemonic = "invalid";
                inst.operators = "";
            } else if (def->flow == Flow::Jump && nnn == virtualAddress) {
                inst.mnemonic = "loop";
                inst.operators = "again";
            } else {
                const OpcodeText& text = def->text(m_syntax);
                inst.mnemonic = text.mnemonic;
                inst.operators = formatOperands(text.operands, opcode, getTarget, immediate);
            }

            if (m_labels.contains(virtualAddress)) {
                if (inst.mnemonic.empty()) {
                    inst.mnemonic = fmt::format(": {}", m_labels[virtualAddress]);
                } else {
                    inst.mnemonic = fmt::format(": {} {}", m_labels[virtualAddress], inst.mnemonic);
                }
            }
        } else {
            size_t dataLen = 1;
            if (m_dataLengths.contains(instructionDataAddress)) {
                dataLen = m_dataLengths[instructionDataAddress];
            }

            dataLen = std::max<size_t>(1, std::min<size_t>(dataLen, code.size()));

            inst.size = dataLen;

            std::string bytesStr;
            std::string opsStr;

            for (size_t i = 0; i < dataLen; ++i) {
                bytesStr += fmt::format("{:02X}", code[i]);
                opsStr += fmt::format("0x{:02X}", code[i]);

                if (i < dataLen - 1) {
                    bytesStr += " ";
                    opsStr += " ";
                }
            }

            inst.bytes = bytesStr;

            if (m_labels.contains(virtualAddress)) {
                inst.mnemonic = fmt::format(": {}", m_labels[virtualAddress]);
            } else {
                inst.mnemonic = "";
            }

            inst.operators = opsStr;
        }

        return inst;
    }

    void CHIP8Disassembler::drawSettings() {
        constexpr static std::pair<const char*, ChipVariant> Variants[] = {
            { "CHIP-8",     ChipVariant::Chip8 },
            { "Super-CHIP", ChipVariant::SuperChip },
            { "XO-CHIP",    ChipVariant::XOChip }
        };

        if (ImGui::BeginCombo("Variant", Variants[m_variantIndex].first)) {
            for (i32 i = 0; i < IM_ARRAYSIZE(Variants); i++) {
                bool isSelected = (m_variantIndex == i);
                if (ImGui::Selectable(Variants[i].first, isSelected)) {
                    if (!isSelected) {
                        m_variantIndex = i;
                        m_variant = Variants[m_variantIndex].second;
                    }
                }
            }
            ImGui::EndCombo();
        }
    }

    std::string CHIP8Disassembler::getFormattedPatternLanguageType(u64 /*imageBaseAddress*/, u64 /*instructionLoadAddress*/) {
        return "hex::type::Instruction<\"chip-8\", \"default\", 0x00, 0x00>";
    }
}
