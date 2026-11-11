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
        m_dataRows.clear();
        m_codeStarts.clear();
        m_jumpSources.clear();
        m_callTargets.clear();
        m_routineSummaries.clear();
        m_activeRoutines.clear();

        analyzeControlFlow();

        return true;
    }

    void CHIP8Disassembler::analyzeControlFlow() {
        auto provider = ImHexApi::Provider::get();
        if (provider == nullptr || !provider->isReadable() || provider->getActualSize() == 0)
            return;

        // CHIP-8 virtual machine programs started historically at 0x200 but the file is not offseted
        m_labels[0x200] = "main";

        traceRoutine(0x0, std::nullopt);
        groupData(provider->getActualSize());
    }

    void CHIP8Disassembler::groupData(u64 fileSize) {
        // typical sprite height, used when no drawn sprite gives a hint
        constexpr size_t DefaultRowBytes = 8;

        auto isBoundary = [&](u64 offset) {
            auto type = m_addressTypes.find(offset);
            return (type != m_addressTypes.end() && type->second == AddressType::Code) ||
                   m_labels.contains(offset + 0x200) ||
                   m_dataLengths.contains(offset);
        };

        // bytes that follow a labelled block and belong to no label are grouped like that block, e.g. the second plane of a sprite
        size_t rowBytes = DefaultRowBytes;

        u64 offset = 0;
        while (offset < fileSize) {
            auto type = m_addressTypes.find(offset);
            if (type != m_addressTypes.end() && type->second == AddressType::Code) {
                offset += 1;
                continue;
            }

            size_t length = rowBytes;
            if (auto known = m_dataLengths.find(offset); known != m_dataLengths.end()) {
                length = rowBytes = std::max<size_t>(1, known->second);
            } else if (m_labels.contains(offset + 0x200)) {
                length = rowBytes = DefaultRowBytes;
            }

            for (size_t i = 1; i < length; i++) {
                if (offset + i >= fileSize || isBoundary(offset + i)) {
                    length = i;
                    break;
                }
            }

            m_dataRows[offset] = length;
            offset += length;
        }
    }

    std::optional<u16> CHIP8Disassembler::traceRoutine(u64 entryFileOffset, std::optional<u16> entryI) {
        // the original COSMAC VIP interpreter has a 12 level call stack, deeper nesting is not real code
        constexpr size_t MaxCallDepth = 32;

        // a routine is traced once per value of i it is entered with, as that decides which sprites it draws
        const auto key = std::make_pair(entryFileOffset, entryI);
        if (auto summary = m_routineSummaries.find(key); summary != m_routineSummaries.end())
            return summary->second;

        if (m_activeRoutines.contains(key) || m_activeRoutines.size() >= MaxCallDepth)
            return std::nullopt;
        m_activeRoutines.insert(key);

        auto provider = ImHexApi::Provider::get();
        u64 fileSize = provider->getActualSize();

        struct TraceState {
            u64 fileOffset;
            std::optional<u16> i_reg; // nullopt when unknown
        };

        std::queue<TraceState> worklist;
        worklist.push({entryFileOffset, entryI});

        std::set<u64> visited;

        // i at the return instructions, unknown if they disagree or the routine never returns
        std::optional<u16> returnedI;
        bool returned = false;

        while (!worklist.empty()) {
            TraceState state = worklist.front();
            worklist.pop();

            u64 offset = state.fileOffset;
            std::optional<u16> current_i = state.i_reg;

            // prevent infinite loops if we hit already analyzed code of this routine
            if (visited.contains(offset)) continue;

            // skip data and the middle of instructions, but trace known code again as i may differ
            auto knownType = m_addressTypes.find(offset);
            if (knownType != m_addressTypes.end() && !(knownType->second == AddressType::Code && m_codeStarts.contains(offset))) continue;
            if (offset + 1 >= fileSize) continue;

            visited.insert(offset);

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

            m_codeStarts.insert(offset);
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

            // keeps existing labels, so sprite_ and sound_ labels set later replace it for drawn data
            auto labelDataTarget = [&](u16 virtAddr) {
                auto targetOffset = virtualAddressToFileOffset(virtAddr);
                if (targetOffset && targetOffset.value() < fileSize && !m_labels.contains(virtAddr)) {
                    m_labels[virtAddr] = fmt::format("data_{:03X}", virtAddr);
                }
            };

            // unknown opcodes are treated as plain instructions
            switch (def != nullptr ? def->flow : Flow::Next) {
                case Flow::Return: // return from subroutine
                    if (!returned) {
                        returnedI = current_i;
                        returned = true;
                    } else if (returnedI != current_i) {
                        returnedI = std::nullopt;
                    }
                    fallsThrough = false;
                    break;
                case Flow::Halt: // exit interpreter
                    fallsThrough = false;
                    break;
                case Flow::Jump: // jump to NNN
                case Flow::Call: { // call NNN
                    const bool isCall = def->flow == Flow::Call;

                    auto targetOffset = virtualAddressToFileOffset(nnn);
                    if (targetOffset && targetOffset.value() < fileSize) {
                        if (isCall) {
                            m_callTargets.insert(nnn);
                        } else {
                            m_jumpSources[nnn].insert(offset);
                        }

                        if (isCall) {
                            // there is a single thread, so i after the call is whatever the callee left in it
                            current_i = traceRoutine(targetOffset.value(), current_i);
                        } else {
                            worklist.push({targetOffset.value(), current_i});
                        }

                        // a jump-to-self only needs no label when it is printed as loop again
                        u16 currentVirtualAddress = offset + 0x200;
                        if (nnn != currentVirtualAddress || !(m_guessPreprocessor && m_syntax == Syntax::Octo)) {
                            auto existing = m_labels.find(nnn);

                            if (existing == m_labels.end()) {
                                m_labels[nnn] = fmt::format("{}_{:03X}", isCall ? "sub" : "label", nnn);
                            } else if (isCall && existing->second.starts_with("label_")) {
                                // a call target is a subroutine even if something jumped to it first
                                existing->second = fmt::format("sub_{:03X}", nnn);
                            }
                        }
                    } else if (isCall) {
                        current_i = std::nullopt; // callee is not traceable
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

            const u16 knownI = current_i.value_or(0); // below 0x200 is the interpreter, so it never labels anything

            switch (def != nullptr ? def->effect : Effect::None) {
                case Effect::SetI: // i := NNN
                    current_i = nnn;
                    labelDataTarget(nnn);
                    break;
                case Effect::SetILong: // i := long NNNN
                    current_i = immediate;
                    labelDataTarget(immediate);
                    break;
                case Effect::ClobberI:
                    current_i = std::nullopt;
                    break;
                case Effect::DrawSprite: // sprite vX vY N
                case Effect::DrawBigSprite: // sprite vX vY 0 for SUPER-CHIP and later: 16x16 pixels = 32 bytes
                    if (knownI >= 0x200) {
                        // label using the virtual address
                        m_labels[knownI] = fmt::format("sprite_{:03X}", knownI);

                        auto spriteOffset = virtualAddressToFileOffset(knownI);
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
                    if (knownI >= 0x200) {
                        m_labels[knownI] = fmt::format("sound_{:03X}", knownI);

                        auto audioOffset = virtualAddressToFileOffset(knownI);
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

        m_activeRoutines.erase(key);
        m_routineSummaries[key] = returnedI;

        return returnedI;
    }

    void CHIP8Disassembler::end() {}

    const char* CHIP8Disassembler::hexPrefix() const {
        return m_syntax == Syntax::Chipper ? "#" : "0x";
    }

    std::string CHIP8Disassembler::formatByte(u8 value) const {
        if (m_decimalBytes) return fmt::format("{}", value);

        return fmt::format("{}{:02X}", hexPrefix(), value);
    }

    bool CHIP8Disassembler::isLoopHead(u16 virtualAddress) const {
        auto sources = m_jumpSources.find(virtualAddress);
        if (sources == m_jumpSources.end() || sources->second.size() != 1 || m_callTargets.contains(virtualAddress))
            return false;

        // Octo closes a loop with a single again, and only a jump from further down does that
        return *sources->second.begin() + 0x200 > virtualAddress;
    }

    // Octo compiles a comparison to vF := left, vF -= right (or vF =- right) and a skip on the borrow flag in vF
    // Example of such comparison
    // original:
    // if v1 < 64 then again
    //
    // disassembled:
    // vF := 64
    // vF =- v1
    // if vF == 0 then
    // jump label_3B3
    //
    std::string CHIP8Disassembler::guessComparison(u64 dataAddress, std::span<const u8> code) const {
        if (code.size() < 6) return "";

        // the three instructions have to be traced code and nothing may jump into the middle of them
        for (u64 i = 0; i < 6; i++) {
            auto type = m_addressTypes.find(dataAddress + i);
            if (type == m_addressTypes.end() || type->second != AddressType::Code) return "";
        }
        if (!m_codeStarts.contains(dataAddress + 2) || !m_codeStarts.contains(dataAddress + 4)) return "";
        if (m_labels.contains(dataAddress + 2 + 0x200) || m_labels.contains(dataAddress + 4 + 0x200)) return "";

        const u16 load   = (code[0] << 8) | code[1];
        const u16 sub    = (code[2] << 8) | code[3];
        const u16 skip   = (code[4] << 8) | code[5];

        const bool loadsConstant = (load & 0xFF00) == 0x6F00; // vF := NN
        const bool loadsRegister = (load & 0xFF0F) == 0x8F00; // vF := vY
        const bool subtracts     = (sub & 0xFF0F) == 0x8F05;  // vF -= vX, flag is set when vF >= vX
        const bool subtractsFrom = (sub & 0xFF0F) == 0x8F07;  // vF =- vX, flag is set when vX >= vF

        if (!(loadsConstant || loadsRegister) || !(subtracts || subtractsFrom)) return "";
        if (skip != 0x3F00 && skip != 0x4F00) return "";

        const u8 right = (sub & 0x00F0) >> 4;
        if (right == 0xF) return "";

        // 3F00 runs the next instruction while vF is not zero, 4F00 while it is zero
        const bool flagSet = skip == 0x3F00;

        if (loadsConstant) {
            const std::string constant = formatByte(load & 0x00FF);

            if (subtracts)
                return fmt::format("v{:X} {} {} then", right, flagSet ? "<=" : ">", constant);

            return fmt::format("v{:X} {} {} then", right, flagSet ? ">=" : "<", constant);
        }

        const u8 left = (load & 0x00F0) >> 4;
        if (left == 0xF) return "";

        if (subtracts)
            return fmt::format("v{:X} {} v{:X} then", left, flagSet ? ">=" : "<", right);

        return fmt::format("v{:X} {} v{:X} then", left, flagSet ? "<=" : ">", right);
    }

    // ImHex drops lines with an empty mnemonic when exporting, so Octo statements move their first token there
    static void moveFirstTokenToMnemonic(std::string& mnemonic, std::string& operators) {
        if (!mnemonic.empty()) return;

        const size_t split = operators.find(' ');
        mnemonic = operators.substr(0, split);
        operators = split == std::string::npos ? "" : operators.substr(split + 1);
    }

    std::string CHIP8Disassembler::labelPrefix(const std::string& label, const std::string& mnemonic) const {
        if (m_syntax == Syntax::Chipper) {
            return mnemonic.empty() ? fmt::format("{}:", label) : fmt::format("{}: {}", label, mnemonic);
        }

        return mnemonic.empty() ? fmt::format(": {}", label) : fmt::format(": {} {}", label, mnemonic);
    }

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
                return fmt::format("{}{:03X}", hexPrefix(), targetAddr);
            };

            const OpcodeDef* def = decodeOpcode(opcode, m_variant);
            size_t size = def != nullptr ? def->size : 2;

            // a truncated 4-byte instruction at the end of the file is invalid
            if (size > code.size()) {
                size = 2;
                def = nullptr;
            }

            const bool guessOcto = m_guessPreprocessor && m_syntax == Syntax::Octo;

            std::string comparison;
            if (guessOcto) {
                comparison = guessComparison(instructionDataAddress, code);
                if (!comparison.empty()) size = 6;
            }

            inst.size = size;
            inst.bytes = "";
            for (size_t i = 0; i < size; ++i) {
                if (i > 0) inst.bytes += ' ';
                inst.bytes += fmt::format("{:02X}", code[i]);
            }

            u16 immediate = size == 4 ? u16((code[2] << 8) | code[3]) : 0;

            auto byteFormatter = [this](u8 value) { return formatByte(value); };

            if (!comparison.empty()) {
                inst.mnemonic = "if";
                inst.operators = comparison;
            } else if (def == nullptr) {
                inst.mnemonic = "invalid";
                inst.operators = "";
            } else if (guessOcto && def->flow == Flow::Jump && nnn == virtualAddress) {
                inst.mnemonic = "loop";
                inst.operators = "again";
            } else if (guessOcto && def->flow == Flow::Jump && isLoopHead(nnn)) {
                inst.mnemonic = "again";
                inst.operators = "";
            } else {
                const OpcodeText& text = def->text(m_syntax);
                inst.mnemonic = text.mnemonic;
                inst.operators = formatOperands(text.operands, opcode, getTarget, byteFormatter, immediate);

                // Octo compiles vX -= NN to an addition of the two's complement, so big constants are most likely negative
                const OpcodeFields fields = splitOpcode(opcode);
                if (guessOcto && def->pattern == 0x7000 && fields.nn >= 0xC0) {
                    inst.operators = fmt::format("v{:X} -= {}", fields.x, formatByte(u8(256 - fields.nn)));
                }
            }

            moveFirstTokenToMnemonic(inst.mnemonic, inst.operators);

            if (m_labels.contains(virtualAddress)) {
                if (guessOcto && isLoopHead(virtualAddress)) {
                    inst.mnemonic = fmt::format("loop {}", inst.mnemonic);
                } else {
                    inst.mnemonic = labelPrefix(m_labels[virtualAddress], inst.mnemonic);
                }
            }
        } else {
            size_t dataLen = 1;
            if (m_dataRows.contains(instructionDataAddress)) {
                dataLen = m_dataRows[instructionDataAddress];
            }

            dataLen = std::max<size_t>(1, std::min<size_t>(dataLen, code.size()));

            inst.size = dataLen;

            std::string bytesStr;
            std::string opsStr;

            // Chipper separates data bytes with commas, Octo with spaces
            const char* opsSeparator = m_syntax == Syntax::Chipper ? "," : " ";

            for (size_t i = 0; i < dataLen; ++i) {
                bytesStr += fmt::format("{:02X}", code[i]);
                opsStr += formatByte(code[i]);

                if (i < dataLen - 1) {
                    bytesStr += " ";
                    opsStr += opsSeparator;
                }
            }

            inst.bytes = bytesStr;

            // a label already starts an Octo data row, but ImHex needs a mnemonic on the others
            std::string dataMnemonic = m_syntax == Syntax::Chipper ? "db" : ":byte";

            if (m_labels.contains(virtualAddress)) {
                inst.mnemonic = labelPrefix(m_labels[virtualAddress], m_syntax == Syntax::Chipper ? dataMnemonic : "");
            } else {
                inst.mnemonic = dataMnemonic;
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

        constexpr static std::pair<const char*, Syntax> Syntaxes[] = {
            { "Octo",    Syntax::Octo },
            { "Chipper", Syntax::Chipper }
        };

        if (ImGui::BeginCombo("Syntax", Syntaxes[static_cast<int>(m_syntax)].first)) {
            for (const auto& [name, syntax] : Syntaxes) {
                bool isSelected = (m_syntax == syntax);
                if (ImGui::Selectable(name, isSelected)) {
                    m_syntax = syntax;
                }
            }
            ImGui::EndCombo();
        }

        ImGui::Checkbox("Print bytes as decimal", &m_decimalBytes);

        ImGui::BeginDisabled(m_syntax != Syntax::Octo);
        ImGui::Checkbox("Guess preprocessor instructions", &m_guessPreprocessor);
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Octo only: recognizes comparisons, negative constants and loop / again");
    }

    std::string CHIP8Disassembler::getFormattedPatternLanguageType(u64 /*imageBaseAddress*/, u64 /*instructionLoadAddress*/) {
        return "hex::type::Instruction<\"chip-8\", \"default\", 0x00, 0x00>";
    }
}
