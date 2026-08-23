#include "chip8_disassembler.hpp"

#include <hex/api/imhex_api/provider.hpp>
#include <hex/providers/provider.hpp>

#include <fmt/format.h>

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

            m_addressTypes[offset] = AddressType::Code;
            m_addressTypes[offset + 1] = AddressType::Code;

            u8 firstNibble = (opcode & 0xF000) >> 12;
            u16 nnn = opcode & 0x0FFF;
            u8 n = opcode & 0x000F; // for Dxyn

            bool fallsThrough = true; // does execution continue to pc + 2?

            auto virtualAddressToFileOffset = [](u16 virtAddr) -> std::optional<u64> {
                if (virtAddr >= 0x200) return virtAddr - 0x200;
                return std::nullopt; // addresses below 0x200 point to the interpreter
            };

            switch (firstNibble) {
                case 0x0:
                    if (opcode == 0x00EE) { // return from subroutine
                        fallsThrough = false;
                    }
                    break;
                case 0x1: // jump to NNN
                case 0x2: { // call NNN
                    auto targetOffset = virtualAddressToFileOffset(nnn);
                    if (targetOffset && targetOffset.value() < fileSize) {
                        worklist.push({targetOffset.value(), current_i});

                        if (!m_labels.contains(nnn)) {
                            m_labels[nnn] = fmt::format("label_{:03X}", nnn);
                        }
                    }
                    if (firstNibble == 0x1) fallsThrough = false;
                    // calls eventually return (00EE), so the instruction after the call is executed later
                    break;
                }
                case 0x3: // skip if vX == NN
                case 0x4: // skip if vX != NN
                case 0x5: // skip if vX == vY
                case 0x9: // skip if vX != vY
                    if (offset + 3 < fileSize) {
                        // execution can branch to pc + 4 if the condition is met
                        worklist.push({offset + 4, current_i});
                    }
                    break;
                case 0xA: // i := NNN
                    current_i = nnn;
                    break;
                case 0xB: // jump to NNN + v0
                    // v0 is dynamic, so we stop tracing this specific branch
                    fallsThrough = false;
                    break;
                case 0xD: // sprite vX vY N
                    if (current_i >= 0x200) {
                        // label using the virtual address
                        m_labels[current_i] = fmt::format("sprite_{:03X}", current_i);

                        auto spriteOffset = virtualAddressToFileOffset(current_i);
                        if (spriteOffset) {
                            u64 offsetVal = spriteOffset.value();

                            // use max() in case different instructions draw the same sprite with different heights
                            m_dataLengths[offsetVal] = std::max<size_t>(m_dataLengths[offsetVal], n);

                            for (u16 idx = 0; idx < n; idx++) {
                                if (offsetVal + idx < fileSize) {
                                    m_addressTypes[offsetVal + idx] = AddressType::Sprite;
                                }
                            }
                        }
                    }
                    break;
            }

            // add the next instruction to the queue if the flow allows it
            if (fallsThrough && offset + 3 < fileSize) {
                worklist.push({offset + 2, current_i});
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
            inst.size = 2;
            inst.bytes = fmt::format("{:02X} {:02X}", code[0], code[1]);

            u16 opcode = (code[0] << 8) | code[1];
            u8 firstNibble = (opcode & 0xF000) >> 12;
            u8 x  = (opcode & 0x0F00) >> 8;
            u8 y  = (opcode & 0x00F0) >> 4;
            u8 n  = (opcode & 0x000F);
            u8 nn = (opcode & 0x00FF);
            u16 nnn = (opcode & 0x0FFF);

            auto getTarget = [&](u16 targetAddr) -> std::string {
                if (m_labels.contains(targetAddr)) return m_labels[targetAddr];
                return fmt::format("0x{:03X}", targetAddr);
            };

            inst.mnemonic = "";

            switch (firstNibble) {
                case 0x0:
                    if (opcode == 0x00E0)      { inst.mnemonic = "clear"; inst.operators = ""; }
                    else if (opcode == 0x00EE) { inst.mnemonic = "return"; inst.operators = ""; }
                    else                       { inst.mnemonic = "invalid"; inst.operators = ""; }
                    break;
                case 0x1: inst.mnemonic = "jump";  inst.operators = getTarget(nnn); break;
                case 0x2: inst.mnemonic = ":call"; inst.operators = getTarget(nnn); break;
                case 0x3: inst.operators = fmt::format("if v{:X} != 0x{:02X} then", x, nn); break;
                case 0x4: inst.operators = fmt::format("if v{:X} == 0x{:02X} then", x, nn); break;
                case 0x5: inst.operators = fmt::format("if v{:X} != v{:X} then", x, y); break;
                case 0x6: inst.operators = fmt::format("v{:X} := 0x{:02X}", x, nn); break;
                case 0x7: inst.operators = fmt::format("v{:X} += 0x{:02X}", x, nn); break;
                case 0x8:
                    switch (n) {
                        case 0x0: inst.operators = fmt::format("v{:X} := v{:X}", x, y); break;
                        case 0x1: inst.operators = fmt::format("v{:X} |= v{:X}", x, y); break;
                        case 0x2: inst.operators = fmt::format("v{:X} &= v{:X}", x, y); break;
                        case 0x3: inst.operators = fmt::format("v{:X} ^= v{:X}", x, y); break;
                        case 0x4: inst.operators = fmt::format("v{:X} += v{:X}", x, y); break;
                        case 0x5: inst.operators = fmt::format("v{:X} -= v{:X}", x, y); break;
                        case 0x6: inst.operators = fmt::format("v{:X} >>= v{:X}", x, y); break;
                        case 0x7: inst.operators = fmt::format("v{:X} =- v{:X}", x, y); break;
                        case 0xE: inst.operators = fmt::format("v{:X} <<= v{:X}", x, y); break;
                    }
                    break;
                case 0x9: inst.operators = fmt::format("if v{:X} == v{:X} then", x, y); break;
                case 0xA: inst.operators = fmt::format("i := {}", getTarget(nnn)); break;
                case 0xB: inst.mnemonic = "jump0"; inst.operators = getTarget(nnn); break;
                case 0xC: inst.operators = fmt::format("v{:X} := random 0x{:02X}", x, nn); break;
                case 0xD: inst.mnemonic = "sprite"; inst.operators = fmt::format("v{:X} v{:X} {}", x, y, n); break;
                case 0xE:
                    if (nn == 0x9E)      inst.operators = fmt::format("if v{:X} -key then", x);
                    else if (nn == 0xA1) inst.operators = fmt::format("if v{:X} key then", x);
                    break;
                case 0xF:
                    switch (nn) {
                        case 0x07: inst.operators = fmt::format("v{:X} := delay", x); break;
                        case 0x0A: inst.operators = fmt::format("v{:X} := key", x); break;
                        case 0x15: inst.operators = fmt::format("delay := v{:X}", x); break;
                        case 0x18: inst.operators = fmt::format("buzzer := v{:X}", x); break;
                        case 0x1E: inst.operators = fmt::format("i += v{:X}", x); break;
                        case 0x29: inst.operators = fmt::format("i := hex v{:X}", x); break;
                        case 0x33: inst.mnemonic = "bcd";  inst.operators = fmt::format("v{:X}", x); break;
                        case 0x55: inst.mnemonic = "save"; inst.operators = fmt::format("v{:X}", x); break;
                        case 0x65: inst.mnemonic = "load"; inst.operators = fmt::format("v{:X}", x); break;
                    }
                    break;
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

    void CHIP8Disassembler::drawSettings() {}
}
