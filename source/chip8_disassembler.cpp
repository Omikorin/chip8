#include "chip8_disassembler.hpp"

#include <hex/api/imhex_api/provider.hpp>
#include <hex/providers/provider.hpp>

#include <queue>
namespace hex::plugin::chip8 {

    CHIP8Disassembler::CHIP8Disassembler() : Architecture("CHIP-8") {}

    CHIP8Disassembler::~CHIP8Disassembler() {}

    bool CHIP8Disassembler::start() {
        m_addressTypes.clear();
        m_labels.clear();

        u64 entrypoint = 0x200;
        m_labels[entrypoint] = "main";

        analyzeControlFlow(entrypoint);

        return true;
    }

    void CHIP8Disassembler::analyzeControlFlow(u64 startAddress) {
        auto provider = ImHexApi::Provider::get();
        if (provider == nullptr || !provider->isReadable() || provider->getActualSize() == 0)
            return;

        std::queue<u64> worklist;
        worklist.push(startAddress);

        while (!worklist.empty()) {
            u64 pc = worklist.front();
            worklist.pop();

            // prevent infinite loops if we hit already analyzed code
            if (m_addressTypes.contains(pc)) continue;
            if (pc + 1 >= provider->getActualSize()) continue;

            u8 bytes[2] = {0};
            provider->read(pc, bytes, 2);
            u16 opcode = (bytes[0] << 8) | bytes[1];

            m_addressTypes[pc] = AddressType::Code;
            m_addressTypes[pc + 1] = AddressType::Code;

            u8 firstNibble = (opcode & 0xF000) >> 12;
            u16 nnn = opcode & 0x0FFF;

            bool fallsThrough = true; // does execution continue to pc + 2?

            switch (firstNibble) {
                case 0x0:
                    if (opcode == 0x00EE) { // return from subroutine
                        fallsThrough = false;
                    }
                    break;
                case 0x1: // jump to NNN
                    worklist.push(nnn);
                    fallsThrough = false;
                    break;
                case 0x2: // call NNN
                    worklist.push(nnn);
                    // calls eventually return (00EE), so the instruction after the call is executed later
                    break;
                case 0x3: // skip if vX == NN
                case 0x4: // skip if vX != NN
                case 0x5: // skip if vX == vY
                case 0x9: // skip if vX != vY
                    // execution can branch to pc + 4 if the condition is met
                    worklist.push(pc + 4);
                    break;
                case 0xB: // jump to NNN + v0
                    // v0 is dynamic, so we stop tracing this specific branch
                    fallsThrough = false;
                    break;
            }

            // add the next instruction to the queue if the flow allows it
            if (fallsThrough) {
                worklist.push(pc + 2);
            }
        }
    }

    void CHIP8Disassembler::end() {}

    std::optional<Instruction> CHIP8Disassembler::disassemble(u64 imageBaseAddress, u64 instructionLoadAddress, u64 instructionDataAddress, std::span<const u8> code) {
        return std::nullopt;
    }

    void CHIP8Disassembler::drawSettings() {}
}
