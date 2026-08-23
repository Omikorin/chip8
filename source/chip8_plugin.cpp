#include <hex/plugin.hpp>

#include <hex/api/content_registry/disassemblers.hpp>

#include "chip8_disassembler.hpp"

using namespace hex;
using namespace hex::plugin::chip8;

IMHEX_PLUGIN_SETUP("CHIP-8 Plugin", "Michał Korczak", "CHIP-8 disassembler with static analysis") {

    ContentRegistry::Disassemblers::add<CHIP8Disassembler>();
}
