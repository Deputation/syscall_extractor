#include "common.hpp"

std::vector<std::string> zydis_t::disassemble(void* address, size_t bytes_length)
{
	std::vector<std::string> disassembled_instructions;

	ZyanU64 runtime_address = 0;
	ZyanUSize offset = 0;
	
	ZydisDecodedInstruction instruction;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&this->decoder, 
		reinterpret_cast<ZyanU8*>(address) + offset, bytes_length - offset, &instruction)))
	{
		char buffer[256];
		
		ZydisFormatterFormatInstruction(&this->formatter, &instruction, buffer, sizeof(buffer),
			runtime_address);
		
		disassembled_instructions.push_back(std::string(buffer));
	
		offset += instruction.length;
		runtime_address += instruction.length;
	}

	return disassembled_instructions;
}

zydis_t::zydis_t()
{
	ZydisDecoderInit(&this->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	ZydisFormatterInit(&this->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

std::shared_ptr<zydis_t> disassembler::zydis;

void disassembler::initialize()
{
	zydis = std::make_shared<zydis_t>();
}