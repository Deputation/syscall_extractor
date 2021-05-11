#pragma once

class zydis_t
{
private:
	/// <summary>
	/// Refer to Zydis' docs.
	/// </summary>
	ZydisDecoder decoder;
	/// <summary>
	/// Refer to Zydis' docs.
	/// </summary>
	ZydisFormatter formatter;

public:
	/// <summary>
	/// Disassemble code at an address.
	/// </summary>
	/// <param name="address">The address to start disassembling at.</param>
	/// <param name="bytes_length">How many bytes to disassemble.</param>
	/// <returns>An std::vector filled with std::strings, each std::vector 
	/// element will contain the text representation of an instruciton.</returns>
	std::vector<std::string> disassemble(void* address, size_t bytes_length);

	/// <summary>
	/// Initialize the zydis decoder and formatter.
	/// </summary>
	zydis_t();
};

namespace disassembler
{
	/// <summary>
	/// Represents the zydis wrapper that only performs the task we need it to perform.
	/// </summary>
	extern std::shared_ptr<zydis_t> zydis;

	/// <summary>
	/// Initialize the zydis disassembling backend.
	/// </summary>
	void initialize();
}