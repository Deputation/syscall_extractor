#pragma once

enum e_syscall_extractor_errors : int32_t
{
	// Couldn't find a mov eax, ID instruction while disassembling the syscall's address.
	mov_eax_instruction_not_found = -3, 
	
	// Couldn't find a valid address when calling GetProcAddress to find the syscall stub in ntdll.dll.
	syscall_address_not_found = -2,

	// Couldn't find the syscall's object in the syscall_data vector. The syscall likely doesn't exist
	// in this windows version.
	syscall_name_not_found = -1,

	// Used to "initialize" a yet to be initialized id.
	uninitialized = 0
};

class syscall_t
{
private:
	std::string name;
	void* address;

	/// <summary>
	/// Represents the syscall's ID. It's going to sit uninitialized until syscall_t::get_id() is called.
	/// </summary>
	uint32_t id;

	/// <summary>
	/// bool that represents whether or not the syscall has been disassembled and its ID cached.
	///  
	/// It will be true even if the syscall's ID couldn't be found for whatever reason / error, in this case the 
	/// error will be stored in the ID property and can be retrieved with syscall_t::get_id().
	/// </summary>
	bool id_initialized;

public:
	/// <summary>
	/// Gets the syscall's name.
	/// </summary>
	/// <returns>A copy of the name property as initialized.</returns>
	std::string get_name();

	/// <summary>
	/// Get the address this syscall's stub resides in.
	/// </summary>
	/// <returns>The addrses this syscall's stub resides in.</returns>
	void* get_address();

	/// <summary>
	/// Will try to retrieve the syscall's id, if the id field has not been initialized or the disassembling previously
	/// errored out, there won't be any disassembling performed, the same will happen if the id has already been retrieved
	/// successfully, and a the cached id will be returned.
	/// </summary>
	/// <returns>If > 0, the syscall's id, otherwise, an error code from the e_syscall_extractor_errors enum.</returns>
	uint32_t get_id();

	/// <summary>
	/// Will instantiate a syscall object instance and will immediately try retrieving its address by name via GetProcAddress from ntdll.dll.
	/// </summary>
	/// <param name="name">The syscall's name.</param>
	syscall_t(std::string name);
};

namespace data
{
	/// <summary>
	/// Hardcoded constant data representing the names of all syscalls in windows 20h2.
	/// </summary>
	extern const char* const windows_20h2_syscalls[];

	/// <summary>
	/// Vector containing std::shared_ptrs that we will need to be able to store and retrieve data.
	/// </summary>
	extern std::vector<std::shared_ptr<syscall_t>> syscall_data;

	/// <summary>
	/// The get_syscall_id function will get a syscall's id via disassembling, if the syscall has already been disassembled
	/// in the past, or its address is zero for whatever reason, either an error will be returned, or the syscall's ID.
	/// All errors are represented by a negative number in the e_syscall_extractor_errors enum.
	/// </summary>
	/// <param name="name">The syscall's name.</param>
	/// <returns>If > 0, the syscall's ID, otherwise, an error from e_syscall_extractor_errors.</returns>
	uint32_t get_syscall_id(std::string name);

	/// <summary>
	/// Populate the syscall_data std::vector with the objects that we'll need.
	/// </summary>
	void initialize();
}