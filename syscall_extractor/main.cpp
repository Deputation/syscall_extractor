#include "common.hpp"

int main(void)
{
	// Initialize the shared_ptr vector with all the syscall_t objects containing the data needed
	// to exxtract a syscall's ID. Syscalls that cannot be found on this system will not be pushed in.
	data::initialize();

	// Initialize the zydis disassembler backend
	disassembler::initialize();

	// Loop through the syscals that we obtained and try to retrieve all the IDs.
	// Some "syscalls" might not have an ID simply because they're not implemented as canonical syscalls, but 
	// follow the same naming conventions and are treated as such by Windows, such as NtQuerySystemTime, which
	// jumps straight to RtlQuerySystemTime like this:
	// 
	// NtQuerySystemTime proc
	//	jmp     RtlQuerySystemTime; 
	// NtQuerySystemTime endp

	auto gathered_syscall_ids = 0;

	for (const auto& syscall : data::syscall_data)
	{
		// Try getting the ID of the syscall by disassembling its stub in ntdll.dll.
		const auto id = syscall->get_id();

		// If there were no errors, print the syscall's name and its id.
		if (id > 0)
		{
			std::cout << "[+] " << syscall->get_name() << "'s ID is: 0x" << std::hex << id << std::endl;
		
			gathered_syscall_ids++;
		}
	}

	std::cout << "[+] Gathered a total of " << std::dec << gathered_syscall_ids << " syscall IDs." << std::endl;
	
	return 0;
}