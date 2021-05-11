# syscall_extractor
A C++ syscall ID extractor for Windows. Developed, debugged and tested in 20H2. It contains 471 syscall names extracted from https://github.com/j00ru/windows-syscalls for Windows 20H2.

# How?
It extracts Windows syscall IDs by disassembling stubs located in ``ntdll.dll``, it then looks for any ``mov eax`` instructions and tries to grab the syscall hex code contained in the stubs. Notes and explanations about special cases can be found in the source files as well as an explanation regarding how errors are "reported".

# Documentation
Documentation is already present in the header files to thoroughly explain what each function and class member is supposed to do, if not already clear at first.

# Credits
To format the syscalls nicely and get an output that can be easily converted to a C-style array from j00ru's repository, [AgentBlackout](https://github.com/AgentBlackout) gave me a nice python script that I'll leave here, feel free to customize it as you desire since it's very simple to undestand.

``
import requests
import json
x = requests.get("https://raw.githubusercontent.com/j00ru/windows-syscalls/master/x64/json/nt-per-system.json")
p = json.loads(x.text)
print(p["Windows 10"]["20H2"].keys())
``