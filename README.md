# syscall_extractor
An x64 only C++ syscall ID extractor for Windows. Developed, debugged and tested in 20H2. It contains 471 syscall names extracted from https://github.com/j00ru/windows-syscalls for Windows 20H2. PRs are open!

# How?
It extracts Windows syscall IDs by disassembling stubs located in ``ntdll.dll``, it then looks for any ``mov eax`` instructions and tries to grab the syscall hex code contained in the stubs. Notes and explanations about special cases can be found in the source files as well as an explanation regarding how errors are "reported". [Zydis](https://github.com/zyantific/zydis) is used as a disassembler for the project.

# Documentation
Documentation is already present in the header files to thoroughly explain what each function and class member is supposed to do, if not already clear at first.

# Notes
Make sure you have zydis installed, either via [vcpkg](https://github.com/microsoft/vcpkg) or included manually in the project's folder (you will likely need to edit the project settings if you plan on doing this). The triplet I used when developing the extractor was ``zydis:x64-windows-static``.

# Credits
To format the syscalls nicely and get an output that can be easily converted to a C-style array from j00ru's repository, [AgentBlackout](https://github.com/AgentBlackout) gave me a nice python script that I'll leave here, feel free to customize it as you desire since it's very simple to understand. A copy of the file can be found in the repository as well with the name syscall-names-grabber.py.

```py
import requests
import json
x = requests.get("https://raw.githubusercontent.com/j00ru/windows-syscalls/master/x64/json/nt-per-system.json")
p = json.loads(x.text)
print(p["Windows 10"]["20H2"].keys())
```
