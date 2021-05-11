import requests
import json
x = requests.get("https://raw.githubusercontent.com/j00ru/windows-syscalls/master/x64/json/nt-per-system.json")
p = json.loads(x.text)
print(p["Windows 10"]["20H2"].keys())
