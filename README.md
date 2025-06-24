Intelbras SIMNext Memory PoC - CVE-2025-XXXXX
Proof of Concept (PoC) tool to demonstrate the cleartext password storage vulnerability (CWE-316) in the Intelbras SIMNext software.

CVE ID: CVE-2025-XXXXX (Pending)

⚠️ Legal Disclaimer
This tool was developed for strictly educational and security research purposes. Using this script against systems for which you do not have explicit authorization is illegal. The author is not responsible for any damage, misuse, or illegal activity caused by this tool. Use it responsibly.

📖 Vulnerability Description
The Intelbras SIMNext software (version [Version Tested] and possibly prior versions) stores the administrator user's password in cleartext within the memory of the SIMNext.exe process after authentication.

This script dynamically exploits this flaw: instead of searching for the unknown password, it searches for a known "anchor value" in memory (such as the connection status string "MainIPConnected"). Upon finding this anchor, the script displays the surrounding memory region, revealing the administrator password stored nearby.

✨ Features
Dynamic Discovery: Does not require prior knowledge of the password.

Anchor-Based Search: Uses a known string to locate the region of interest in memory.

Detailed Hexdump: Displays a memory dump in both hexadecimal and text format for easy analysis.

Automated: Automatically finds the target process's PID.

🛠️ Requirements
Python 3.x

Operating System: Windows

Python Libraries:

psutil

You can install the required library with pip:

pip install psutil

🚀 How to Use
Clone the repository:

git clone https://github.com/g0nc/PoC_Intelbras_SIMNEXT.git
cd YOUR-REPOSITORY

Open SIMNext: Start the Intelbras SIMNext software and log in with an administrator account. The application must remain running.

Run the Script: Open a terminal (Command Prompt or PowerShell) as Administrator and execute the script.

python poc_simnext.py

Analyze the Output: The script will search for the SIMNext.exe process. Once found, it will begin scanning for the anchor string ("MainIPConnected"). If successful, it will display a hexdump of the memory. Look for readable data in the text column to find the password.

--> Anchor found at address: 0x1A9FBD9C4E0
--- Memory Dump around anchor (starting from 0x1A9FBD9C460) ---
00000000:   00 00 00 00 00 00 00 00  00 00 00 4D 61 69 6E 49 |...........MainI|
00000010:   50 43 6F 6E 6E 65 63 74  65 64 00 00 61 64 6D 69 |PConnected..admi|
00000020:   6E 00 00 00 39 34 30 30  35 39 37 34 61 40 00 00 |n...94005974a@..|
00000030:   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |................|
--- End of Dump ---

📄 License
This project is licensed under the MIT License. See the LICENSE file for details.
