from ctypes import *
import ctypes.wintypes
import sys
import os

def inject_dll(pid, dll_path):
    OpenProcess = windll.kernel32.OpenProcess
    OpenProcess.restype  = ctypes.wintypes.HANDLE
    OpenProcess.argtypes = ( ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD )
    
    VirtualAllocEx = windll.kernel32.VirtualAllocEx
    VirtualAllocEx.restype  = ctypes.wintypes.LPVOID
    VirtualAllocEx.argtypes = ( ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD )
    
    WriteProcessMemory = windll.kernel32.WriteProcessMemory
    WriteProcessMemory.restype  = ctypes.wintypes.BOOL
    WriteProcessMemory.argtypes = [ ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER( ctypes.c_size_t ) ]

    CreateRemoteThread = windll.kernel32.CreateRemoteThread
    CreateRemoteThread.restype  = ctypes.wintypes.HANDLE
    CreateRemoteThread.argtypes = [ ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.LPVOID, ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD, ctypes.wintypes.LPDWORD ]
    
    GetModuleHandleW = windll.kernel32.GetModuleHandleW
    GetModuleHandleW.restype  = ctypes.wintypes.HMODULE
    GetModuleHandleW.argtypes = [ ctypes.wintypes.LPCWSTR ]
    
    GetProcAddress = windll.kernel32.GetProcAddress
    GetProcAddress.restype  = ctypes.c_void_p
    GetProcAddress.argtypes = [ ctypes.wintypes.HMODULE, ctypes.wintypes.LPCSTR ] 

    target_pid = int( pid )

    PROCESS_ALL_ACCESS = 0x1F0FFF
    target_process_handle = OpenProcess( PROCESS_ALL_ACCESS, False, target_pid )

    if target_process_handle:
        print("[+] OPEN PROCESS")
    else:
        print("[X] OPEN PROCESS FAILED")
        return False

    dll_path_bytes = bytes(dll_path, 'UTF-8')
    dll_path_length = len(dll_path_bytes) + 1
    remote_memory_address = VirtualAllocEx(target_process_handle, None, dll_path_length, 0x3000, 0x40)

    if remote_memory_address:
        print("[+] Virtual Remote Memory")
    else:
        print("[X] Virtual Remote Memory FAILED")
        return False

    if WriteProcessMemory(target_process_handle, remote_memory_address, dll_path_bytes, dll_path_length, None) == 0:
        print("[X] Failed to write the DLL path to the target process.") 
        return False
    else:
        print("[*] Success to write the DLL path to the target process.")

    kernel32_handle = GetModuleHandleW('kernel32.dll')
    loadlibrary_address = GetProcAddress(kernel32_handle, b'LoadLibraryA')
    
    if kernel32_handle:
        print("[+] kernel32.dll HANDLE")
    else:
        print("[X] kernel32.dll HANDLE FAILED")
    
    if loadlibrary_address:
        print("[+] LoadLibraryA Address")
    else:
        print("[X] LoadLibraryA Address FAILED")
    

    if CreateRemoteThread(target_process_handle, None, 0, loadlibrary_address, remote_memory_address, 0, None) == 0:
        print("[X] Failed to create remote thread in the target process.")
        return False
    else:
        print("[*] Success to create remote thread in the target process.")

    print(f"[*] Successfully injected '{dll_path}' into '{target_process_name}'")
    return True
    
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python dll_injector.py <target_process_name> <dll_path>")
        sys.exit()

    pid = sys.argv[1]
    dll_path = sys.argv[2]

    if not os.path.exists(dll_path):
        print(f"Error: DLL file '{dll_path}' does not exist.")
        sys.exit()

    inject_dll(pid, dll_path)
