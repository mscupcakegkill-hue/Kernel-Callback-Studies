use std::io::{self, Write};
use std::ptr;
use std::mem;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

// Device path — must match kernel driver's symbolic link
const DEVICE_PATH: &[u16] = &[
    '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
    'D' as u16, 'A' as u16, 'S' as u16, 'H' as u16,
    'D' as u16, 'r' as u16, 'i' as u16, 'v' as u16,
    'e' as u16, 'r' as u16, 0u16,
];

// IOCTL codes — must match kernel driver definitions
const IOCTL_ADD_BLACKLIST: u32       = 0x800;
const IOCTL_REMOVE_BLACKLIST: u32    = 0x801;
const IOCTL_CLEAR_BLACKLIST: u32     = 0x802;
const IOCTL_LIST_BLACKLIST: u32      = 0x803;
const IOCTL_GET_BLACKLIST_COUNT: u32 = 0x804;

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

fn add_blacklist(handle: HANDLE, name: &str) -> bool {
    let mut buffer = [0u8; 256];
    let name_bytes = name.as_bytes();
    let len = name_bytes.len().min(255);
    buffer[..len].copy_from_slice(&name_bytes[..len]);
    buffer[len] = 0;

    let mut returned: u32 = 0;
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_ADD_BLACKLIST,
            buffer.as_mut_ptr() as *mut _,
            (len + 1) as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        ) != 0
    }
}

fn remove_blacklist(handle: HANDLE, name: &str) -> bool {
    let mut buffer = [0u8; 256];
    let name_bytes = name.as_bytes();
    let len = name_bytes.len().min(255);
    buffer[..len].copy_from_slice(&name_bytes[..len]);
    buffer[len] = 0;

    let mut returned: u32 = 0;
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_REMOVE_BLACKLIST,
            buffer.as_mut_ptr() as *mut _,
            (len + 1) as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        ) != 0
    }
}

fn clear_blacklist(handle: HANDLE) -> bool {
    let mut returned: u32 = 0;
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_CLEAR_BLACKLIST,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        ) != 0
    }
}

fn list_blacklist(handle: HANDLE) {
    let mut buffer = [0u8; 4096];
    let mut returned: u32 = 0;
    unsafe {
        if DeviceIoControl(
            handle,
            IOCTL_LIST_BLACKLIST,
            ptr::null_mut(),
            0,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut returned,
            ptr::null_mut(),
        ) != 0 {
            let mut offset = 0;
            while offset < returned as usize {
                let s = &buffer[offset..];
                if let Some(end) = s.iter().position(|&b| b == 0) {
                    let name = std::str::from_utf8(&s[..end]).unwrap_or("(invalid)");
                    println!("  - {}", name);
                    offset += end + 1;
                } else {
                    break;
                }
            }
        }
    }
}

fn get_count(handle: HANDLE) -> usize {
    let mut count: usize = 0;
    let mut returned: u32 = 0;
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_GET_BLACKLIST_COUNT,
            ptr::null_mut(),
            0,
            &mut count as *mut _ as *mut _,
            mem::size_of::<usize>() as u32,
            &mut returned,
            ptr::null_mut(),
        );
    }
    count
}

fn print_help() {
    println!("DASH Driver CLI — Kernel Process Blocker");
    println!("Commands:");
    println!("  add <process.exe>     — Add to blacklist");
    println!("  remove <process.exe>  — Remove from blacklist");
    println!("  clear                 — Clear all blacklist");
    println!("  list                  — Show blacklist");
    println!("  count                 — Show blacklist entry count");
    println!("  help                  — Show this help");
    println!("  exit                  — Quit");
}

fn main() {
    println!("[DASH] Opening device...");

    let handle = match open_device() {
        Some(h) => {
            println!("[DASH] Connected to driver!");
            h
        }
        None => {
            eprintln!("[DASH] ERROR: Cannot open device. Is driver loaded?");
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

        match parts[0] {
            "add" => {
                if parts.len() < 2 {
                    println!("Usage: add <process.exe>");
                } else {
                    if add_blacklist(handle, parts[1]) {
                        println!("[+] Added: {}", parts[1]);
                    } else {
                        println!("[-] Failed to add (duplicate or list full?)");
                    }
                }
            }

            "remove" => {
                if parts.len() < 2 {
                    println!("Usage: remove <process.exe>");
                } else {
                    if remove_blacklist(handle, parts[1]) {
                        println!("[-] Removed: {}", parts[1]);
                    } else {
                        println!("[-] Not found in blacklist");
                    }
                }
            }

            "clear" => {
                if clear_blacklist(handle) {
                    println!("[*] Blacklist cleared!");
                } else {
                    println!("[-] Failed to clear");
                }
            }

            "list" => {
                let count = get_count(handle);
                println!("[*] Blacklist ({} entries):", count);
                list_blacklist(handle);
            }

            "count" => {
                let count = get_count(handle);
                println!("[*] Blacklist count: {}", count);
            }

            "help" => print_help(),

            "exit" => break,

            "" => {}

            _ => println!("Unknown command. Type 'help' for commands."),
        }
    }

    unsafe { CloseHandle(handle); }
    println!("[DASH] Disconnected.");
}
