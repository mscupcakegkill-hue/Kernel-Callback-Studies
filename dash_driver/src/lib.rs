#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ffi::c_char;
use wdk_sys::{
    HANDLE, BOOLEAN, NTSTATUS, STATUS_SUCCESS, DRIVER_OBJECT, DEVICE_OBJECT, IRP,
    ACCESS_MASK, OBJECT_ATTRIBUTES, CLIENT_ID, UNICODE_STRING,
    InitializeObjectAttributes, OBJ_KERNEL_HANDLE,
    IoCreateDevice, IoCreateSymbolicLink, IoCompleteRequest, IoDeleteDevice, IoDeleteSymbolicLink,
    IRP_MJ_DEVICE_CONTROL, IRP_MJ_CREATE, IRP_MJ_CLOSE,
    IoGetCurrentIrpStackLocation,
};

// ============================================================
// IOCTL Codes
// ============================================================
const IOCTL_ADD_BLACKLIST: u32       = 0x800;
const IOCTL_REMOVE_BLACKLIST: u32    = 0x801;
const IOCTL_CLEAR_BLACKLIST: u32     = 0x802;
const IOCTL_LIST_BLACKLIST: u32      = 0x803;
const IOCTL_GET_BLACKLIST_COUNT: u32 = 0x804;

// ============================================================
// Constants
// ============================================================
const MAX_BLACKLIST_ENTRIES: usize = 64;
const MAX_NAME_LENGTH: usize       = 256;

// ============================================================
// UTF-16 Device / Symlink Names
// ============================================================
const DEVICE_NAME_UTF16: [u16; 20] = [
    0x005C, 0x0044, 0x0065, 0x0076, 0x0069, 0x0063, 0x0065, // \Device
    0x005C,                                                   // \
    0x0044, 0x0041, 0x0053, 0x0048,                           // DASH
    0x0044, 0x0072, 0x0069, 0x0076, 0x0065, 0x0072,           // Driver
    0x0000,                                                   // null
];

const SYMLINK_NAME_UTF16: [u16; 24] = [
    0x005C, 0x0044, 0x006F, 0x0073,                           // \Dos
    0x0044, 0x0065, 0x0076, 0x0069, 0x0063, 0x0065, 0x0073,   // Devices
    0x005C,                                                   // \
    0x0044, 0x0041, 0x0053, 0x0048,                           // DASH
    0x0044, 0x0072, 0x0069, 0x0076, 0x0065, 0x0072,           // Driver
    0x0000,                                                   // null
];

// ============================================================
// Dynamic Blacklist
// ============================================================
static mut BLACKLIST: [[u8; MAX_NAME_LENGTH]; MAX_BLACKLIST_ENTRIES] =
    [[0u8; MAX_NAME_LENGTH]; MAX_BLACKLIST_ENTRIES];
static mut BLACKLIST_COUNT: usize = 0;

// ============================================================
// External Kernel Functions
// ============================================================
extern "system" {
    fn DbgPrint(format: *const c_char, ...) -> i32;

    fn PsSetCreateProcessNotifyRoutine(
        notify_routine: Option<unsafe extern "system" fn(HANDLE, HANDLE, BOOLEAN)>,
        remove: BOOLEAN,
    ) -> NTSTATUS;

    fn PsLookupProcessByProcessId(
        ProcessId: HANDLE,
        Process: *mut *mut core::ffi::c_void,
    ) -> NTSTATUS;

    fn PsGetProcessImageFileName(Process: *mut core::ffi::c_void) -> *mut c_char;

    fn ObfDereferenceObject(Object: *mut core::ffi::c_void);

    fn ZwOpenProcess(
        ProcessHandle: *mut HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ClientId: *mut CLIENT_ID,
    ) -> NTSTATUS;

    fn ZwTerminateProcess(
        ProcessHandle: HANDLE,
        ExitStatus: NTSTATUS,
    ) -> NTSTATUS;

    fn ZwClose(Handle: HANDLE) -> NTSTATUS;

    fn RtlCopyMemory(
        Destination: *mut core::ffi::c_void,
        Source: *const core::ffi::c_void,
        Length: usize,
    );

    fn RtlZeroMemory(
        Destination: *mut core::ffi::c_void,
        Length: usize,
    );
}

// ============================================================
// UNICODE_STRING Helper  ✅ BUG-1 FIXED
// ============================================================
unsafe fn init_unicode_string(dest: *mut UNICODE_STRING, src: *const u16) {
    // Count characters (not bytes) until null terminator
    let mut char_count: u16 = 0;
    while *src.add(char_count as usize) != 0 {
        char_count += 1;
    }

    (*dest).Length = char_count * 2;                    // Length in bytes (excludes null)
    (*dest).MaximumLength = (char_count + 1) * 2;       // Max length in bytes (includes null)
    (*dest).Buffer = src as *mut u16;                   // Pointer to UTF-16 buffer
}

// ============================================================
// String Utilities  ✅ BUG-2 FIXED
// ============================================================
// Compare two null-terminated byte strings
// Returns true if identical (including null at same position)
unsafe fn string_compare(a: *const u8, b: *const u8) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }

    let mut i = 0;
    while i < MAX_NAME_LENGTH {
        let byte_a = *a.add(i);
        let byte_b = *b.add(i);

        // If either hits null, both must hit null at the same position
        if byte_a == 0 || byte_b == 0 {
            return byte_a == byte_b;
        }

        if byte_a != byte_b {
            return false;
        }
        i += 1;
    }

    // Safety valve: strings longer than MAX_NAME_LENGTH -> not equal
    false
}

// Check if a name exists in the blacklist
unsafe fn is_blacklisted(name: *const u8) -> bool {
    if name.is_null() {
        return false;
    }

    for i in 0..BLACKLIST_COUNT {
        if string_compare(BLACKLIST[i].as_ptr(), name) {
            return true;
        }
    }
    false
}

// ============================================================
// Blacklist Management
// ============================================================
unsafe fn add_to_blacklist(name: *const u8) -> bool {
    if name.is_null() || BLACKLIST_COUNT >= MAX_BLACKLIST_ENTRIES {
        return false;
    }

    // Prevent duplicates
    if is_blacklisted(name) {
        return false;
    }

    // Calculate name length (excluding null)
    let mut len = 0;
    while len < MAX_NAME_LENGTH - 1 && *name.add(len) != 0 {
        len += 1;
    }

    // Copy name + null terminator into the next free slot
    RtlCopyMemory(
        BLACKLIST[BLACKLIST_COUNT].as_mut_ptr() as *mut core::ffi::c_void,
        name as *const core::ffi::c_void,
        len + 1,
    );

    BLACKLIST_COUNT += 1;
    true
}

unsafe fn remove_from_blacklist(name: *const u8) -> bool {
    if name.is_null() || BLACKLIST_COUNT == 0 {
        return false;
    }

    for i in 0..BLACKLIST_COUNT {
        if string_compare(BLACKLIST[i].as_ptr(), name) {
            // Shift remaining entries down
            for j in i..BLACKLIST_COUNT - 1 {
                RtlCopyMemory(
                    BLACKLIST[j].as_mut_ptr() as *mut core::ffi::c_void,
                    BLACKLIST[j + 1].as_ptr() as *const core::ffi::c_void,
                    MAX_NAME_LENGTH,
                );
            }

            // Clear the now-unused last slot
            RtlZeroMemory(
                BLACKLIST[BLACKLIST_COUNT - 1].as_mut_ptr() as *mut core::ffi::c_void,
                MAX_NAME_LENGTH,
            );

            BLACKLIST_COUNT -= 1;
            return true;
        }
    }
    false
}

unsafe fn clear_blacklist() {
    for i in 0..BLACKLIST_COUNT {
        RtlZeroMemory(
            BLACKLIST[i].as_mut_ptr() as *mut core::ffi::c_void,
            MAX_NAME_LENGTH,
        );
    }
    BLACKLIST_COUNT = 0;
}

// ============================================================
// Process Notify Callback
// ============================================================
unsafe extern "system" fn process_callback(
    _parent_id: HANDLE,
    process_id: HANDLE,
    create: BOOLEAN,
) {
    // Only handle process creation events
    if create == 0 {
        return;
    }

    // --- Resolve PID -> EPROCESS ---
    let mut eprocess: *mut core::ffi::c_void = core::ptr::null_mut();
    let lookup_status = PsLookupProcessByProcessId(process_id, &mut eprocess);

    if lookup_status != STATUS_SUCCESS || eprocess.is_null() {
        return;
    }

    // --- Get process image file name ---
    let name_ptr = PsGetProcessImageFileName(eprocess);

    if name_ptr.is_null() {
        ObfDereferenceObject(eprocess);
        return;
    }

    // Log every new process
    let msg = b"[DASH] New Process: %s (PID: %p)\n\0";
    DbgPrint(msg.as_ptr() as *const c_char, name_ptr, process_id);

    // --- Check against blacklist ---
    if !is_blacklisted(name_ptr as *const u8) {
        ObfDereferenceObject(eprocess);
        return;
    }

    // --- Blacklisted target detected ---
    let warn = b"[DASH] BLOCKED: %s — TERMINATING!\n\0";
    DbgPrint(warn.as_ptr() as *const c_char, name_ptr);

    // --- Build CLIENT_ID for ZwOpenProcess ---
    let mut client_id = CLIENT_ID {
        UniqueProcess: process_id,
        UniqueThread: core::ptr::null_mut(),
    };

    // --- Initialize OBJECT_ATTRIBUTES with OBJ_KERNEL_HANDLE ---
    let mut obj_attr: OBJECT_ATTRIBUTES = core::mem::zeroed();
    InitializeObjectAttributes(
        &mut obj_attr,
        core::ptr::null_mut(),   // ObjectName = NULL
        OBJ_KERNEL_HANDLE,       // Kernel-mode only handle
        core::ptr::null_mut(),   // RootDirectory = NULL
        core::ptr::null_mut(),   // SecurityDescriptor = NULL
    );

    // --- Open target process with PROCESS_TERMINATE (0x0001) ---
    let mut process_handle: HANDLE = core::ptr::null_mut();
    let open_status = ZwOpenProcess(
        &mut process_handle,
        0x0001, // PROCESS_TERMINATE
        &mut obj_attr,
        &mut client_id,
    );

    if open_status != STATUS_SUCCESS || process_handle.is_null() {
        let err = b"[DASH] Open failed: %s (0x%X)\n\0";
        DbgPrint(err.as_ptr() as *const c_char, name_ptr, open_status);
        ObfDereferenceObject(eprocess);
        return;
    }

    // --- Terminate the process ---
    let terminate_status = ZwTerminateProcess(process_handle, 0);

    if terminate_status == STATUS_SUCCESS {
        let ok = b"[DASH] Terminated: %s (PID: %p)\n\0";
        DbgPrint(ok.as_ptr() as *const c_char, name_ptr, process_id);
    } else {
        let err = b"[DASH] Terminate failed: %s (0x%X)\n\0";
        DbgPrint(err.as_ptr() as *const c_char, name_ptr, terminate_status);
    }

    // --- Cleanup: close handle FIRST, then deref object ---
    ZwClose(process_handle);
    ObfDereferenceObject(eprocess);
}

// ============================================================
// IOCTL Dispatch Handler
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
        // --- ADD: Add a name to the blacklist ---
        IOCTL_ADD_BLACKLIST => {
            let input_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
            let input_length = (*irp_stack).Parameters.DeviceIoControl.InputBufferLength;

            if !input_buffer.is_null() && input_length > 0 && input_length <= MAX_NAME_LENGTH as u32 {
                // Force null-terminate to prevent buffer overread
                *input_buffer.add((input_length - 1) as usize) = 0;

                if add_to_blacklist(input_buffer) {
                    let msg = b"[DASH] IOCTL: Added to blacklist\n\0";
                    DbgPrint(msg.as_ptr() as *const c_char);
                    information = 1;
                } else {
                    status = 0xC0000001; // STATUS_UNSUCCESSFUL
                }
            } else {
                status = 0xC000000D; // STATUS_INVALID_PARAMETER
            }
        }

        // --- REMOVE: Remove a name from the blacklist ---
        IOCTL_REMOVE_BLACKLIST => {
            let input_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
            let input_length = (*irp_stack).Parameters.DeviceIoControl.InputBufferLength;

            if !input_buffer.is_null() && input_length > 0 {
                *input_buffer.add((input_length - 1) as usize) = 0;

                if remove_from_blacklist(input_buffer) {
                    let msg = b"[DASH] IOCTL: Removed from blacklist\n\0";
                    DbgPrint(msg.as_ptr() as *const c_char);
                    information = 1;
                } else {
                    status = 0xC0000001;
                }
            } else {
                status = 0xC000000D;
            }
        }

        // --- CLEAR: Remove all entries ---
        IOCTL_CLEAR_BLACKLIST => {
            clear_blacklist();
            let msg = b"[DASH] IOCTL: Blacklist cleared\n\0";
            DbgPrint(msg.as_ptr() as *const c_char);
            information = 1;
        }

        // --- LIST: Retrieve all blacklisted names ---
        IOCTL_LIST_BLACKLIST => {
            let output_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
            let output_length = (*irp_stack).Parameters.DeviceIoControl.OutputBufferLength;

            if !output_buffer.is_null() && output_length > 0 {
                let mut offset = 0usize;
                for i in 0..BLACKLIST_COUNT {
                    let entry = BLACKLIST[i].as_ptr();
                    let mut len = 0usize;
                    while len < MAX_NAME_LENGTH && *entry.add(len) != 0 {
                        len += 1;
                    }
                    len += 1; // include null terminator

                    if offset + len <= output_length as usize {
                        RtlCopyMemory(
                            output_buffer.add(offset) as *mut core::ffi::c_void,
                            entry as *const core::ffi::c_void,
                            len,
                        );
                        offset += len;
                    } else {
                        break; // output buffer full
                    }
                }
                information = offset as u64;
            } else {
                status = 0xC000000D;
            }
        }

        // --- COUNT: Get number of blacklisted entries ---
        IOCTL_GET_BLACKLIST_COUNT => {
            let output_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut usize;
            let output_length = (*irp_stack).Parameters.DeviceIoControl.OutputBufferLength;

            if !output_buffer.is_null() && output_length as usize >= core::mem::size_of::<usize>() {
                *output_buffer = BLACKLIST_COUNT;
                information = core::mem::size_of::<usize>() as u64;
            } else {
                status = 0xC000000D;
            }
        }

        // --- Unknown IOCTL ---
        _ => {
            status = 0xC0000010; // STATUS_INVALID_DEVICE_REQUEST
        }
    }

    // Complete the IRP
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
    // 1. Deregister process notify callback
    PsSetCreateProcessNotifyRoutine(Some(process_callback), 1);

    // 2. Delete symbolic link
    let mut symlink_str: UNICODE_STRING = core::mem::zeroed();
    init_unicode_string(&mut symlink_str, SYMLINK_NAME_UTF16.as_ptr());
    IoDeleteSymbolicLink(&mut symlink_str);

    // 3. Delete device object
    if !(*driver_object).DeviceObject.is_null() {
        IoDeleteDevice((*driver_object).DeviceObject);
    }

    let msg = b"[DASH] Driver Unloaded\n\0";
    DbgPrint(msg.as_ptr() as *const c_char);
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
        // --- Initialize UNICODE_STRINGs ---
        let mut device_name: UNICODE_STRING = core::mem::zeroed();
        init_unicode_string(&mut device_name, DEVICE_NAME_UTF16.as_ptr());

        let mut symlink_name: UNICODE_STRING = core::mem::zeroed();
        init_unicode_string(&mut symlink_name, SYMLINK_NAME_UTF16.as_ptr());

        // --- Create Device Object ---
        let mut device_object: *mut DEVICE_OBJECT = core::ptr::null_mut();
        let status = IoCreateDevice(
            driver_object,
            0,                      // DeviceExtensionSize
            &mut device_name,       // DeviceName
            0x0000,                 // DeviceType = FILE_DEVICE_UNKNOWN
            0,                      // DeviceCharacteristics
            0,                      // Exclusive = FALSE
            &mut device_object,
        );

        if status != STATUS_SUCCESS {
            return status;
        }

        // --- Create Symbolic Link ---
        let symlink_status = IoCreateSymbolicLink(&mut symlink_name, &mut device_name);

        if symlink_status != STATUS_SUCCESS {
            IoDeleteDevice(device_object);
            return symlink_status;
        }

        // --- Register Dispatch Routines ---
        (*driver_object).MajorFunction[IRP_MJ_CREATE as usize] = Some(create_close_handler);
        (*driver_object).MajorFunction[IRP_MJ_CLOSE as usize] = Some(create_close_handler);
        (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(device_control_handler);
        (*driver_object).DriverUnload = Some(driver_unload);

        // --- Register Process Creation Callback ---
        let cb_status = PsSetCreateProcessNotifyRoutine(Some(process_callback), 0);

        if cb_status == STATUS_SUCCESS {
            let msg = b"[DASH] Driver Loaded — IOCTL + Kill Mode Active\n\0";
            DbgPrint(msg.as_ptr() as *const c_char);
        }

        cb_status
    }
}

// ============================================================
// Panic Handler (required for #![no_std])
// ============================================================
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
