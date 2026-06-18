#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ffi::c_char;
use wdk_sys::{HANDLE, BOOLEAN, NTSTATUS, STATUS_SUCCESS, DRIVER_OBJECT};

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
}

unsafe extern "system" fn process_callback(
    _parent_id: HANDLE,
    process_id: HANDLE,
    create: BOOLEAN,
) {
    if create != 0 {
        let mut eprocess: *mut core::ffi::c_void = core::ptr::null_mut();

        let lookup_status = PsLookupProcessByProcessId(process_id, &mut eprocess);

        if lookup_status == STATUS_SUCCESS && !eprocess.is_null() {
            let name_ptr = PsGetProcessImageFileName(eprocess);
            
            if !name_ptr.is_null() {
                let msg = b"[DASH] New Process: %s (PID: %p)\n\0";
                DbgPrint(msg.as_ptr() as *const c_char, name_ptr, process_id);
            }

            ObfDereferenceObject(eprocess);
        } else {
            let msg = b"[DASH] New Process Created! (PID: %p)\n\0";
            DbgPrint(msg.as_ptr() as *const c_char, process_id);
        }
    }
}

unsafe extern "system" fn driver_unload(_driver: *mut DRIVER_OBJECT) {
    PsSetCreateProcessNotifyRoutine(Some(process_callback), 1);

    let msg = b"[DASH] Driver Unloaded, Callback Removed!\n\0";
    DbgPrint(msg.as_ptr() as *const c_char);
}

#[no_mangle]
pub extern "system" fn DriverEntry(
    driver: *mut DRIVER_OBJECT,
    _path: *mut core::ffi::c_void,
) -> NTSTATUS {
    unsafe {
        (*driver).DriverUnload = Some(driver_unload);

        let status = PsSetCreateProcessNotifyRoutine(Some(process_callback), 0);

        if status == STATUS_SUCCESS {
            let msg = b"[DASH] Driver Loaded Successfully!\n\0";
            DbgPrint(msg.as_ptr() as *const c_char);
        }

        status
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
