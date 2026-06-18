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
}

unsafe extern "system" fn process_callback(
    _parent_id: HANDLE,
    _process_id: HANDLE,
    create: BOOLEAN,
) {
    if create != 0 {
        let msg = b"[DASH] New Process Created!\n\0";
        DbgPrint(msg.as_ptr() as *const c_char);
    }
}

// Unload routine — must remove callback before driver unloads to prevent BSOD
unsafe extern "system" fn driver_unload(_driver: *mut DRIVER_OBJECT) {
    // remove = 1 (TRUE) to deregister the callback
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
        // Register unload routine first
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
