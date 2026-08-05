//! Windows sandbox implementation using Job Objects and AppContainer restrictions.

use crate::{parse_command_str, sanitize_env, SandboxConfig};

#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    JobObjectBasicUIRestrictions, SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
    JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_HANDLES,
    JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
    JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};

/// Execute a command within a Windows Job Object sandbox container.
pub fn execute_in_windows_sandbox(command_str: &str, config: &SandboxConfig) -> Result<i32, String> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (command_str, config);
        Err("Windows sandbox can only be executed on Windows OS".to_string())
    }

    #[cfg(target_os = "windows")]
    {
        let (program, args) = parse_command_str(command_str)?;
        let sanitized_env = sanitize_env(std::env::vars(), config);

        // 1. Create Windows Job Object
        let job_handle: HANDLE = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job_handle.is_null() {
            let err = unsafe { GetLastError() };
            return Err(format!("Failed to create Windows Job Object handle (Win32 error: {})", err));
        }

        // Ensure job handle cleanup on function exit
        struct JobHandleGuard(HANDLE);
        impl Drop for JobHandleGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { CloseHandle(self.0) };
                }
            }
        }
        let _guard = JobHandleGuard(job_handle);

        // 2. Set Job Object Extended Limit Flags (Kill on job close + optional memory limit)
        let mut ext_limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        ext_limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        if let Some(mem_mb) = config.memory_limit_mb {
            let bytes = (mem_mb as usize) * 1024 * 1024;
            ext_limit.ProcessMemoryLimit = bytes;
            ext_limit.BasicLimitInformation.LimitFlags |= windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        }

        let res = unsafe {
            SetInformationJobObject(
                job_handle,
                JobObjectExtendedLimitInformation,
                &ext_limit as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if res == 0 {
            let err_code = unsafe { GetLastError() };
            return Err(format!("Failed to set Job Object limit information (Win32 error: {})", err_code));
        }


        // 3. Set Job Object UI Restrictions
        let mut ui_restrictions: JOBOBJECT_BASIC_UI_RESTRICTIONS = unsafe { std::mem::zeroed() };
        ui_restrictions.UIRestrictionsClass = JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_EXITWINDOWS;

        let res = unsafe {
            SetInformationJobObject(
                job_handle,
                JobObjectBasicUIRestrictions,
                &ui_restrictions as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        };
        if res == 0 {
            let err_code = unsafe { GetLastError() };
            return Err(format!("Failed to set Job Object UI restrictions (Win32 error: {})", err_code));
        }

        // 4. Spawn child process with sanitized environment
        let mut cmd = Command::new(&program);
        cmd.args(&args);
        cmd.env_clear();
        cmd.envs(sanitized_env);

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn child process '{}': {}", program, e))?;

        // 5. Assign child process handle to Job Object
        let child_raw_handle = child.as_raw_handle();
        let assign_res = unsafe { AssignProcessToJobObject(job_handle, child_raw_handle as HANDLE) };
        if assign_res == 0 {
            let err_code = unsafe { GetLastError() };
            let _ = child.kill();
            return Err(format!("Failed to assign child process to Windows Job Object (Win32 error: {})", err_code));
        }

        println!("[SANDBOX] Launched process in Windows Job Object container (PID: {})", child.id());

        // 6. Wait for child process exit
        let exit_status = child
            .wait()
            .map_err(|e| format!("Failed waiting for sandboxed process execution: {}", e))?;

        Ok(exit_status.code().unwrap_or(-1))
    }
}



