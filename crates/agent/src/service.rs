//! Windows Service lifecycle management.
//!
//! Uses the `windows-service` crate on Windows.
//! On other platforms this module is a no-op stub.

#[cfg(any(windows, test))]
use std::ffi::OsString;
#[cfg(any(windows, test))]
use std::path::Path;

#[cfg(any(windows, test))]
fn build_service_launch_arguments(config_path: &Path) -> Vec<OsString> {
    vec![
        OsString::from("--config"),
        config_path.as_os_str().to_os_string(),
        OsString::from("service"),
    ]
}

#[cfg(any(windows, test))]
fn build_child_launch_arguments(config_path: &Path) -> Vec<OsString> {
    vec![
        OsString::from("--config"),
        config_path.as_os_str().to_os_string(),
        OsString::from("run"),
    ]
}

#[cfg(windows)]
pub mod imp {
    use anyhow::{Context, Result};
    use std::ffi::OsString;
    use std::path::Path;
    use std::process::Command;
    use std::sync::{mpsc, OnceLock};
    use std::thread;
    use std::time::Duration;
    use tracing::{error, info, warn};
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    const SERVICE_NAME: &str = "TrueIDAgent";
    const DISPLAY_NAME: &str = "TrueID Identity Agent";
    static CONFIG_PATH: OnceLock<OsString> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Installs the agent as a Windows Service.
    ///
    /// Parameters: `config_path` - path to config.toml.
    /// Returns: `Ok(())` on success or an error.
    pub fn install(config_path: &Path) -> Result<()> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
        let exe_path = std::env::current_exe()?;
        let service_info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe_path,
            launch_arguments: super::build_service_launch_arguments(config_path),
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
        info!("Service '{}' installed", SERVICE_NAME);
        Ok(())
    }

    /// Uninstalls the Windows Service.
    ///
    /// Parameters: none.
    /// Returns: `Ok(())` on success or an error.
    pub fn uninstall() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
        service.delete()?;
        info!("Service '{}' uninstalled", SERVICE_NAME);
        Ok(())
    }

    /// Runs the service wrapper under Service Control Manager.
    ///
    /// Parameters: `config_path` - path to config.toml.
    /// Returns: `Ok(())` when the service dispatcher exits cleanly.
    pub fn run(config_path: &Path) -> Result<()> {
        let _ = CONFIG_PATH.set(config_path.as_os_str().to_os_string());
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        Ok(())
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(err) = run_service_wrapper() {
            error!(error = %err, "Windows service wrapper failed");
        }
    }

    fn set_status(
        status_handle: &service_control_handler::ServiceStatusHandle,
        current_state: ServiceState,
        exit_code: ServiceExitCode,
        wait_hint: Duration,
    ) -> windows_service::Result<()> {
        info!(
            state = ?current_state,
            exit_code = ?exit_code,
            wait_hint_secs = wait_hint.as_secs(),
            "Updating Windows service status"
        );
        let controls_accepted = match current_state {
            ServiceState::Running => ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            _ => ServiceControlAccept::empty(),
        };
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        })
    }

    fn run_service_wrapper() -> Result<()> {
        let config_path = CONFIG_PATH
            .get()
            .cloned()
            .context("service config path not initialized")?;

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let status_handle = service_control_handler::register(
            SERVICE_NAME,
            move |control_event| match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    info!(event = ?control_event, "Received Windows service control event");
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )?;

        set_status(
            &status_handle,
            ServiceState::StartPending,
            ServiceExitCode::Win32(0),
            Duration::from_secs(10),
        )?;

        let exe_path = std::env::current_exe()?;
        let child_args = super::build_child_launch_arguments(Path::new(&config_path));
        let mut child = Command::new(&exe_path)
            .args(&child_args)
            .spawn()
            .with_context(|| {
                format!(
                    "failed to spawn agent child '{}' with config '{}'",
                    exe_path.display(),
                    Path::new(&config_path).display()
                )
            })?;

        info!(
            executable = %exe_path.display(),
            config = %Path::new(&config_path).display(),
            args = ?child_args,
            pid = child.id(),
            "Windows service wrapper started agent child"
        );

        set_status(
            &status_handle,
            ServiceState::Running,
            ServiceExitCode::Win32(0),
            Duration::default(),
        )?;

        let mut service_exit_code = ServiceExitCode::Win32(0);

        loop {
            if shutdown_rx.try_recv().is_ok() {
                info!("Stopping agent child on service shutdown");
                if let Err(err) = child.kill() {
                    warn!(error = %err, "Failed to terminate agent child");
                }
                match child.wait() {
                    Ok(status) => {
                        info!(status = ?status.code(), "Agent child terminated after service stop");
                    }
                    Err(err) => warn!(error = %err, "Failed waiting for agent child after stop"),
                }
                break;
            }

            if let Some(status) = child.try_wait()? {
                if status.success() {
                    info!(status = ?status.code(), "Agent child exited cleanly");
                } else {
                    service_exit_code = ServiceExitCode::ServiceSpecific(1);
                    warn!(status = ?status.code(), "Agent child exited unexpectedly");
                }
                break;
            }

            thread::sleep(Duration::from_millis(500));
        }

        set_status(
            &status_handle,
            ServiceState::StopPending,
            service_exit_code,
            Duration::from_secs(5),
        )?;
        set_status(
            &status_handle,
            ServiceState::Stopped,
            service_exit_code,
            Duration::default(),
        )?;
        Ok(())
    }
}

#[cfg(not(windows))]
pub mod imp {
    use anyhow::{bail, Result};
    use std::path::Path;

    pub fn install(_config_path: &Path) -> Result<()> {
        bail!("Windows Service installation not available on this platform");
    }

    pub fn uninstall() -> Result<()> {
        bail!("Windows Service uninstallation not available on this platform");
    }

    pub fn run(_config_path: &Path) -> Result<()> {
        bail!("Windows Service runtime not available on this platform");
    }
}

pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_service_launch_arguments_with_config_and_service_subcommand() {
        let args = build_service_launch_arguments(Path::new("C:\\TrueID\\config.toml"));
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            rendered,
            vec![
                "--config".to_string(),
                "C:\\TrueID\\config.toml".to_string(),
                "service".to_string(),
            ]
        );
    }

    #[test]
    fn builds_child_launch_arguments_with_config_and_run_subcommand() {
        let args = build_child_launch_arguments(Path::new("C:\\TrueID\\config.toml"));
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            rendered,
            vec![
                "--config".to_string(),
                "C:\\TrueID\\config.toml".to_string(),
                "run".to_string(),
            ]
        );
    }
}
