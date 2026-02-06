//! Windows Service lifecycle management.
//!
//! Uses the `windows-service` crate on Windows.
//! On other platforms this module is a no-op stub.

#[cfg(windows)]
pub mod imp {
    use std::ffi::OsString;
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};
    use anyhow::Result;
    use tracing::info;

    const SERVICE_NAME: &str = "TrueIDAgent";
    const DISPLAY_NAME: &str = "TrueID Identity Agent";

    /// Installs the agent as a Windows Service.
    ///
    /// Parameters: none.
    /// Returns: `Ok(())` on success or an error.
    pub fn install() -> Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let exe_path = std::env::current_exe()?;
        let service_info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe_path,
            launch_arguments: vec![OsString::from("service")],
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
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT,
        )?;
        let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
        service.delete()?;
        info!("Service '{}' uninstalled", SERVICE_NAME);
        Ok(())
    }
}

#[cfg(not(windows))]
pub mod imp {
    use anyhow::{bail, Result};

    pub fn install() -> Result<()> {
        bail!("Windows Service installation not available on this platform");
    }

    pub fn uninstall() -> Result<()> {
        bail!("Windows Service uninstallation not available on this platform");
    }
}

pub use imp::*;
