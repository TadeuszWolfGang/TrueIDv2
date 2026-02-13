//! Windows Event Log subscription via EvtSubscribe.
//!
//! This module only compiles on Windows. On other platforms it provides
//! a no-op stub so the rest of the agent can be built and tested.

#[cfg(windows)]
mod imp {
    use anyhow::{anyhow, Result};
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use tokio::sync::mpsc;
    use tracing::{info, warn};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{BOOLEAN, HANDLE, WIN32_ERROR};
    use windows::Win32::System::EventLog::*;

    /// Starts a real-time subscription on the given channel with an XPath query.
    /// Parsed XML strings are sent through `tx`.
    ///
    /// Parameters: `channel` - event log channel name, `query` - XPath filter,
    /// `tx` - channel sender for raw XML strings.
    /// Returns: subscription handle or an error.
    pub fn subscribe(
        channel: &str,
        query: &str,
        tx: mpsc::UnboundedSender<String>,
    ) -> Result<EvtHandle> {
        let channel_wide: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();
        let query_wide: Vec<u16> = query.encode_utf16().chain(std::iter::once(0)).collect();

        // Box the sender so we can pass it as *mut c_void context.
        let context = Box::into_raw(Box::new(tx));

        let handle = unsafe {
            EvtSubscribe(
                None,
                None,
                PCWSTR(channel_wide.as_ptr()),
                PCWSTR(query_wide.as_ptr()),
                None,
                Some(context as *const core::ffi::c_void),
                Some(subscription_callback),
                EvtSubscribeToFutureEvents.0 as u32,
            )
        }
        .map_err(|e| anyhow!("EvtSubscribe failed: {}", e))?;

        info!(channel, "Subscribed to event log");
        Ok(handle)
    }

    /// System callback invoked by Windows for each matching event.
    unsafe extern "system" fn subscription_callback(
        action: u32,
        context: *const core::ffi::c_void,
        event: isize,
    ) -> u32 {
        if action != EvtSubscribeActionDeliver.0 as u32 {
            return 0;
        }
        let tx = &*(context as *const mpsc::UnboundedSender<String>);
        match render_event_xml(EVT_HANDLE(event)) {
            Ok(xml) => {
                let _ = tx.send(xml);
            }
            Err(err) => {
                warn!(error = %err, "EvtRender failed");
            }
        }
        0
    }

    /// Renders an event handle to an XML string via EvtRender.
    ///
    /// Parameters: `event` - event handle from callback.
    /// Returns: XML string or an error.
    fn render_event_xml(event: EVT_HANDLE) -> Result<String> {
        let mut buf_size: u32 = 0;
        let mut prop_count: u32 = 0;

        // First call to get required buffer size.
        let _ = unsafe {
            EvtRender(
                None,
                event,
                EvtRenderEventXml.0 as u32,
                0,
                None,
                &mut buf_size,
                &mut prop_count,
            )
        };

        let mut buffer = vec![0u16; (buf_size as usize) / 2 + 1];
        let ok = unsafe {
            EvtRender(
                None,
                event,
                EvtRenderEventXml.0 as u32,
                buf_size,
                Some(buffer.as_mut_ptr() as *mut _),
                &mut buf_size,
                &mut prop_count,
            )
        };
        if !ok.as_bool() {
            return Err(anyhow!("EvtRender failed"));
        }

        let xml = OsString::from_wide(&buffer)
            .to_string_lossy()
            .trim_end_matches('\0')
            .to_string();
        Ok(xml)
    }
}

#[cfg(not(windows))]
mod imp {
    use anyhow::Result;
    use tokio::sync::mpsc;
    use tracing::warn;

    /// Stub for non-Windows platforms. Returns an error.
    pub fn subscribe(
        channel: &str,
        _query: &str,
        _tx: mpsc::UnboundedSender<String>,
    ) -> Result<()> {
        warn!(channel, "EvtSubscribe not available on this platform");
        Ok(())
    }
}

#[allow(unused_imports)]
pub use imp::subscribe;
