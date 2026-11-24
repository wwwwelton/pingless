//! Native Windows Filtering Platform (WFP) management for Pingless.
//!
//! Uses the Base Filtering Engine (BFE) in user-mode via `FwpmEngineOpen0` with a
//! dynamic session (`FWPM_SESSION_FLAG_DYNAMIC`), ensuring all filters and sublayers
//! are automatically purged by the Windows kernel if Pingless exits or stops.
//!
//! Provides kernel-level enforcement for:
//! 1. Resolving applications into native WFP App IDs via `FwpmGetAppIdFromFileName0`.
//! 2. Kill-Switch: Hardware/kernel-level blocking at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
//!    and `FWPM_LAYER_ALE_AUTH_CONNECT_V6` for chosen programs when the tunnel is down.
//! 3. Process protection: Prevents protected programs from ever establishing direct
//!    outbound connections if not tunneled.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use parking_lot::Mutex;
use tracing::{debug, warn};

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_CONDITION_ALE_APP_ID, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_BYTE_BLOB,
    FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FwpmEngineClose0, FwpmEngineOpen0,
    FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmSubLayerAdd0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::core::GUID;

// Pingless WFP Sublayer GUID: {5b7f1b2c-9a4d-4e8f-b631-7e8c4f2a9101}
const PINGLESS_SUBLAYER_GUID: GUID = GUID::from_u128(0x5b7f1b2c_9a4d_4e8f_b631_7e8c4f2a9101);
// High weight so our ALE block rules take precedence in this sublayer
const SUBLAYER_WEIGHT: u16 = 0x8000;

fn to_wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// A wrapper around an allocated WFP `FWP_BYTE_BLOB` containing an AppId.
pub struct WfpAppId {
    blob: *mut FWP_BYTE_BLOB,
    pub path: PathBuf,
}

// SAFETY: WFP AppId blobs are immutable and can be safely sent across threads.
unsafe impl Send for WfpAppId {}
unsafe impl Sync for WfpAppId {}

impl WfpAppId {
    /// Resolves an executable path into a kernel-compatible WFP AppId blob.
    pub fn from_file_path(path: &Path) -> Result<Self> {
        let wide = to_wide(path.as_os_str());
        let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let res = unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) };
        if res != ERROR_SUCCESS || blob.is_null() {
            anyhow::bail!("FwpmGetAppIdFromFileName0 failed with error code 0x{res:X} for {path:?}");
        }
        Ok(Self {
            blob,
            path: path.to_path_buf(),
        })
    }

    pub fn as_ptr(&self) -> *mut FWP_BYTE_BLOB {
        self.blob
    }
}

impl Drop for WfpAppId {
    fn drop(&mut self) {
        if !self.blob.is_null() {
            unsafe {
                FwpmFreeMemory0(self.blob.cast());
            }
            self.blob = std::ptr::null_mut();
        }
    }
}

/// Native Windows Filtering Platform engine session.
pub struct WfpEngine {
    handle: HANDLE,
    active_filters: Mutex<HashMap<PathBuf, Vec<u64>>>,
    registered_sublayer: AtomicBool,
}

// SAFETY: WFP engine handles can be shared/used across threads safely.
unsafe impl Send for WfpEngine {}
unsafe impl Sync for WfpEngine {}

impl WfpEngine {
    /// Opens a dynamic WFP BFE session.
    pub fn open() -> Result<Self> {
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let mut name = to_wide(OsStr::new("Pingless WFP Dynamic Session"));
        session.displayData.name = name.as_mut_ptr();

        let mut handle: HANDLE = std::ptr::null_mut();
        let res = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_DEFAULT as u32,
                std::ptr::null(),
                &session,
                &mut handle,
            )
        };

        if res != ERROR_SUCCESS || handle.is_null() {
            anyhow::bail!("FwpmEngineOpen0 failed with 0x{res:X}; requires Administrator rights");
        }

        let engine = Self {
            handle,
            active_filters: Mutex::new(HashMap::new()),
            registered_sublayer: AtomicBool::new(false),
        };

        engine.init_sublayer()?;
        Ok(engine)
    }

    fn init_sublayer(&self) -> Result<()> {
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.subLayerKey = PINGLESS_SUBLAYER_GUID;
        let mut name = to_wide(OsStr::new("Pingless ALE Sublayer"));
        sublayer.displayData.name = name.as_mut_ptr();
        sublayer.weight = SUBLAYER_WEIGHT;

        let res = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, std::ptr::null_mut()) };
        // FWP_E_ALREADY_EXISTS = 0x80320009
        if res == ERROR_SUCCESS || res == 0x80320009 {
            self.registered_sublayer.store(true, Ordering::SeqCst);
            debug!("WFP sublayer registered successfully");
            Ok(())
        } else {
            anyhow::bail!("FwpmSubLayerAdd0 failed with 0x{res:X}");
        }
    }

    /// Adds a kernel-level ALE connect block filter for the specified App ID on IPv4 and IPv6.
    pub fn block_app(&self, app_id: &WfpAppId) -> Result<Vec<u64>> {
        let mut filter_ids = Vec::new();
        let layers = [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6];

        let mut name = to_wide(OsStr::new("Pingless ALE App Kill-Switch"));

        for layer in layers {
            let mut condition: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
            condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
            condition.matchType = FWP_MATCH_EQUAL;
            condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
            condition.conditionValue.Anonymous.byteBlob = app_id.as_ptr();

            let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
            filter.layerKey = layer;
            filter.subLayerKey = PINGLESS_SUBLAYER_GUID;
            filter.action.r#type = FWP_ACTION_BLOCK;
            filter.displayData.name = name.as_mut_ptr();
            filter.numFilterConditions = 1;
            filter.filterCondition = &mut condition;
            filter.weight.r#type = windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT8;
            filter.weight.Anonymous.uint8 = 15;

            let mut filter_id = 0u64;
            let res = unsafe {
                FwpmFilterAdd0(
                    self.handle,
                    &filter,
                    std::ptr::null_mut(),
                    &mut filter_id,
                )
            };

            if res != ERROR_SUCCESS {
                warn!(
                    "FwpmFilterAdd0 failed with 0x{res:X} for app {:?}",
                    app_id.path
                );
            } else {
                debug!("WFP added block filter {filter_id} for {:?}", app_id.path);
                filter_ids.push(filter_id);
            }
        }

        self.active_filters
            .lock()
            .entry(app_id.path.clone())
            .or_default()
            .extend(filter_ids.iter().copied());
        Ok(filter_ids)
    }

    /// Unblocks a specific application by removing its WFP filters.
    pub fn unblock_app(&self, path: &Path) {
        if let Some(ids) = self.active_filters.lock().remove(path) {
            for id in ids {
                unsafe {
                    let _ = FwpmFilterDeleteById0(self.handle, id);
                }
            }
        }
    }

    /// Clears all currently active filters managed by this instance.
    pub fn clear_filters(&self) {
        let mut filters = self.active_filters.lock();
        for (_, ids) in filters.drain() {
            for id in ids {
                unsafe {
                    let _ = FwpmFilterDeleteById0(self.handle, id);
                }
            }
        }
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        self.clear_filters();
        if !self.handle.is_null() {
            unsafe {
                FwpmEngineClose0(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}
