//! Debug sequences for PSOC Edge devices.
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use std::time::Duration;

use bitfield::bitfield;
use probe_rs_target::{Chip, CoreType};

use crate::{
    architecture::arm::{
        ApV2Address, ArmDebugInterface, ArmError, DebugPortWire, FullyQualifiedApAddress, Pins,
        armv8m::Dhcsr,
        core::cortex_m,
        dp::{Abort, DpAddress, DpRegister},
        memory::ArmMemoryInterface,
        sequences::{
            ArmDebugSequence, DefaultArmSequence, cortex_m_wait_for_reset,
        },
    },
    config::CoreExt,
    core::memory_mapped_registers::MemoryMappedRegister,
    probe::BitSequence,
};

bitfield! {
    /// CM55 control register.
    #[derive(Clone, Copy)]
    struct MxCm55Ctl(u32);
    impl Debug;

    /// Clock-gates the CM55, preventing it from starting until the CM33
    /// has set up the system and initialized the CM55's vector table.
    pub cm55_wait, set_cm55_wait: 4;
}
impl MxCm55Ctl {
    /// Secure alias address (`APPSS->APPCPUSS->MXCM55->CM55_CTL`)
    /// The CM33 AP accesses this register with a secure transaction by default,
    /// so the non-secure alias (`0x44160000`) could return a stale/incorrect value.
    const ADDRESS: u64 = 0x54160000;
}

bitfield! {
    /// CM55 local command register (APPSS->APPCPUSS->MXCM55->CM55_CMD).
    ///
    /// Writing the reset value triggers a local CM55 reset without affecting CM33
    /// or the rest of the system. The 0xA5FA key must be included in the write.
    #[derive(Clone, Copy)]
    struct MxCm55Cmd(u32);
    impl Debug;
}
impl MxCm55Cmd {
    /// Secure alias address for the CM55_CMD register.
    const ADDRESS: u64 = 0x54160004;
    /// Write this value to trigger a local CM55 reset (key=0xA5FA, RESET=1).
    const RESET: u32 = 0x05FA_0001;
}

bitfield! {
    /// Application CPU subsystem access port control register.
    #[derive(Clone, Copy)]
    struct AppCpussApCtl(u32);
    impl Debug;

    /// Enables the CM55 debug access port.
    pub cm55_enable, set_cm55_enable: 0;

    /// Enables invasive debug access to the CM55 (halting, stepping, breakpoints).
    pub cm55_dbg_enable, set_cm55_dbg_enable: 4;

    /// Enables non-invasive debug access to the CM55 (tracing and memory access).
    pub cm55_nid_enable, set_cm55_nid_enable: 5;
}
impl AppCpussApCtl {
    const ADDRESS: u64 = 0x441C1000;
}

bitfield! {
    /// CM55 power domain sense register (PWRMODE->PD6->PD_SENSE).
    ///
    /// Controls whether the CM55 power domain is turned on. After a reset the CM55
    /// domain is off; the debugger must enable it before accessing any CM55 registers.
    #[derive(Clone, Copy)]
    struct PwrmodePd6PdSense(u32);
    impl Debug;

    /// Powers on the CM55 core power domain.
    pub pd_on_cm55, set_pd_on_cm55: 4;
}
impl PwrmodePd6PdSense {
    const ADDRESS: u64 = 0x42410060;
}

/// Safe RAM address for the CM55 pre-initialization endless-loop instruction.
///
/// Located in the CM55's low internal memory (ITCM/DTCM window), which is one of
/// the few regions the CM55 AP is allowed to access immediately after reset.
const CM55_ENDLESS_LOOP_ADDR: u64 = 0x0003_FF00;

/// `b .` (branch-to-self, `0xE7FE`) packed into a 32-bit word.
const CM55_ENDLESS_LOOP_INSTR: u32 = 0xE7FE_E7FE;

/// Safe initial stack pointer value used when pre-initializing the CM55.
const CM55_SAFE_SP: u32 = 0x0000_0100;

/// DCRSR register selectors (ARMv8-M Architecture Reference Manual, `DCRSR.REGSEL`),
/// passed to `cortex_m::{read,write}_core_reg` as [`crate::RegisterId`]s.
const REGSEL_SP: u16 = 13;
const REGSEL_LR: u16 = 14;
const REGSEL_PC: u16 = 15;
const REGSEL_MSP: u16 = 17;

/// ADIv6 base address of the system (SYS) access port (`__apid=0`).
///
/// The bus-access portal used to acquire the device before the CM33/CM55 APs are open,
/// so it is addressed directly
const SYS_AP_BASE: u64 = 0xF000_0000;

// ADIv6 memory-AP register offsets (same layout for all APv2 memory APs).
const AP_CSW: u64 = 0xD00;
const AP_TAR: u64 = 0xD04;
const AP_DRW: u64 = 0xD0C;

/// SYS AP CSW for 32-bit secure word accesses with single auto-increment
/// (DbgSwEnable | MasterType | Cacheable | Privileged | Data | Size=Word).
const SYS_AP_CSW_WORD: u32 = 0xAB00_0002;

/// Test Mode Control Register (`SRSS->TST_MODE`).
const TST_MODE_ADDRESS: u32 = 0x5240_0400;

/// `TST_MODE.TEST_MODE` (bit 31): request the boot ROM to stay in its Listen Window.
const TEST_MODE_MSK: u32 = 0x8000_0000;

/// Extended boot status word, mirrored at the base of secure SRAM (`SRAM_S_BASE`).
const EXT_BOOT_STATUS_ADDRESS: u32 = 0x3400_0000;

/// Value of [`EXT_BOOT_STATUS_ADDRESS`] once the boot ROM has reached its idle
/// Listen Window (i.e. the device is acquired in Test Mode).
const EXT_BOOT_STATUS_IDLE: u32 = 0xAA00_B5F8;

/// Maximum time to wait for the boot ROM to reach its idle Listen Window after
/// `TST_MODE.TEST_MODE` was requested. A device that was acquired reports idle within
/// a few milliseconds; a longer wait only delays the next acquisition attempt.
const TIMEOUT_BOOT_COMPLETE_MS: u64 = 1000;

/// Settle time after a reset before further debug access (DFP `__Reset_Finish_Delay`).
const RESET_FINISH_DELAY_MS: u64 = 50;

/// Maximum time to wait for the debug port to come back after a system reset.
const TIMEOUT_RESET_RECOVER_MS: u64 = 3000;

/// Width of the XRES pulse used to acquire the device.
///
/// The PSOC Edge SW-DP is held in reset while XRES is asserted, so the pin is only
/// pulsed and the debug port is connected right afterwards, inside the boot ROM
/// Listen Window.
const XRES_PULSE_MS: u64 = 5;

/// Number of XRES pulse + Test Mode acquisition attempts made during an under-reset
/// attach. Firmware can close the Listen Window before the acquisition lands, and each
/// pulse restarts the boot ROM to open a new one.
const ACQUIRE_ATTEMPTS: usize = 4;

/// PSOC Edge debug sequences.
#[derive(Debug)]
pub struct PsocEdge {
    // The access port for the system CPU (CM33).
    cm33_ap: FullyQualifiedApAddress,

    // The access port for the application CPU (CM55).
    cm55_ap: FullyQualifiedApAddress,

    // Whether the CM55 debug interface was successfully enabled. Used to decide
    // whether to re-enable it after a system reset.
    cm55_enabled: AtomicBool,

    // Saved DEMCR values for exact reset-catch restore semantics per core.
    cm33_demcr_saved: AtomicU32,
    cm55_demcr_saved: AtomicU32,
    cm33_demcr_valid: AtomicBool,
    cm55_demcr_valid: AtomicBool,

    // Set when attaching under reset (reset_hardware_assert ran). Test Mode
    // acquisition only makes sense under reset (to catch the boot ROM Listen
    // Window); on a free-running device the SYS AP is locked and writing TST_MODE
    // wedges the part, so we skip it unless this is set.
    under_reset: AtomicBool,
}

impl PsocEdge {
    /// Creates debug sequences for a PSOC Edge chip.
    pub fn create(chip: &Chip) -> Arc<Self> {
        let [cm33, cm55] = &*chip.cores else {
            unreachable!("PSOC Edge E84 devices have two cores");
        };
        let [cm33_ap, cm55_ap] = [cm33, cm55].map(|core| {
            core.memory_ap()
                .expect("PSOC Edge core must have a memory AP")
        });

        Arc::new(PsocEdge {
            cm33_ap,
            cm55_ap,
            cm55_enabled: AtomicBool::new(false),
            cm33_demcr_saved: AtomicU32::new(0),
            cm55_demcr_saved: AtomicU32::new(0),
            cm33_demcr_valid: AtomicBool::new(false),
            cm55_demcr_valid: AtomicBool::new(false),
            under_reset: AtomicBool::new(false),
        })
    }
}

impl ArmDebugSequence for PsocEdge {
    fn debug_port_setup(
        &self,
        interface: &mut dyn DebugPortWire,
        dp: DpAddress,
    ) -> Result<(), ArmError> {
        // The PSOC Edge SW-DP is an SWD-only DPv3 that powers up in the dormant
        // state. It does not react to the legacy JTAG-to-SWD switch sequence the
        // default setup sends first, and the default's dormant fallback only runs
        // after two one-second connect timeouts, which is longer than the attach
        // budget of some frontends. Wake the DP with the dormant-to-SWD selection
        // sequence directly, like the vendor OpenOCD does.
        let mut result = Ok(());
        for attempt in 1..=3 {
            // Dormant-to-SWD selection (ARM ADI v6 §B5.3):
            // line reset, JTAG-to-dormant, 8 high cycles, 128-bit selection
            // alert, then 4 low cycles plus the SWD activation code.
            interface.swj_sequence(&BitSequence::from_u64(51, 0x0007_FFFF_FFFF_FFFF))?;
            interface.swj_sequence(&BitSequence::from_u64(31, 0x33BB_BBBA))?;
            interface.swj_sequence(&BitSequence::from_u64(8, 0xFF))?;
            interface.swj_sequence(&BitSequence::from_u64(64, 0x8685_2D95_6209_F392))?;
            interface.swj_sequence(&BitSequence::from_u64(64, 0x19BC_0EA2_E3DD_AFE9))?;
            interface.swj_sequence(&BitSequence::from_u64(12, 0x1A0))?;

            // debug_port_connect performs the line reset and DPIDR read that
            // complete the activation.
            result = self.debug_port_connect(interface, dp);
            match &result {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::debug!("PSoC Edge: dormant connect attempt {attempt} failed: {e}")
                }
            }
        }
        result
    }

    fn reset_hardware_assert(&self, interface: &mut dyn DebugPortWire) -> Result<(), ArmError> {
        // Record that this attach asserted reset. `debug_device_unlock` uses this to
        // decide whether Test Mode acquisition is safe: it only is under reset, where
        // the boot ROM is still in its Listen Window. This hook only runs on the
        // under-reset attach path, so a normal (running-target) attach leaves the flag
        // clear and skips the destructive SYS AP TST_MODE write.
        self.under_reset.store(true, Ordering::Relaxed);

        // PSOC Edge holds its SW-DP in reset for as long as XRES is asserted: no line
        // reset is answered and DPIDR never becomes readable, so the generic
        // "assert nRESET and keep it asserted while connecting" flow can never attach.
        // The device is instead acquired the way the vendor tools do it: pulse XRES and
        // connect immediately afterwards, while the boot ROM is still in its Listen
        // Window, so that `debug_device_unlock` can set `TST_MODE.TEST_MODE` before
        // user firmware is given control. XRES is therefore released here and not in
        // `reset_hardware_deassert`.
        let mut n_reset = Pins(0);
        n_reset.set_nreset(true);

        interface.swj_pins(Pins(0), n_reset, Duration::ZERO)?;
        std::thread::sleep(Duration::from_millis(XRES_PULSE_MS));
        interface.swj_pins(n_reset, n_reset, Duration::ZERO)?;

        Ok(())
    }

    fn on_attach(
        &self,
        interface: &mut dyn ArmDebugInterface,
        core_ap: &FullyQualifiedApAddress,
        core_type: CoreType,
    ) -> Result<(), ArmError> {
        if core_ap == &self.cm55_ap {
            let dp = self.cm33_ap.dp();

            // If the CM55 has already been enabled, do NOT re-run the full power-up /
            // CPU_WAIT-release sequence on every attach. `session.core(1)` calls this
            // on each access (connect, `info threads`, register reads), and re-driving
            // that sequence re-writes DHCSR and can resume a core the debugger had
            // already halted, which then makes register reads fail. Instead just
            // confirm the debug interface is still live and (re-)halt the core.
            if self.cm55_enabled.load(Ordering::Relaxed) {
                match self.ensure_cm55_halted(interface) {
                    Ok(()) => {
                        return DefaultArmSequence(()).on_attach(interface, core_ap, core_type);
                    }
                    Err(e) => {
                        // Interface no longer responding — fall back to a full re-enable.
                        tracing::debug!("CM55 re-attach halt check failed: {:?}", e);
                        Self::recover_dp_or_reconnect(interface, dp);
                        self.cm55_enabled.store(false, Ordering::Relaxed);
                    }
                }
            }

            // Enable the CM55 via the CM33 AP. If this fails with a hardware error
            // (e.g. AHB stall accessing an unclocked register), clear DP sticky error
            // flags so subsequent CM33 operations are not affected.
            match self.try_enable_cm55(interface) {
                Ok(()) => {}
                Err(ArmError::CoreDisabled) => {
                    return Err(ArmError::CoreDisabled);
                }
                Err(e) => {
                    // Non-CoreDisabled failure while enabling the CM55 (e.g. firmware has
                    // locked the secure APPSS space, or the CM55 power domain is unclocked
                    // while the device sleeps): the faulted access can leave the DP so
                    // wedged that not even an ABORT write is acknowledged. Reconnect the
                    // debug port and report the core as disabled so the caller/GDB stub
                    // can treat it as not-yet-debuggable.
                    tracing::debug!("CM55 enable failed during attach: {:?}", e);
                    Self::recover_dp_or_reconnect(interface, dp);
                    return Err(ArmError::CoreDisabled);
                }
            }
        }

        DefaultArmSequence(()).on_attach(interface, core_ap, core_type)
    }

    fn debug_device_unlock(
        &self,
        interface: &mut dyn ArmDebugInterface,
        default_ap: &FullyQualifiedApAddress,
        _permissions: &crate::Permissions,
    ) -> Result<(), ArmError> {
        // Test Mode acquisition writes the boot ROM TST_MODE register through the
        // SYS AP. That only helps when attaching under reset, where the boot ROM is
        // still in its Listen Window. On a free-running device the SYS AP is locked:
        // the access faults and, worse, can wedge the part so hard that it needs a
        // power cycle. Only attempt it when we asserted reset for this attach.
        if !self.under_reset.load(Ordering::Relaxed) {
            tracing::debug!(
                "PSoC Edge: not attaching under reset, skipping Test Mode acquisition"
            );
            return Ok(());
        }
        // Firmware that locks the secure SYS AP or drops the debug link can close the
        // Listen Window before the acquisition lands, so the XRES pulse and the
        // TST_MODE write are retried as a unit: each pulse restarts the boot ROM and
        // opens a fresh window. A faulting SYS AP access also leaves the DP wedged, so
        // the port is reconnected between attempts.
        let dp = default_ap.dp();
        let sys_ap = Self::sys_ap(dp);

        for attempt in 1..=ACQUIRE_ATTEMPTS {
            match self.acquire_test_mode(interface, &sys_ap) {
                Ok(true) => {
                    // XRES was already released by `reset_hardware_assert`, so the reset
                    // catch the caller arms afterwards can never fire: the core is running
                    // the boot ROM Listen Window by now. Halt it here instead, which is the
                    // state the under-reset attach path expects once reset is deasserted.
                    if let Err(e) = self.halt_cm33(interface) {
                        tracing::debug!(
                            "PSoC Edge: could not halt the CM33 after acquire: {:?}",
                            e
                        );
                    }
                    return Ok(());
                }
                Ok(false) => {
                    tracing::debug!(
                        "PSoC Edge: Listen Window missed on acquire attempt {attempt}"
                    );
                }
                Err(e) => {
                    tracing::debug!("PSoC Edge: acquire attempt {attempt} faulted: {:?}", e);
                }
            }

            if attempt == ACQUIRE_ATTEMPTS {
                break;
            }

            // Restart the boot ROM for another Listen Window, then bring the debug port
            // back up: XRES holds the SW-DP in reset, and a faulted SYS AP access can
            // wedge it hard enough that not even an ABORT write is acknowledged.
            if let Err(e) = Self::pulse_xres(interface) {
                tracing::debug!("PSoC Edge: could not pulse XRES for re-acquire: {:?}", e);
                break;
            }
            if let Err(e) = interface.reinitialize() {
                tracing::debug!("PSoC Edge: DP reinitialize before re-acquire failed: {:?}", e);
                Self::recover_dp(interface, dp);
            }
        }

        // Acquisition is best-effort: a device that keeps its firmware running simply
        // stays un-acquired, and attach continues with whatever access is available.
        tracing::debug!("PSoC Edge: continuing without Test Mode acquisition");
        Ok(())
    }

    fn reset_system(
        &self,
        interface: &mut dyn ArmMemoryInterface,
        _core_type: CoreType,
        _debug_base: Option<u64>,
    ) -> Result<(), ArmError> {
        let ap = interface.fully_qualified_address();

        if ap == self.cm55_ap {
            // Local CM55 reset: write CM55_CMD reset value via the CM33 AP so that only
            // the CM55 is reset, leaving CM33 and the rest of the system untouched.
            // The CMD register lives in the APPSS secure address space; CM55 AHB can
            // also reach it but the CM33 AP is the safer path since CM55 may be halted.
            tracing::debug!("PSoC Edge: local CM55 reset via CM33 AP");

            let local_reset_result = (|| -> Result<(), ArmError> {
                {
                    let arm = interface
                        .get_arm_debug_interface()
                        .map_err(ArmError::Probe)?;
                    let mut cm33_ap = arm.memory_interface(&self.cm33_ap)?;
                    cm33_ap.write_word_32(MxCm55Cmd::ADDRESS, MxCm55Cmd::RESET)?;
                }

                // Wait for CM55 to come back up by polling DHCSR via the CM55 AP.
                cortex_m_wait_for_reset(interface)?;
                Ok(())
            })();

            if let Err(e) = local_reset_result {
                tracing::warn!(
                    "PSoC Edge: local CM55 reset failed ({:?}), falling back to SYSRESETREQ",
                    e
                );
                let dp = self.cm33_ap.dp();
                match interface.get_arm_debug_interface() {
                    Ok(arm) => Self::recover_dp_or_reconnect(arm, dp),
                    Err(err) => tracing::warn!(
                        "PSoC Edge: could not obtain ARM debug interface to recover DP: {:?}",
                        err
                    ),
                }
                self.reset_system_and_reconnect(interface)?;
            }

            // Re-enable CM55 debug AP access (local reset and system reset both clear AppCpussApCtl).
            self.cm55_enabled.store(false, Ordering::Relaxed);
            let enable_result = {
                let arm = interface
                    .get_arm_debug_interface()
                    .map_err(ArmError::Probe)?;
                self.try_enable_cm55(arm)
            };
            match enable_result {
                Ok(()) => {}
                Err(ArmError::CoreDisabled) => {
                    tracing::debug!("PSoC Edge: CM55 not ready after reset");
                }
                Err(e) => {
                    let dp = self.cm33_ap.dp();
                    match interface.get_arm_debug_interface() {
                        Ok(arm) => Self::recover_dp_or_reconnect(arm, dp),
                        Err(err) => tracing::warn!(
                            "PSoC Edge: could not obtain ARM debug interface to recover DP: {:?}",
                            err
                        ),
                    }
                    return Err(e);
                }
            }
            return Ok(());
        }

        // CM33 (system) reset path: issue AIRCR.SYSRESETREQ, then re-enable CM55
        // debug access if it was active before the reset.
        tracing::debug!("PSoC Edge: system reset via AIRCR.SYSRESETREQ");
        self.reset_system_and_reconnect(interface)?;

        // Give secure boot time to re-run before touching CM55 debug registers.
        std::thread::sleep(std::time::Duration::from_millis(RESET_FINISH_DELAY_MS));

        if self.cm55_enabled.load(Ordering::Relaxed) {
            tracing::debug!("PSoC Edge: re-enabling CM55 debug access after system reset");
            self.cm55_enabled.store(false, Ordering::Relaxed);
            let enable_result = {
                let arm = interface
                    .get_arm_debug_interface()
                    .map_err(ArmError::Probe)?;
                self.try_enable_cm55(arm)
            };
            match enable_result {
                Ok(()) => {}
                Err(ArmError::CoreDisabled) => {
                    // CM55 not yet started by firmware — not an error; it will be
                    // re-enabled on the next on_attach call when firmware starts it.
                    tracing::debug!(
                        "PSoC Edge: CM55 not ready after system reset (firmware may not have started it yet)"
                    );
                }
                Err(e) => {
                    // The re-enable may fault if secure boot has re-locked the CM55's
                    // secure space. The link is usually down for good at this point, so
                    // a bare ABORT write is not acknowledged: do a full reconnect so the
                    // session stays usable for shutdown and for the next operation. The
                    // CM55 is re-enabled on the next on_attach once firmware releases it.
                    let dp = self.cm33_ap.dp();
                    match interface.get_arm_debug_interface() {
                        Ok(arm) => Self::recover_dp_or_reconnect(arm, dp),
                        Err(err) => tracing::warn!(
                            "PSoC Edge: could not obtain ARM debug interface to recover DP: {:?}",
                            err
                        ),
                    }
                    tracing::debug!(
                        "PSoC Edge: failed to re-enable CM55 after system reset: {:?}",
                        e
                    );
                }
            }
        }

        Ok(())
    }

    fn debug_core_start(
        &self,
        interface: &mut dyn ArmDebugInterface,
        core_ap: &FullyQualifiedApAddress,
        core_type: CoreType,
        debug_base: Option<u64>,
        cti_base: Option<u64>,
    ) -> Result<(), ArmError> {
        if core_ap == &self.cm55_ap {
            // CM55 enablement is deferred to on_attach() which has proper error recovery
            // for the AHB stall that can occur when accessing CM55 registers in boot ROM state.
            return Ok(());
        }
        DefaultArmSequence(()).debug_core_start(interface, core_ap, core_type, debug_base, cti_base)
    }

    fn reset_catch_set(
        &self,
        core: &mut dyn ArmMemoryInterface,
        _core_type: CoreType,
        _debug_base: Option<u64>,
    ) -> Result<(), ArmError> {
        use crate::architecture::arm::armv8m::Demcr;

        let ap = core.fully_qualified_address();
        let current_demcr = core.read_word_32(Demcr::get_mmio_address())?;

        if ap == self.cm33_ap {
            self.cm33_demcr_saved
                .store(current_demcr, Ordering::Relaxed);
            self.cm33_demcr_valid.store(true, Ordering::Relaxed);
        } else if ap == self.cm55_ap {
            self.cm55_demcr_saved
                .store(current_demcr, Ordering::Relaxed);
            self.cm55_demcr_valid.store(true, Ordering::Relaxed);
        }

        let mut demcr = Demcr(current_demcr);
        demcr.set_vc_corereset(true);
        core.write_word_32(Demcr::get_mmio_address(), demcr.into())?;

        // Clear S_RESET_ST side effects on write by reading DHCSR.
        let _ = core.read_word_32(Dhcsr::get_mmio_address())?;

        Ok(())
    }

    fn reset_catch_clear(
        &self,
        core: &mut dyn ArmMemoryInterface,
        _core_type: CoreType,
        _debug_base: Option<u64>,
    ) -> Result<(), ArmError> {
        use crate::architecture::arm::armv8m::Demcr;

        let ap = core.fully_qualified_address();
        let restored = if ap == self.cm33_ap && self.cm33_demcr_valid.load(Ordering::Relaxed) {
            self.cm33_demcr_valid.store(false, Ordering::Relaxed);
            Some(self.cm33_demcr_saved.load(Ordering::Relaxed))
        } else if ap == self.cm55_ap && self.cm55_demcr_valid.load(Ordering::Relaxed) {
            self.cm55_demcr_valid.store(false, Ordering::Relaxed);
            Some(self.cm55_demcr_saved.load(Ordering::Relaxed))
        } else {
            None
        };

        if let Some(previous_demcr) = restored {
            core.write_word_32(Demcr::get_mmio_address(), previous_demcr)?;
            return Ok(());
        }

        // Fallback: no saved state for this core, so clear reset-catch bit only.
        let mut demcr = Demcr(core.read_word_32(Demcr::get_mmio_address())?);
        demcr.set_vc_corereset(false);
        core.write_word_32(Demcr::get_mmio_address(), demcr.into())?;
        Ok(())
    }
}

impl PsocEdge {
    /// Build the fully-qualified address of the system (SYS) access port.
    fn sys_ap(dp: DpAddress) -> FullyQualifiedApAddress {
        FullyQualifiedApAddress::v2_with_dp(dp, ApV2Address(Some(SYS_AP_BASE)))
    }

    /// Write one 32-bit word to `addr` through the SYS AP using raw TAR/DRW writes.
    ///
    /// `memory_interface()` is not used for the SYS AP: it would initialise a generic
    /// AMBA memory-AP adapter and reset CSW to a default that clears `DbgSwEnable`,
    /// breaking subsequent transfers. The SYS AP is a proprietary bus-access portal.
    fn write_sys_ap32(
        interface: &mut dyn ArmDebugInterface,
        sys_ap: &FullyQualifiedApAddress,
        addr: u32,
        value: u32,
    ) -> Result<(), ArmError> {
        interface.write_raw_ap_register(sys_ap, AP_TAR, addr)?;
        interface.write_raw_ap_register(sys_ap, AP_DRW, value)?;
        Ok(())
    }

    /// Read one 32-bit word from `addr` through the SYS AP using raw TAR/DRW accesses.
    fn read_sys_ap32(
        interface: &mut dyn ArmDebugInterface,
        sys_ap: &FullyQualifiedApAddress,
        addr: u32,
    ) -> Result<u32, ArmError> {
        interface.write_raw_ap_register(sys_ap, AP_TAR, addr)?;
        interface.read_raw_ap_register(sys_ap, AP_DRW)
    }

    /// Pulses XRES through an already-open debug interface.
    ///
    /// Restarts the boot ROM so a new Listen Window opens. The debug port is held in
    /// reset while XRES is asserted, so callers must reconnect it afterwards.
    fn pulse_xres(interface: &mut dyn ArmDebugInterface) -> Result<(), ArmError> {
        let mut n_reset = Pins(0);
        n_reset.set_nreset(true);
        let n_reset = n_reset.0 as u32;

        interface.swj_pins(0, n_reset, 0)?;
        std::thread::sleep(Duration::from_millis(XRES_PULSE_MS));
        interface.swj_pins(n_reset, n_reset, 0)?;

        Ok(())
    }

    /// Acquire the device in Test Mode via the SYS AP.
    ///
    /// Sets `TST_MODE.TEST_MODE` so the boot ROM stays in its Listen Window, then polls
    /// the extended boot status until it reports idle. Returns `Ok(true)` once the
    /// device is acquired and `Ok(false)` if the Listen Window closed before that;
    /// returns an error only on a debug transport fault, which the caller recovers from.
    fn acquire_test_mode(
        &self,
        interface: &mut dyn ArmDebugInterface,
        sys_ap: &FullyQualifiedApAddress,
    ) -> Result<bool, ArmError> {
        // Configure the SYS AP for 32-bit secure word accesses before using TAR/DRW.
        interface.write_raw_ap_register(sys_ap, AP_CSW, SYS_AP_CSW_WORD)?;

        // Request Test Mode so the boot ROM does not hand control to user firmware.
        Self::write_sys_ap32(interface, sys_ap, TST_MODE_ADDRESS, TEST_MODE_MSK)?;

        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(TIMEOUT_BOOT_COMPLETE_MS);
        loop {
            let status = Self::read_sys_ap32(interface, sys_ap, EXT_BOOT_STATUS_ADDRESS)?;
            if status == EXT_BOOT_STATUS_IDLE {
                tracing::debug!("PSoC Edge: acquired in Test Mode (boot status idle)");
                return Ok(true);
            }
            if std::time::Instant::now() >= deadline {
                tracing::debug!(
                    "PSoC Edge: boot status did not reach idle (last=0x{:08X})",
                    status
                );
                return Ok(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    /// Enable the CM55 debug interface via the CM33 memory AP.
    ///
    /// This powers up the CM55 domain, opens the CM55 AP, and enables debug. If the
    /// CM55 is still held in its post-reset wait state (boot firmware has not started
    /// it yet), it is released from wait and pre-initialized to a safe state so the
    /// debugger can attach to it directly
    ///
    /// Returns `Err(ArmError::CoreDisabled)` if the CM55 debug interface cannot be
    /// enabled. Returns other errors on hardware faults (e.g. AHB bus stall).
    fn try_enable_cm55(&self, interface: &mut dyn ArmDebugInterface) -> Result<(), ArmError> {
        // Power up the CM55 domain and open its AP + debug features via the CM33 AP.
        // Without this the CM55 AP and its peripheral registers are inaccessible. The
        // PWRMODE and APPCPUSS registers are reachable from CM33 at any time.
        {
            let mut cm33_ap = interface.memory_interface(&self.cm33_ap)?;

            let pd_sense_val = cm33_ap.read_word_32(PwrmodePd6PdSense::ADDRESS)?;
            let mut pd_sense = PwrmodePd6PdSense(pd_sense_val);
            if !pd_sense.pd_on_cm55() {
                tracing::debug!("Powering on CM55 domain");
                pd_sense.set_pd_on_cm55(true);
                cm33_ap.write_word_32(PwrmodePd6PdSense::ADDRESS, pd_sense.0)?;
            }

            // Enable the CM55 AP bits via CM33's system control register. This must
            // happen before any access through the CM55 AP.
            let ap_ctl_val = cm33_ap.read_word_32(AppCpussApCtl::ADDRESS)?;
            let mut ap_ctl = AppCpussApCtl(ap_ctl_val);
            ap_ctl.set_cm55_enable(true);
            ap_ctl.set_cm55_dbg_enable(true);
            ap_ctl.set_cm55_nid_enable(true);
            cm33_ap.write_word_32(AppCpussApCtl::ADDRESS, ap_ctl.0)?;
        }

        // Write C_DEBUGEN to DHCSR via the CM55 AP and verify it sticks.
        // DHCSR is in the CoreSight PPB space and is safe to access
        // even when CM55 is not running — unlike peripheral registers like MxCm55Ctl.
        //
        // Only enable debug here; do NOT force C_HALT. Forcing a halt on every attach
        // stops the running firmware and leaves non-halting profilers (e.g. `profile
        // flat pcsr`, which reads DWT_PCSR while the core runs) sampling a halted core
        // (PCSR reads 0xFFFFFFFF). Callers that need the core halted (gdb attach, the
        // callstack profiler) request the halt explicitly through the normal core API,
        // which also resumes it afterwards.
        {
            let mut cm55_ap = interface.memory_interface(&self.cm55_ap)?;
            let mut dhcsr = Dhcsr(0);
            dhcsr.enable_write();
            dhcsr.set_c_debugen(true);
            cm55_ap.write_word_32(Dhcsr::get_mmio_address(), dhcsr.into())?;

            // Verify the write was accepted by polling DHCSR.C_DEBUGEN.
            // The write may not take effect immediately, so retry a few times.
            const MAX_RETRIES: usize = 10;
            let mut enabled = false;
            for attempt in 1..=MAX_RETRIES {
                let dhcsr = Dhcsr(cm55_ap.read_word_32(Dhcsr::get_mmio_address())?);
                if dhcsr.c_debugen() {
                    tracing::debug!(
                        "CM55 debug interface enabled (attempt {}/{})",
                        attempt,
                        MAX_RETRIES
                    );
                    enabled = true;
                    break;
                }
                if attempt < MAX_RETRIES {
                    // Give the debug interface a moment to process the write
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
            if !enabled {
                tracing::warn!(
                    "CM55 debug interface did not respond to DHCSR.C_DEBUGEN write after {} attempts",
                    MAX_RETRIES
                );
                return Err(ArmError::CoreDisabled);
            }
        }

        // If the CM55 is still held in wait (boot firmware has not started it), release
        // it and set a safe initial state so the debugger can attach directly.
        //
        // MxCm55Ctl lives in the secure APPSS space. Once user firmware is running it
        // typically locks that space down, so the read faults with a DAP FaultResponse.
        // That fault is expected and simply means firmware has already taken the CM55
        // out of wait — so we treat it as "not waiting", clear the resulting DP sticky
        // error flags, and skip the release step (the core was already halted above via
        // DHCSR.C_HALT).
        let mut wait_read_faulted = false;
        let cpu_wait = {
            let mut cm33_ap = interface.memory_interface(&self.cm33_ap)?;
            match cm33_ap.read_word_32(MxCm55Ctl::ADDRESS) {
                Ok(val) => MxCm55Ctl(val).cm55_wait(),
                Err(e) => {
                    tracing::debug!(
                        "CM55 wait-state register not readable ({:?}); assuming firmware manages the CM55",
                        e
                    );
                    wait_read_faulted = true;
                    false
                }
            }
        };
        if wait_read_faulted {
            // The secure MxCm55Ctl read faulting (firmware locked the APPSS space) can
            // wedge the DP hard enough that a bare ABORT write no longer ACKs, which
            // would break every access after this. A full debug-port reconnect (line
            // reset + power-up) clears it; the just-written CM55 C_DEBUGEN is core
            // state and survives the reconnect. Fall back to the lighter sticky-flag
            // clear only if the reconnect itself is unavailable.
            if let Err(e) = interface.reinitialize() {
                tracing::debug!(
                    "DP reinitialize after CM55 wait-state fault failed: {:?}",
                    e
                );
                Self::recover_dp(interface, self.cm33_ap.dp());
            }
        }
        if cpu_wait {
            tracing::debug!("CM55 held in CPU_WAIT; releasing and pre-initializing");
            self.release_cm55_from_wait(interface)?;
        }

        self.cm55_enabled.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Lightweight re-attach path for an already-enabled CM55.
    ///
    /// Instead of re-running the full power-up / CPU_WAIT-release sequence (which
    /// re-writes DHCSR and can resume a core the debugger had already halted), this
    /// just confirms the CM55 debug interface is still responding and (re-)halts the
    /// core for the debugger.
    ///
    /// Returns `Err(ArmError::CoreDisabled)` if the CM55 debug interface is no longer
    /// accessible, so the caller can fall back to a full re-enable.
    /// Enables debug on the CM33 and halts it.
    ///
    /// Used after Test Mode acquisition, where the core runs the boot ROM Listen
    /// Window rather than being held in reset, so a reset catch cannot stop it.
    fn halt_cm33(&self, interface: &mut dyn ArmDebugInterface) -> Result<(), ArmError> {
        let mut cm33_ap = interface.memory_interface(&self.cm33_ap)?;

        let mut halt = Dhcsr(0);
        halt.enable_write();
        halt.set_c_debugen(true);
        halt.set_c_halt(true);
        cm33_ap.write_word_32(Dhcsr::get_mmio_address(), halt.into())?;

        for _ in 0..100 {
            if Dhcsr(cm33_ap.read_word_32(Dhcsr::get_mmio_address())?).s_halt() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        Err(ArmError::Timeout)
    }

    fn ensure_cm55_halted(&self, interface: &mut dyn ArmDebugInterface) -> Result<(), ArmError> {        let mut cm55_ap = interface.memory_interface(&self.cm55_ap)?;

        let dhcsr = Dhcsr(cm55_ap.read_word_32(Dhcsr::get_mmio_address())?);
        if !dhcsr.c_debugen() {
            return Err(ArmError::CoreDisabled);
        }
        if dhcsr.s_halt() {
            // Already halted — nothing to do.
            return Ok(());
        }

        // Core is running (e.g. firmware released it after the previous attach); halt
        // it so the debugger can read its state.
        let mut halt = Dhcsr(0);
        halt.enable_write();
        halt.set_c_debugen(true);
        halt.set_c_halt(true);
        cm55_ap.write_word_32(Dhcsr::get_mmio_address(), halt.into())?;

        for _ in 0..100 {
            if Dhcsr(cm55_ap.read_word_32(Dhcsr::get_mmio_address())?).s_halt() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        Ok(())
    }

    /// Release the CM55 from its post-reset wait state.
    ///
    /// Sets vector-catch-on-reset so the core halts the instant it is released, clears
    /// the `CPU_WAIT` bit via the CM33 AP, halts the core, restores the caller's
    /// original `DEMCR`, then pre-initializes the core to a safe state.
    fn release_cm55_from_wait(
        &self,
        interface: &mut dyn ArmDebugInterface,
    ) -> Result<(), ArmError> {
        use crate::architecture::arm::armv8m::Demcr;

        // Enable vector-catch-on-reset so the CM55 halts immediately once released.
        let saved_demcr = {
            let mut cm55_ap = interface.memory_interface(&self.cm55_ap)?;
            let saved = cm55_ap.read_word_32(Demcr::get_mmio_address())?;
            let mut demcr = Demcr(saved);
            demcr.set_vc_corereset(true);
            cm55_ap.write_word_32(Demcr::get_mmio_address(), demcr.into())?;
            saved
        };

        // Clear CPU_WAIT via the CM33 AP so the CM55 leaves its wait state.
        {
            let mut cm33_ap = interface.memory_interface(&self.cm33_ap)?;
            let mut ctl = MxCm55Ctl(cm33_ap.read_word_32(MxCm55Ctl::ADDRESS)?);
            ctl.set_cm55_wait(false);
            cm33_ap.write_word_32(MxCm55Ctl::ADDRESS, ctl.0)?;
        }

        // Halt the CM55 and wait until it reports being in debug state.
        let halted = {
            let mut cm55_ap = interface.memory_interface(&self.cm55_ap)?;
            let mut dhcsr = Dhcsr(0);
            dhcsr.enable_write();
            dhcsr.set_c_debugen(true);
            dhcsr.set_c_halt(true);
            cm55_ap.write_word_32(Dhcsr::get_mmio_address(), dhcsr.into())?;

            let mut halted = false;
            for _ in 0..100 {
                if Dhcsr(cm55_ap.read_word_32(Dhcsr::get_mmio_address())?).s_halt() {
                    halted = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            halted
        };

        // Restore the original DEMCR (removes the temporary vector-catch).
        {
            let mut cm55_ap = interface.memory_interface(&self.cm55_ap)?;
            cm55_ap.write_word_32(Demcr::get_mmio_address(), saved_demcr)?;
        }

        if !halted {
            tracing::warn!(
                "CM55 did not halt after clearing CPU_WAIT; skipping pre-initialization"
            );
            return Ok(());
        }

        self.preinit_cm55(interface)
    }

    /// Pre-initialize a freshly-released CM55 to a safe, well-defined state.
    ///
    /// When the CM55 has not been set up by firmware its `PC`/`SP` hold boot-time
    /// garbage, which makes the debugger fault on the first step or resume. A link
    /// register with the top nibble set (`0xF...`, an `EXC_RETURN` pattern) indicates
    /// this uninitialized state. In that case the core is pointed at an endless-loop
    /// instruction in safe internal memory with sane stack pointers.
    fn preinit_cm55(&self, interface: &mut dyn ArmDebugInterface) -> Result<(), ArmError> {
        let mut cm55_ap = interface.memory_interface(&self.cm55_ap)?;

        let lr = cortex_m::read_core_reg(&mut *cm55_ap, crate::RegisterId(REGSEL_LR))?;
        if lr & 0xF000_0000 != 0xF000_0000 {
            // Core already holds a plausible state; leave it untouched.
            return Ok(());
        }

        tracing::debug!(
            "Pre-initializing CM55: pc=0x{:X}, sp=0x{:X}",
            CM55_ENDLESS_LOOP_ADDR | 1,
            CM55_SAFE_SP
        );
        cm55_ap.write_word_32(CM55_ENDLESS_LOOP_ADDR, CM55_ENDLESS_LOOP_INSTR)?;
        cortex_m::write_core_reg(
            &mut *cm55_ap,
            crate::RegisterId(REGSEL_PC),
            (CM55_ENDLESS_LOOP_ADDR as u32) | 1,
        )?;
        cortex_m::write_core_reg(&mut *cm55_ap, crate::RegisterId(REGSEL_SP), CM55_SAFE_SP)?;
        cortex_m::write_core_reg(&mut *cm55_ap, crate::RegisterId(REGSEL_MSP), CM55_SAFE_SP)?;
        Ok(())
    }

    /// Issue AIRCR.SYSRESETREQ and wait for the debug port to come back.
    ///
    /// A PSOC Edge system reset takes the debug interface down while the boot ROM
    /// secures the system, so both the SYSRESETREQ write and the DHCSR polls
    /// afterwards can fail with transport errors of various shapes. Treat the
    /// write error as expected, then reconnect the debug port and poll DHCSR
    /// until it reads clean again or the recovery timeout elapses.
    fn reset_system_and_reconnect(
        &self,
        interface: &mut dyn ArmMemoryInterface,
    ) -> Result<(), ArmError> {
        use crate::architecture::arm::core::armv7m::Aircr;

        let mut aircr = Aircr(0);
        aircr.vectkey();
        aircr.set_sysresetreq(true);
        if let Err(e) = interface.write_word_32(Aircr::get_mmio_address(), aircr.into()) {
            tracing::debug!(
                "PSoC Edge: SYSRESETREQ write reported {:?} (expected when the reset drops the link)",
                e
            );
        }

        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(TIMEOUT_RESET_RECOVER_MS);
        loop {
            match interface.read_word_32(Dhcsr::get_mmio_address()) {
                // S_RESET_ST is sticky and clears on read: a read with the bit
                // clear means the reset has completed and no new one started.
                Ok(val) if !Dhcsr(val).s_reset_st() => return Ok(()),
                Ok(_) => {}
                Err(e) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(e);
                    }
                    // The debug port may still be down; try to bring it back.
                    if let Ok(probe) = interface.get_arm_debug_interface() {
                        let _ = probe.reinitialize();
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(ArmError::Timeout);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Recover the debug port after a faulted access wedged it.
    ///
    /// A faulting access into a locked or unclocked region can leave the DP so
    /// wedged that a bare ABORT write is not acknowledged. Do a full debug-port
    /// reconnect (line reset + power-up) and fall back to the lighter
    /// sticky-flag clear only when the reconnect is unavailable.
    fn recover_dp_or_reconnect(interface: &mut dyn ArmDebugInterface, dp: DpAddress) {
        if let Err(e) = interface.reinitialize() {
            tracing::debug!("DP reinitialize failed: {:?}", e);
            Self::recover_dp(interface, dp);
        }
    }

    /// Clear all DP sticky error flags via the ABORT register.
    ///
    /// Called after a failed AHB access that may have set STICKYERR/STICKYORUN.
    fn recover_dp(interface: &mut dyn ArmDebugInterface, dp: DpAddress) {
        let mut abort = Abort(0);
        abort.set_dapabort(true);
        abort.set_orunerrclr(true);
        abort.set_wderrclr(true);
        abort.set_stkerrclr(true);
        abort.set_stkcmpclr(true);
        // Attempt to clear sticky error flags. Every caller treats this as best-effort
        // and logs its own outcome, and the write legitimately goes unacknowledged
        // while the link is still down after a system reset, so a failure here is not
        // by itself a problem worth warning about.
        match interface.write_raw_dp_register(dp, Abort::ADDRESS, abort.0) {
            Ok(()) => tracing::debug!("Cleared DP sticky error flags"),
            Err(e) => tracing::debug!("Failed to clear DP sticky error flags: {:?}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PsocEdge;
    use crate::config::Registry;

    #[test]
    fn validate_psoc_edge_targets() {
        let registry = Registry::from_builtin_families();
        let family = registry
            .families()
            .iter()
            .find(|family| family.name == "psoc_e84")
            .unwrap();
        for chip in family.variants() {
            _ = PsocEdge::create(chip);
        }
    }
}
