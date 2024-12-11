use axerrno::ax_err_type;

pub fn has_hardware_support() -> bool {
    if let Some(feature) = raw_cpuid::CpuId::new().get_feature_info() {
        feature.has_vmx()
    } else {
        false
    }
}

pub fn read_vmcs_revision_id() -> u32 {
    0
}

fn as_axerr(err: x86::vmx::VmFail) -> axerrno::AxError {
    use x86::vmx::VmFail;
    match err {
        VmFail::VmFailValid => ax_err_type!(BadState, "Unsupported instruction"),
        VmFail::VmFailInvalid => ax_err_type!(BadState, "Unsupported instruction"),
    }
}
