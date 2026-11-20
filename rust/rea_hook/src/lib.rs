//! Hook `UC_HOOK_BLOCK` của winemu: kiểm cờ TF mỗi basic block mà không quay lại Python.
//!
//! Python giữ engine unicorn; thư viện này chỉ cung cấp hàm callback ABI C. Python đăng ký nó bằng `uc_hook_add`
//! với `user_data` trỏ tới `State`, đồng thời đưa con trỏ hàm `uc_reg_read`/`uc_emu_stop` của chính libunicorn
//! đang nạp (cùng một tiến trình), nên không cần link hay tải thêm libunicorn lần nữa.
use std::os::raw::{c_int, c_void};

pub const TF: u64 = 0x100;
pub const ABI_VERSION: u32 = 1;

type RegRead = unsafe extern "C" fn(uc: *mut c_void, regid: c_int, value: *mut c_void) -> c_int;
type EmuStop = unsafe extern "C" fn(uc: *mut c_void) -> c_int;

/// Bộ nhớ dùng chung với Python (ctypes.Structure cùng thứ tự trường).
#[repr(C)]
pub struct State {
    /// Số basic block đã chạy kể từ lần Python đặt về 0.
    pub nblk: u64,
    /// Địa chỉ block bắt đầu có TF (hợp lệ khi `tf_pend != 0`).
    pub tf_addr: u64,
    /// != 0: đã thấy TF và đã gọi emu_stop, chờ Python xử lý rồi đặt về 0.
    pub tf_pend: u32,
    /// Mã thanh ghi EFLAGS của unicorn (UC_X86_REG_EFLAGS).
    pub eflags_id: i32,
    /// Con trỏ hàm uc_reg_read, uc_emu_stop do Python điền.
    pub reg_read: Option<RegRead>,
    pub emu_stop: Option<EmuStop>,
}

#[no_mangle]
pub extern "C" fn rea_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub extern "C" fn rea_state_size() -> usize {
    std::mem::size_of::<State>()
}

/// Callback `uc_cb_hookcode_t`: (uc, address, size, user_data). Không bao giờ panic ra ngoài ranh giới FFI.
///
/// # Safety
/// `user_data` phải trỏ tới một `State` còn sống trong suốt thời gian hook được gắn; `uc` là engine hợp lệ.
#[no_mangle]
pub unsafe extern "C" fn rea_on_block(
    uc: *mut c_void,
    addr: u64,
    _size: u32,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    let st = &mut *(user_data as *mut State);
    st.nblk = st.nblk.wrapping_add(1);
    if st.tf_pend != 0 {
        return;
    }
    let rr = match st.reg_read {
        Some(f) => f,
        None => return,
    };
    let mut v: u64 = 0;
    if rr(uc, st.eflags_id, &mut v as *mut u64 as *mut c_void) != 0 {
        return;
    }
    if v & TF != 0 {
        st.tf_addr = addr;
        st.tf_pend = 1;
        if let Some(stop) = st.emu_stop {
            stop(uc);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static STOPS: AtomicU32 = AtomicU32::new(0);
    static mut FLAGS: u64 = 0;
    static mut RC: c_int = 0;

    unsafe extern "C" fn fake_rr(_uc: *mut c_void, _id: c_int, value: *mut c_void) -> c_int {
        *(value as *mut u64) = FLAGS;
        RC
    }
    unsafe extern "C" fn fake_stop(_uc: *mut c_void) -> c_int {
        STOPS.fetch_add(1, Ordering::SeqCst);
        0
    }
    fn state() -> State {
        State {
            nblk: 0,
            tf_addr: 0,
            tf_pend: 0,
            eflags_id: 9,
            reg_read: Some(fake_rr),
            emu_stop: Some(fake_stop),
        }
    }

    #[test]
    fn tf_dat_thi_dung_va_ghi_dia_chi() {
        unsafe {
            STOPS.store(0, Ordering::SeqCst);
            FLAGS = 0x302;
            RC = 0;
            let mut s = state();
            rea_on_block(
                std::ptr::null_mut(),
                0x1000_1234,
                5,
                &mut s as *mut State as *mut c_void,
            );
            assert_eq!((s.nblk, s.tf_pend, s.tf_addr), (1, 1, 0x1000_1234));
            assert_eq!(STOPS.load(Ordering::SeqCst), 1);
            // đang chờ: block kế tiếp chỉ đếm, không dừng lần nữa, không đổi địa chỉ
            rea_on_block(
                std::ptr::null_mut(),
                0x1000_9999,
                5,
                &mut s as *mut State as *mut c_void,
            );
            assert_eq!((s.nblk, s.tf_addr), (2, 0x1000_1234));
            assert_eq!(STOPS.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn khong_co_tf_thi_chi_dem() {
        unsafe {
            STOPS.store(0, Ordering::SeqCst);
            FLAGS = 0x202 | 0x1_0000_0000; // bit cao không được nhầm thành TF
            RC = 0;
            let mut s = state();
            for a in 0..3u64 {
                rea_on_block(
                    std::ptr::null_mut(),
                    a,
                    1,
                    &mut s as *mut State as *mut c_void,
                );
            }
            assert_eq!((s.nblk, s.tf_pend), (3, 0));
            assert_eq!(STOPS.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn loi_doc_thanh_ghi_hoac_thieu_ham_thi_bo_qua() {
        unsafe {
            STOPS.store(0, Ordering::SeqCst);
            FLAGS = 0x302;
            RC = 5; // uc_reg_read báo lỗi
            let mut s = state();
            rea_on_block(
                std::ptr::null_mut(),
                1,
                1,
                &mut s as *mut State as *mut c_void,
            );
            assert_eq!((s.nblk, s.tf_pend), (1, 0));
            s.reg_read = None;
            rea_on_block(
                std::ptr::null_mut(),
                1,
                1,
                &mut s as *mut State as *mut c_void,
            );
            assert_eq!((s.nblk, s.tf_pend), (2, 0));
            rea_on_block(std::ptr::null_mut(), 1, 1, std::ptr::null_mut()); // user_data null: không crash
            assert_eq!(STOPS.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn bo_cuc_state_on_dinh() {
        assert_eq!(rea_state_size(), 8 + 8 + 4 + 4 + 8 + 8);
        assert_eq!(rea_abi_version(), 1);
    }
}
