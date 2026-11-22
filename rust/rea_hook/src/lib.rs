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

/// Entropy Shannon (bit/byte, chưa làm tròn) của `len` byte tại `data`; trống hoặc con trỏ null cho 0.0.
/// Cộng các số hạng theo thứ tự byte xuất hiện lần đầu, đúng thứ tự `Counter` của Python, để kết quả làm tròn 2 chữ số khớp bản Python.
///
/// # Safety
/// `data` phải trỏ tới ít nhất `len` byte đọc được (hoặc null).
#[no_mangle]
pub unsafe extern "C" fn rea_entropy(data: *const u8, len: usize) -> f64 {
    if data.is_null() || len == 0 {
        return 0.0;
    }
    let s = std::slice::from_raw_parts(data, len);
    let mut cnt = [0u64; 256];
    let mut order = [0u8; 256];
    let mut k = 0usize;
    for &b in s {
        let c = &mut cnt[b as usize];
        if *c == 0 {
            order[k] = b;
            k += 1;
        }
        *c += 1;
    }
    let n = len as f64;
    let mut sum = 0.0f64;
    for &b in &order[..k] {
        let p = cnt[b as usize] as f64 / n;
        sum += p * p.log2();
    }
    -sum
}

/// Quét chuỗi in được: kind 0 = ASCII `[\x20-\x7e]{min,}`, kind 1 = UTF-16LE `([\x20-\x7e]\x00){min,}`.
/// Cùng ngữ nghĩa `re.findall` của Python (tham lam, không chồng lấn; UTF-16 thử từ mọi offset). Ghi cặp (offset byte, số ký tự)
/// vào `out` tối đa `cap` cặp, trả tổng số chuỗi (có thể lớn hơn `cap`: Python cấp lại bộ đệm rồi gọi lại).
///
/// # Safety
/// `data` đọc được `len` byte; `out` ghi được `2 * cap` u64 (hoặc null khi `cap` = 0).
#[no_mangle]
pub unsafe extern "C" fn rea_strings(
    data: *const u8,
    len: usize,
    min: usize,
    kind: u32,
    out: *mut u64,
    cap: usize,
) -> usize {
    if data.is_null() || len == 0 || min == 0 || (cap > 0 && out.is_null()) {
        return 0;
    }
    let d = std::slice::from_raw_parts(data, len);
    let pr = |b: u8| (0x20..=0x7e).contains(&b);
    let mut n = 0usize;
    let mut emit = |off: usize, chars: usize| {
        if n < cap {
            *out.add(2 * n) = off as u64;
            *out.add(2 * n + 1) = chars as u64;
        }
        n += 1;
    };
    let mut i = 0usize;
    if kind == 0 {
        while i < len {
            if pr(d[i]) {
                let st = i;
                while i < len && pr(d[i]) {
                    i += 1;
                }
                if i - st >= min {
                    emit(st, i - st);
                }
            } else {
                i += 1;
            }
        }
    } else {
        while i + 1 < len {
            let mut k = 0usize;
            while i + 2 * k + 1 < len && pr(d[i + 2 * k]) && d[i + 2 * k + 1] == 0 {
                k += 1;
            }
            if k >= min {
                emit(i, k);
                i += 2 * k;
            } else {
                i += 1;
            }
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runs(b: &[u8], min: usize, kind: u32) -> Vec<(u64, u64)> {
        let mut o = vec![0u64; 64];
        let n = unsafe { rea_strings(b.as_ptr(), b.len(), min, kind, o.as_mut_ptr(), 32) };
        (0..n.min(32)).map(|i| (o[2 * i], o[2 * i + 1])).collect()
    }

    #[test]
    fn strings_cases() {
        assert_eq!(runs(b"ab\x00abcdef\x01xyz123", 6, 0), vec![(3, 6), (10, 6)]);
        assert_eq!(runs(b"a\x00b\x00c\x00d\x00e\x00f\x00g", 6, 1), vec![(0, 6)]);
        assert_eq!(
            runs(b"x\x00a\x00b\x00c\x00d\x00e\x00f\x00", 6, 1),
            vec![(0, 7)]
        );
        assert!(runs(b"abc", 6, 0).is_empty() && runs(b"", 6, 1).is_empty());
        let mut o = [0u64; 2];
        assert_eq!(
            unsafe { rea_strings(b"abcdefgh".as_ptr(), 8, 3, 0, o.as_mut_ptr(), 0) },
            1
        );
    }

    fn ent(b: &[u8]) -> f64 {
        unsafe { rea_entropy(b.as_ptr(), b.len()) }
    }

    #[test]
    fn entropy_cases() {
        assert_eq!(ent(&[]), 0.0);
        assert_eq!(unsafe { rea_entropy(std::ptr::null(), 5) }, 0.0);
        assert_eq!(ent(&[7u8; 1000]), 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((ent(&all) - 8.0).abs() < 1e-12);
        assert!((ent(&[0, 1, 0, 1]) - 1.0).abs() < 1e-12);
    }

    /// Ngữ cảnh giả đi theo tham số `uc`: mỗi test một bản riêng nên chạy song song không dẫm lên nhau.
    struct Fake {
        flags: u64,
        rc: c_int,
        stops: u32,
    }

    unsafe extern "C" fn fake_rr(uc: *mut c_void, _id: c_int, value: *mut c_void) -> c_int {
        let f = &*(uc as *const Fake);
        *(value as *mut u64) = f.flags;
        f.rc
    }
    unsafe extern "C" fn fake_stop(uc: *mut c_void) -> c_int {
        (*(uc as *mut Fake)).stops += 1;
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
    unsafe fn block(f: &mut Fake, s: &mut State, addr: u64) {
        rea_on_block(
            f as *mut Fake as *mut c_void,
            addr,
            5,
            s as *mut State as *mut c_void,
        );
    }

    #[test]
    fn tf_dat_thi_dung_va_ghi_dia_chi() {
        unsafe {
            let mut f = Fake {
                flags: 0x302,
                rc: 0,
                stops: 0,
            };
            let mut s = state();
            block(&mut f, &mut s, 0x1000_1234);
            assert_eq!((s.nblk, s.tf_pend, s.tf_addr), (1, 1, 0x1000_1234));
            assert_eq!(f.stops, 1);
            // đang chờ: block kế tiếp chỉ đếm, không dừng lần nữa, không đổi địa chỉ
            block(&mut f, &mut s, 0x1000_9999);
            assert_eq!((s.nblk, s.tf_addr), (2, 0x1000_1234));
            assert_eq!(f.stops, 1);
        }
    }

    #[test]
    fn khong_co_tf_thi_chi_dem() {
        unsafe {
            let mut f = Fake {
                flags: 0x202 | 0x1_0000_0000,
                rc: 0,
                stops: 0,
            }; // bit cao không được nhầm thành TF
            let mut s = state();
            for a in 0..3u64 {
                block(&mut f, &mut s, a);
            }
            assert_eq!((s.nblk, s.tf_pend), (3, 0));
            assert_eq!(f.stops, 0);
        }
    }

    #[test]
    fn loi_doc_thanh_ghi_hoac_thieu_ham_thi_bo_qua() {
        unsafe {
            let mut f = Fake {
                flags: 0x302,
                rc: 5,
                stops: 0,
            }; // uc_reg_read báo lỗi
            let mut s = state();
            block(&mut f, &mut s, 1);
            assert_eq!((s.nblk, s.tf_pend), (1, 0));
            s.reg_read = None;
            block(&mut f, &mut s, 1);
            assert_eq!((s.nblk, s.tf_pend), (2, 0));
            rea_on_block(
                &mut f as *mut Fake as *mut c_void,
                1,
                1,
                std::ptr::null_mut(),
            ); // user_data null: không crash
            assert_eq!(f.stops, 0);
        }
    }

    #[test]
    fn bo_cuc_state_on_dinh() {
        assert_eq!(rea_state_size(), 8 + 8 + 4 + 4 + 8 + 8);
        assert_eq!(rea_abi_version(), 1);
    }
}
