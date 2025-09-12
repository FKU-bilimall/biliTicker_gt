use std::ffi::{c_char, CStr, CString};
use std::ptr::null;
use crate::abstraction::{Api, GenerateW, Test};
use crate::click::Click;
use crate::slide::Slide;

//极验Challenge结构体
#[repr(C)]
pub struct GeetestChallenge {
    challenge: *mut c_char,
    gt: *mut c_char,
}

#[repr(C)]
pub struct GeetestResult {
    validate: *mut c_char,
    message: *mut c_char,
}

#[unsafe(no_mangle)]
pub extern "C" fn new_slide() -> *mut SlideFFI {
    Box::into_raw(Box::new(SlideFFI::new()))
}

#[unsafe(no_mangle)]
pub extern "C" fn free_slide(ptr: *mut SlideFFI) {
    if ptr.is_null() {
        return;
    } else {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_register_test(
    ptr: *mut SlideFFI,
    url: *const c_char,
) -> GeetestChallenge {
    // 检查空指针
    if ptr.is_null() || url.is_null() {
        return GeetestChallenge {
            challenge: std::ptr::null_mut(),
            gt: std::ptr::null_mut(),
        };
    }

    let slide = unsafe { &mut *ptr };

    // 转换 C 字符串到 Rust 字符串
    let c_str = unsafe { CStr::from_ptr(url) };
    let url_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            return GeetestChallenge {
                challenge: std::ptr::null_mut(),
                gt: std::ptr::null_mut(),
            }
        }
    };

    // 调用注册方法
    match slide.inner.register_test(url_str) {
        Ok((gt, challenge)) => {
            // 转换 Rust 字符串到 C 字符串
            let gt_cstring = match CString::new(gt) {
                Ok(s) => s,
                Err(_) => {
                    return GeetestChallenge {
                        challenge: std::ptr::null_mut(),
                        gt: std::ptr::null_mut(),
                    }
                }
            };

            let challenge_cstring = match CString::new(challenge) {
                Ok(s) => s,
                Err(_) => {
                    // 如果 challenge 转换失败，需要释放 gt_cstring
                    drop(gt_cstring);
                    return GeetestChallenge {
                        challenge: std::ptr::null_mut(),
                        gt: std::ptr::null_mut(),
                    }
                }
            };

            GeetestChallenge {
                gt: gt_cstring.into_raw(),
                challenge: challenge_cstring.into_raw(),
            }
        }
        Err(_) => GeetestChallenge {
            challenge: std::ptr::null_mut(),
            gt: std::ptr::null_mut(),
        },
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_generate_w(
    ptr: *mut SlideFFI,
    key: *const c_char,
    gt: *const c_char,
    challenge: *const c_char,
    c_ptr: *const u8,
    c_len: usize,
    s: *const c_char,
) -> *mut c_char {
    // 检查空指针
    if ptr.is_null() || key.is_null() || gt.is_null() || challenge.is_null() || c_ptr.is_null() || s.is_null() {
        return std::ptr::null_mut();
    }

    let slide = unsafe { &mut *ptr };

    // 转换 C 字符串到 Rust 字符串
    let key_str = match unsafe { CStr::from_ptr(key).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let s_str = match unsafe { CStr::from_ptr(s).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // 复制 c_ptr 指向的数据到 Rust Vec<u8>
    let c_slice = unsafe { std::slice::from_raw_parts(c_ptr, c_len) };

    // 调用 generate_w
    match slide.generate_w(key_str, gt_str, challenge_str, c_slice, s_str) {
        Ok(w) => match CString::new(w) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_calculate_key(
    ptr: *mut SlideFFI,
    gt: *const c_char,
    challenge: *const c_char,
) -> *mut c_char {
    // 检查空指针
    if ptr.is_null() || gt.is_null() || challenge.is_null() {
        return std::ptr::null_mut();
    }

    let slide = unsafe { &mut *ptr };

    // 转换 C 字符串到 Rust 字符串
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // 调用 calculate_key
    match slide.inner.get_new_c_s_args(gt_str, challenge_str) {
        Ok((_, _, args)) => match slide.calculate_key(args) {
            Ok(key) => match CString::new(key) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            },
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_verify(
    ptr: *mut SlideFFI,
    gt: *const c_char,
    challenge: *const c_char,
    w: *const c_char,
) -> GeetestResult {
    // 检查空指针
    if ptr.is_null() || gt.is_null() || challenge.is_null() || w.is_null() {
        return GeetestResult {
            validate: std::ptr::null_mut(),
            message: std::ptr::null_mut(),
        };
    }
    let slide = unsafe { &mut *ptr };
    // 转换 C 字符串到 Rust 字符串
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => {
            return GeetestResult {
                validate: std::ptr::null_mut(),
                message: std::ptr::null_mut(),
            }
        }
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => {
            return GeetestResult {
                validate: std::ptr::null_mut(),
                message: std::ptr::null_mut(),
            }
        }
    };
    let w_str = match unsafe { CStr::from_ptr(w).to_str() } {
        Ok(s) => s,
        Err(_) => {
            return GeetestResult {
                validate: std::ptr::null_mut(),
                message: std::ptr::null_mut(),
            }
        }
    };
    // 调用 verify
    match slide.verify(gt_str, challenge_str, Some(w_str)) {
        Ok((validate, message)) => {
            let validate_c = match CString::new(validate) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            };
            let message_c = match CString::new(message) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            };
            GeetestResult {
                validate: validate_c,
                message: message_c,
            }
        }
        Err(e) => {
            let msg = e;
            GeetestResult {
                validate: std::ptr::null_mut(),
                message: CString::new(msg).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut()),
            }
        }
    }
}

// 释放 GeetestResult 内存
#[unsafe(no_mangle)]
pub extern "C" fn slide_free_geetest_challenge(result: GeetestChallenge) {
    if !result.gt.is_null() {
        let _ = free_string(result.gt);
    }
    if !result.challenge.is_null() {
        let _ = free_string(result.challenge);
    }
}

// 单独释放字符串（可选）
#[unsafe(no_mangle)]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_get_c_s(
    ptr: *mut SlideFFI,
    gt: *const c_char,
    challenge: *const c_char,
    w: *const c_char,
    out_c_ptr: *mut *mut u8,
    out_c_len: *mut usize,
    out_s: *mut *mut c_char,
) -> i32 {
    if ptr.is_null() || gt.is_null() || challenge.is_null() || out_c_ptr.is_null() || out_c_len.is_null() || out_s.is_null() {
        return -1;
    }
    let slide = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let w_str = if w.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(w).to_str() } {
            Ok(s) => Some(s),
            Err(_) => return -2,
        }
    };
    match slide.get_c_s(gt_str, challenge_str, w_str) {
        Ok((c_vec, s_str)) => {
            let len = c_vec.len();
            let c_buf = unsafe { libc::malloc(len) as *mut u8 };
            if c_buf.is_null() {
                return -3;
            }
            unsafe { std::ptr::copy_nonoverlapping(c_vec.as_ptr(), c_buf, len); }
            unsafe { *out_c_ptr = c_buf; }
            unsafe { *out_c_len = len; }
            match CString::new(s_str) {
                Ok(s_cstr) => {
                    unsafe { *out_s = s_cstr.into_raw(); }
                    0
                },
                Err(_) => -4,
            }
        },
        Err(_) => -5,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_get_type(
    ptr: *mut SlideFFI,
    gt: *const c_char,
    challenge: *const c_char,
    w: *const c_char,
) -> *mut c_char {
    if ptr.is_null() || gt.is_null() || challenge.is_null() {
        return std::ptr::null_mut();
    }
    let slide = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let w_str = if w.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(w).to_str() } {
            Ok(s) => Some(s),
            Err(_) => return std::ptr::null_mut(),
        }
    };
    match slide.get_type(gt_str, challenge_str, w_str) {
        Ok(typ) => match CString::new(typ) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_free_geetest_result(result: GeetestResult) {
    if !result.validate.is_null() {
        let _ = free_string(result.validate);
    }
    if !result.message.is_null() {
        let _ = free_string(result.message);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_free_c_buf(buf: *mut u8, len: usize) {
    if !buf.is_null() && len > 0 {
        unsafe { libc::free(buf as *mut libc::c_void); }
    }
}

#[repr(C)]
pub struct SlideFFI {
    inner: Slide,
}

impl SlideFFI {
    fn new() -> Self {
        SlideFFI {
            inner: Slide::default(),
        }
    }

    fn register_test(&mut self, url: &str) -> Result<(String, String), String> {
        self.inner.register_test(url).map_err(|e| e.to_string())
    }

    fn get_c_s(
        &mut self,
        gt: &str,
        challenge: &str,
        w: Option<&str>,
    ) -> Result<(Vec<u8>, String), String> {
        self.inner.get_c_s(gt, challenge, w).map_err(|e| e.to_string())
    }

    fn get_type(&self, gt: &str, challenge: &str, w: Option<&str>) -> Result<String, String> {
        match self.inner.get_type(gt, challenge, w) {
            Ok(verify_type) => match verify_type {
                crate::abstraction::VerifyType::Slide => Ok("slide".to_string()),
                crate::abstraction::VerifyType::Click => Ok("click".to_string()),
            },
            Err(e) => Err(e.to_string()),
        }
    }

    fn get_new_c_s_args(
        &self,
        gt: &str,
        challenge: &str,
    ) -> Result<(Vec<u8>, String, <Slide as Api>::ArgsType), String> {
        self.inner
            .get_new_c_s_args(gt, challenge)
            .map_err(|e| e.to_string())
    }

    fn verify(&self, gt: &str, challenge: &str, w: Option<&str>) -> Result<(String, String), String> {
        self.inner.verify(gt, challenge, w).map_err(|e| e.to_string())
    }

    fn calculate_key(&mut self, args: <Slide as Api>::ArgsType) -> Result<String, String> {
        self.inner.calculate_key(args).map_err(|e| e.to_string())
    }
    fn generate_w(
        &self,
        key: &str,
        gt: &str,
        challenge: &str,
        c: &[u8],
        s: &str,
    ) -> Result<String, String> {
        self.inner
            .generate_w(key, gt, challenge, c, s)
            .map_err(|e| e.to_string())
    }

    fn test (&mut self, url: &str) -> Result<String, String> {
        self.inner.test(url).map_err(|e| e.to_string())
    }
}

struct ClickFFI {
    inner: Click,
}

impl ClickFFI {
    fn new() -> Self {
        ClickFFI {
            inner: Click::default(),
        }
    }

    fn register_test(&mut self, url: &str) -> Result<(String, String), String> {
        self.inner.register_test(url).map_err(|e| e.to_string())
    }

    fn get_c_s(
        &mut self,
        gt: &str,
        challenge: &str,
        w: Option<&str>,
    ) -> Result<(Vec<u8>, String), String> {
        self.inner.get_c_s(gt, challenge, w).map_err(|e| e.to_string())
    }

    fn get_type(&self, gt: &str, challenge: &str, w: Option<&str>) -> Result<String, String> {
        match self.inner.get_type(gt, challenge, w) {
            Ok(verify_type) => match verify_type {
                crate::abstraction::VerifyType::Slide => Ok("slide".to_string()),
                crate::abstraction::VerifyType::Click => Ok("click".to_string()),
            },
            Err(e) => Err(e.to_string()),
        }
    }

    fn get_new_c_s_args(
        &self,
        gt: &str,
        challenge: &str,
    ) -> Result<(Vec<u8>, String, <Click as Api>::ArgsType), String> {
        self.inner
            .get_new_c_s_args(gt, challenge)
            .map_err(|e| e.to_string())
    }

    fn verify(&self, gt: &str, challenge: &str, w: Option<&str>) -> Result<(String, String), String> {
        self.inner.verify(gt, challenge, w).map_err(|e| e.to_string())
    }

    fn calculate_key(&mut self, args: <Click as Api>::ArgsType) -> Result<String, String> {
        self.inner.calculate_key(args).map_err(|e| e.to_string())
    }

    fn generate_w(
        &self,
        key: &str,
        gt: &str,
        challenge: &str,
        c: &[u8],
        s: &str,
    ) -> Result<String, String> {
        self.inner
            .generate_w(key, gt, challenge, c, s)
            .map_err(|e| e.to_string())
    }

    fn test (&mut self, url: &str) -> Result<String, String> {
        self.inner.test(url).map_err(|e| e.to_string())
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn new_click() -> *mut ClickFFI {
    Box::into_raw(Box::new(ClickFFI::new()))
}

#[unsafe(no_mangle)]
pub extern "C" fn free_click(ptr: *mut ClickFFI) {
    if ptr.is_null() {
        return;
    } else {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_register_test(
    ptr: *mut ClickFFI,
    url: *const std::ffi::c_char,
) -> GeetestChallenge {
    if ptr.is_null() || url.is_null() {
        return GeetestChallenge {
            challenge: std::ptr::null_mut(),
            gt: std::ptr::null_mut(),
        };
    }
    let click = unsafe { &mut *ptr };
    let c_str = unsafe { CStr::from_ptr(url) };
    let url_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            return GeetestChallenge {
                challenge: std::ptr::null_mut(),
                gt: std::ptr::null_mut(),
            }
        }
    };
    match click.register_test(url_str) {
        Ok((gt, challenge)) => {
            let gt_cstring = match CString::new(gt) {
                Ok(s) => s,
                Err(_) => {
                    return GeetestChallenge {
                        challenge: std::ptr::null_mut(),
                        gt: std::ptr::null_mut(),
                    }
                }
            };
            let challenge_cstring = match CString::new(challenge) {
                Ok(s) => s,
                Err(_) => {
                    drop(gt_cstring);
                    return GeetestChallenge {
                        challenge: std::ptr::null_mut(),
                        gt: std::ptr::null_mut(),
                    }
                }
            };
            GeetestChallenge {
                gt: gt_cstring.into_raw(),
                challenge: challenge_cstring.into_raw(),
            }
        }
        Err(_) => GeetestChallenge {
            challenge: std::ptr::null_mut(),
            gt: std::ptr::null_mut(),
        },
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_generate_w(
    ptr: *mut ClickFFI,
    key: *const std::ffi::c_char,
    gt: *const std::ffi::c_char,
    challenge: *const std::ffi::c_char,
    c_ptr: *const u8,
    c_len: usize,
    s: *const std::ffi::c_char,
) -> *mut std::ffi::c_char {
    if ptr.is_null() || key.is_null() || gt.is_null() || challenge.is_null() || c_ptr.is_null() || s.is_null() {
        return std::ptr::null_mut();
    }
    let click = unsafe { &mut *ptr };
    let key_str = match unsafe { CStr::from_ptr(key).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let s_str = match unsafe { CStr::from_ptr(s).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let c_slice = unsafe { std::slice::from_raw_parts(c_ptr, c_len) };
    match click.generate_w(key_str, gt_str, challenge_str, c_slice, s_str) {
        Ok(w) => match CString::new(w) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_calculate_key(
    ptr: *mut ClickFFI,
    gt: *const std::ffi::c_char,
    challenge: *const std::ffi::c_char,
) -> *mut std::ffi::c_char {
    if ptr.is_null() || gt.is_null() || challenge.is_null() {
        return std::ptr::null_mut();
    }
    let click = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    match click.inner.get_new_c_s_args(gt_str, challenge_str) {
        Ok((_, _, args)) => match click.calculate_key(args) {
            Ok(key) => match CString::new(key) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            },
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_verify(
    ptr: *mut ClickFFI,
    gt: *const std::ffi::c_char,
    challenge: *const std::ffi::c_char,
    w: *const std::ffi::c_char,
) -> GeetestResult {
    if ptr.is_null() || gt.is_null() || challenge.is_null() || w.is_null() {
        return GeetestResult {
            validate: std::ptr::null_mut(),
            message: std::ptr::null_mut(),
        };
    }
    let click = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => {
            return GeetestResult {
                validate: std::ptr::null_mut(),
                message: std::ptr::null_mut(),
            }
        }
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => {
            return GeetestResult {
                validate: std::ptr::null_mut(),
                message: std::ptr::null_mut(),
            }
        }
    };
    let w_str = match unsafe { CStr::from_ptr(w).to_str() } {
        Ok(s) => s,
        Err(_) => {
            return GeetestResult {
                validate: std::ptr::null_mut(),
                message: std::ptr::null_mut(),
            }
        }
    };
    match click.verify(gt_str, challenge_str, Some(w_str)) {
        Ok((validate, message)) => {
            let validate_c = match CString::new(validate) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            };
            let message_c = match CString::new(message) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            };
            GeetestResult {
                validate: validate_c,
                message: message_c,
            }
        }
        Err(e) => {
            let msg = e;
            GeetestResult {
                validate: std::ptr::null_mut(),
                message: CString::new(msg).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut()),
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_get_c_s(
    ptr: *mut ClickFFI,
    gt: *const std::ffi::c_char,
    challenge: *const std::ffi::c_char,
    w: *const std::ffi::c_char,
    out_c_ptr: *mut *mut u8,
    out_c_len: *mut usize,
    out_s: *mut *mut std::ffi::c_char,
) -> i32 {
    if ptr.is_null() || gt.is_null() || challenge.is_null() || out_c_ptr.is_null() || out_c_len.is_null() || out_s.is_null() {
        return -1;
    }
    let click = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let w_str = if w.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(w).to_str() } {
            Ok(s) => Some(s),
            Err(_) => return -2,
        }
    };
    match click.get_c_s(gt_str, challenge_str, w_str) {
        Ok((c_vec, s_str)) => {
            let len = c_vec.len();
            let c_buf = unsafe { libc::malloc(len) as *mut u8 };
            if c_buf.is_null() {
                return -3;
            }
            unsafe { std::ptr::copy_nonoverlapping(c_vec.as_ptr(), c_buf, len); }
            unsafe { *out_c_ptr = c_buf; }
            unsafe { *out_c_len = len; }
            match CString::new(s_str) {
                Ok(s_cstr) => {
                    unsafe { *out_s = s_cstr.into_raw(); }
                    0
                },
                Err(_) => -4,
            }
        },
        Err(_) => -5,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_get_type(
    ptr: *mut ClickFFI,
    gt: *const std::ffi::c_char,
    challenge: *const std::ffi::c_char,
    w: *const std::ffi::c_char,
) -> *mut std::ffi::c_char {
    if ptr.is_null() || gt.is_null() || challenge.is_null() {
        return std::ptr::null_mut();
    }
    let click = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let w_str = if w.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(w).to_str() } {
            Ok(s) => Some(s),
            Err(_) => return std::ptr::null_mut(),
        }
    };
    match click.get_type(gt_str, challenge_str, w_str) {
        Ok(typ) => match CString::new(typ) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_free_geetest_challenge(result: GeetestChallenge) {
    if !result.gt.is_null() {
        let _ = free_string(result.gt);
    }
    if !result.challenge.is_null() {
        let _ = free_string(result.challenge);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_free_geetest_result(result: GeetestResult) {
    if !result.validate.is_null() {
        let _ = free_string(result.validate);
    }
    if !result.message.is_null() {
        let _ = free_string(result.message);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_free_c_buf(buf: *mut u8, len: usize) {
    if !buf.is_null() && len > 0 {
        unsafe { libc::free(buf as *mut libc::c_void); }
    }
}
