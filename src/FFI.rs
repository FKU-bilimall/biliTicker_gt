use crate::abstraction::{Api, GenerateW, Test};
use crate::click::Click;
use crate::slide::Slide;
use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;

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

#[repr(C)]
pub struct GeetestCS {
    c_ptr: *mut u8,
    c_len: usize,
    s: *mut c_char,
}

#[repr(C)]
pub struct ReturnValue {
    data: *mut c_void,
    code: u8,
    message: *mut c_char,
}

#[repr(C)]
pub struct ArgsBundle {
    pub c_ptr: *mut u8,
    pub c_len: usize,
    pub s: *mut c_char,
    pub new_challenge: *mut c_char,
    pub full_bg_url: *mut c_char,
    pub miss_bg_url: *mut c_char,
    pub slider_url: *mut c_char,
}

// === Utility functions for ReturnValue ===

fn make_error_return(msg: &str) -> ReturnValue {
    ReturnValue {
        data: ptr::null_mut(),
        code: 1,
        message: CString::new(msg).map(|s| s.into_raw()).unwrap_or(ptr::null_mut()),
    }
}

fn make_success_return<T>(v: T) -> ReturnValue
where
    T: Sized,
{
    let b = Box::new(v);
    ReturnValue {
        data: Box::into_raw(b) as *mut c_void,
        code: 0,
        message: ptr::null_mut(),
    }
}

fn make_success_str_return(s: String) -> ReturnValue {
    match CString::new(s) {
        Ok(cs) => ReturnValue {
            data: cs.into_raw() as *mut c_void,
            code: 0,
            message: ptr::null_mut(),
        },
        Err(_) => make_error_return("CString conversion failed"),
    }
}

// === SlideFFI exposed FFI ===

#[unsafe(no_mangle)]
pub extern "C" fn new_slide() -> *mut SlideFFI {
    Box::into_raw(Box::new(SlideFFI::new()))
}

#[unsafe(no_mangle)]
pub extern "C" fn free_slide(ptr: *mut SlideFFI) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let slide_ffi = &mut *ptr;
        slide_ffi.drop_inner();
        let _ = Box::from_raw(ptr);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_register_test(ptr: *mut SlideFFI, url: *const c_char) -> ReturnValue {
    if ptr.is_null() || url.is_null() {
        return make_error_return("null pointer");
    }

    let slide = unsafe { &mut *ptr };
    let url_str = match unsafe { CStr::from_ptr(url) }.to_str() {
        Ok(s) => s,
        Err(_) => return make_error_return("url not utf8"),
    };

    match slide.register_test(url_str) {
        Ok((gt, challenge)) => {
            let gt_cstring = CString::new(gt).map_err(|_| "gt CString failed");
            let challenge_cstring = CString::new(challenge).map_err(|_| "challenge CString failed");
            match (gt_cstring, challenge_cstring) {
                (Ok(gt), Ok(challenge)) => {
                    let challenge_struct = GeetestChallenge {
                        gt: gt.into_raw(),
                        challenge: challenge.into_raw(),
                    };
                    make_success_return(challenge_struct)
                }
                (Err(e), _) | (_, Err(e)) => make_error_return(e),
            }
        }
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_generate_w(
    ptr: *mut SlideFFI,
    key: *const c_char,
    gt: *const c_char,
    challenge: *const c_char,
    u8_ptr: *const u8,
    u8_len: usize,
    s: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || key.is_null() || gt.is_null() || challenge.is_null() || u8_ptr.is_null() || s.is_null() {
        return make_error_return("null pointer");
    }
    let slide = unsafe { &mut *ptr };

    let key_str = match unsafe { CStr::from_ptr(key).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("key not utf8"),
    };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("gt not utf8"),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("challenge not utf8"),
    };
    let s_str = match unsafe { CStr::from_ptr(s).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("s not utf8"),
    };

    let c_slice = unsafe { std::slice::from_raw_parts(u8_ptr, u8_len) };

    match slide.generate_w(key_str, gt_str, challenge_str, c_slice, s_str) {
        Ok(w) => make_success_str_return(w),
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_get_new_c_s_args(
    ptr: *mut SlideFFI,
    gt: *const c_char,
    challenge: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || gt.is_null() || challenge.is_null() {
        return make_error_return("null pointer");
    }

    let slide = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("gt not utf8"),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("challenge not utf8"),
    };

    match slide.get_new_c_s_args(gt_str, challenge_str) {
        Ok((v, s, (new_challenge, full_bg_url, miss_bg_url, slider_url))) => {
            // Vec<u8> -> *mut u8
            let c_len = v.len();
            let c_ptr = unsafe {
                let buf = libc::malloc(c_len) as *mut u8;
                if buf.is_null() {
                    return make_error_return("malloc failed");
                }
                std::ptr::copy_nonoverlapping(v.as_ptr(), buf, c_len);
                buf
            };
            // String -> *mut c_char
            let s = match CString::new(s) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    unsafe { libc::free(c_ptr as *mut libc::c_void); }
                    return make_error_return("CString failed for s");
                }
            };
            let new_challenge = match CString::new(new_challenge) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    unsafe { libc::free(c_ptr as *mut libc::c_void); }
                    let _ = unsafe { CString::from_raw(s) };
                    return make_error_return("CString failed for new_challenge");
                }
            };
            let full_bg_url = match CString::new(full_bg_url) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    unsafe { libc::free(c_ptr as *mut libc::c_void); }
                    let _ = unsafe { CString::from_raw(s) };
                    let _ = unsafe { CString::from_raw(new_challenge) };
                    return make_error_return("CString failed for full_bg_url");
                }
            };
            let miss_bg_url = match CString::new(miss_bg_url) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    unsafe { libc::free(c_ptr as *mut libc::c_void); }
                    let _ = unsafe { CString::from_raw(s) };
                    let _ = unsafe { CString::from_raw(new_challenge) };
                    let _ = unsafe { CString::from_raw(full_bg_url) };
                    return make_error_return("CString failed for miss_bg_url");
                }
            };
            let slider_url = match CString::new(slider_url) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    unsafe { libc::free(c_ptr as *mut libc::c_void); }
                    let _ = unsafe { CString::from_raw(s) };
                    let _ = unsafe { CString::from_raw(new_challenge) };
                    let _ = unsafe { CString::from_raw(full_bg_url) };
                    let _ = unsafe { CString::from_raw(miss_bg_url) };
                    return make_error_return("CString failed for slider_url");
                }
            };
            let bundle = ArgsBundle {
                c_ptr,
                c_len,
                s,
                new_challenge,
                full_bg_url,
                miss_bg_url,
                slider_url,
            };
            make_success_return(bundle)
        }
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_calculate_key(
    ptr: *mut SlideFFI,
    new_challenge: *const c_char,
    full_bg_url: *const c_char,
    miss_bg_url: *const c_char,
    slider_url: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || new_challenge.is_null() || full_bg_url.is_null() || miss_bg_url.is_null() || slider_url.is_null() {
        return make_error_return("null pointer");
    }

    let slide = unsafe { &mut *ptr };
    let new_challenge_str = match unsafe { CStr::from_ptr(new_challenge).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => return make_error_return("new_challenge not utf8"),
    };
    let full_bg_url_str = match unsafe { CStr::from_ptr(full_bg_url).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => return make_error_return("full_bg_url not utf8"),
    };
    let miss_bg_url_str = match unsafe { CStr::from_ptr(miss_bg_url).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => return make_error_return("miss_bg_url not utf8"),
    };
    let slider_url_str = match unsafe { CStr::from_ptr(slider_url).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => return make_error_return("slider_url not utf8"),
    };

    match slide.calculate_key((new_challenge_str, full_bg_url_str, miss_bg_url_str, slider_url_str)) {
        Ok(key) => make_success_str_return(key),
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_verify(
    ptr: *mut SlideFFI,
    gt: *const c_char,
    challenge: *const c_char,
    w: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || gt.is_null() || challenge.is_null() || w.is_null() {
        return make_error_return("null pointer");
    }
    let slide = unsafe { &mut *ptr };

    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("gt not utf8"),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("challenge not utf8"),
    };
    let w_str = match unsafe { CStr::from_ptr(w).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("w not utf8"),
    };

    match slide.verify(gt_str, challenge_str, Some(w_str)) {
        Ok((validate, message)) => {
            let result = GeetestResult {
                validate: CString::new(validate).map(|c| c.into_raw()).unwrap_or(ptr::null_mut()),
                message: CString::new(message).map(|c| c.into_raw()).unwrap_or(ptr::null_mut()),
            };
            make_success_return(result)
        }
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_get_c_s(
    ptr: *mut SlideFFI,
    gt: *const c_char,
    challenge: *const c_char,
    w: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || gt.is_null() || challenge.is_null() {
        return make_error_return("null pointer");
    }
    let slide = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("gt not utf8"),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("challenge not utf8"),
    };
    let w_str = if w.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(w).to_str() } {
            Ok(s) => Some(s),
            Err(_) => return make_error_return("w not utf8"),
        }
    };
    match slide.get_c_s(gt_str, challenge_str, w_str) {
        Ok((c_vec, s_str)) => {
            let len = c_vec.len();
            let c_buf = unsafe { libc::malloc(len) as *mut u8 };
            if c_buf.is_null() {
                return make_error_return("malloc failed");
            }
            unsafe { std::ptr::copy_nonoverlapping(c_vec.as_ptr(), c_buf, len); }
            let s_cstr = match CString::new(s_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    unsafe { libc::free(c_buf as *mut libc::c_void); }
                    return make_error_return("CString failed");
                }
            };
            let cs = GeetestCS {
                c_ptr: c_buf,
                c_len: len,
                s: s_cstr,
            };
            make_success_return(cs)
        },
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn slide_get_type(
    ptr: *mut SlideFFI,
    gt: *const c_char,
    challenge: *const c_char,
    w: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || gt.is_null() || challenge.is_null() {
        return make_error_return("null pointer");
    }
    let slide = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("gt not utf8"),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("challenge not utf8"),
    };
    let w_str = if w.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(w).to_str() } {
            Ok(s) => Some(s),
            Err(_) => return make_error_return("w not utf8"),
        }
    };
    match slide.get_type(gt_str, challenge_str, w_str) {
        Ok(typ) => make_success_str_return(typ),
        Err(e) => make_error_return(&e),
    }
}

// === ClickFFI exposed FFI, all use ReturnValue ===

#[unsafe(no_mangle)]
pub extern "C" fn new_click() -> *mut ClickFFI {
    Box::into_raw(Box::new(ClickFFI::new()))
}

#[unsafe(no_mangle)]
pub extern "C" fn free_click(ptr: *mut ClickFFI) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let click_ffi = &mut *ptr;
        click_ffi.drop_inner();
        let _ = Box::from_raw(ptr);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_register_test(ptr: *mut ClickFFI, url: *const c_char) -> ReturnValue {
    if ptr.is_null() || url.is_null() {
        return make_error_return("null pointer");
    }

    let click = unsafe { &mut *ptr };
    let url_str = match unsafe { CStr::from_ptr(url) }.to_str() {
        Ok(s) => s,
        Err(_) => return make_error_return("url not utf8"),
    };

    match click.register_test(url_str) {
        Ok((gt, challenge)) => {
            let gt_cstring = CString::new(gt).map_err(|_| "gt CString failed");
            let challenge_cstring = CString::new(challenge).map_err(|_| "challenge CString failed");
            match (gt_cstring, challenge_cstring) {
                (Ok(gt), Ok(challenge)) => {
                    let challenge_struct = GeetestChallenge {
                        gt: gt.into_raw(),
                        challenge: challenge.into_raw(),
                    };
                    make_success_return(challenge_struct)
                }
                (Err(e), _) | (_, Err(e)) => make_error_return(e),
            }
        }
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_generate_w(
    ptr: *mut ClickFFI,
    key: *const c_char,
    gt: *const c_char,
    challenge: *const c_char,
    c_ptr: *const u8,
    c_len: usize,
    s: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || key.is_null() || gt.is_null() || challenge.is_null() || c_ptr.is_null() || s.is_null() {
        return make_error_return("null pointer");
    }
    let click = unsafe { &mut *ptr };

    let key_str = match unsafe { CStr::from_ptr(key).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("key not utf8"),
    };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("gt not utf8"),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("challenge not utf8"),
    };
    let s_str = match unsafe { CStr::from_ptr(s).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("s not utf8"),
    };

    let c_slice = unsafe { std::slice::from_raw_parts(c_ptr, c_len) };

    match click.generate_w(key_str, gt_str, challenge_str, c_slice, s_str) {
        Ok(w) => make_success_str_return(w),
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_get_new_c_s_args(
    ptr: *mut ClickFFI,
    gt: *const c_char,
    challenge: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || gt.is_null() || challenge.is_null() {
        return make_error_return("null pointer");
    }

    let click = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("gt not utf8"),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("challenge not utf8"),
    };

    match click.get_new_c_s_args(gt_str, challenge_str) {
        Ok((v, s1, s2)) => {
            let c_len = v.len();
            let c_ptr = unsafe {
                let buf = libc::malloc(c_len) as *mut u8;
                if buf.is_null() {
                    return make_error_return("malloc failed");
                }
                std::ptr::copy_nonoverlapping(v.as_ptr(), buf, c_len);
                buf
            };
            // String -> *mut c_char
            let s = match CString::new(s1) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    unsafe { libc::free(c_ptr as *mut libc::c_void); }
                    return make_error_return("CString failed for s1");
                }
            };
            let new_challenge = match CString::new(s2) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    unsafe { libc::free(c_ptr as *mut libc::c_void); }
                    let _ = unsafe { CString::from_raw(s) };
                    return make_error_return("CString failed for s2");
                }
            };
            let bundle = ArgsBundle {
                c_ptr,
                c_len,
                s,
                new_challenge,
                full_bg_url: ptr::null_mut(),
                miss_bg_url: ptr::null_mut(),
                slider_url: ptr::null_mut(),
            };
            make_success_return(bundle)
        }
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_calculate_key(
    ptr: *mut ClickFFI,
    s: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || s.is_null() {
        return make_error_return("null pointer");
    }

    let click = unsafe { &mut *ptr };
    let s_str = match unsafe { CStr::from_ptr(s).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => return make_error_return("new_challenge not utf8"),
    };

    match click.calculate_key(s_str) {
        Ok(key) => make_success_str_return(key),
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_verify(
    ptr: *mut ClickFFI,
    gt: *const c_char,
    challenge: *const c_char,
    w: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || gt.is_null() || challenge.is_null() || w.is_null() {
        return make_error_return("null pointer");
    }
    let click = unsafe { &mut *ptr };

    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("gt not utf8"),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("challenge not utf8"),
    };
    let w_str = match unsafe { CStr::from_ptr(w).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("w not utf8"),
    };

    match click.verify(gt_str, challenge_str, Some(w_str)) {
        Ok((message,validate)) => {
            let result = GeetestResult {
                validate: CString::new(validate).map(|c| c.into_raw()).unwrap_or(ptr::null_mut()),
                message: CString::new(message).map(|c| c.into_raw()).unwrap_or(ptr::null_mut()),
            };
            make_success_return(result)
        }
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_get_c_s(
    ptr: *mut ClickFFI,
    gt: *const c_char,
    challenge: *const c_char,
    w: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || gt.is_null() || challenge.is_null() {
        return make_error_return("null pointer");
    }
    let click = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("gt not utf8"),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("challenge not utf8"),
    };
    let w_str = if w.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(w).to_str() } {
            Ok(s) => Some(s),
            Err(_) => return make_error_return("w not utf8"),
        }
    };
    match click.get_c_s(gt_str, challenge_str, w_str) {
        Ok((c_vec, s_str)) => {
            let len = c_vec.len();
            let c_buf = unsafe { libc::malloc(len) as *mut u8 };
            if c_buf.is_null() {
                return make_error_return("malloc failed");
            }
            unsafe { std::ptr::copy_nonoverlapping(c_vec.as_ptr(), c_buf, len); }
            let s_cstr = match CString::new(s_str) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    unsafe { libc::free(c_buf as *mut libc::c_void); }
                    return make_error_return("CString failed");
                }
            };
            let cs = GeetestCS {
                c_ptr: c_buf,
                c_len: len,
                s: s_cstr,
            };
            make_success_return(cs)
        },
        Err(e) => make_error_return(&e),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn click_get_type(
    ptr: *mut ClickFFI,
    gt: *const c_char,
    challenge: *const c_char,
    w: *const c_char,
) -> ReturnValue {
    if ptr.is_null() || gt.is_null() || challenge.is_null() {
        return make_error_return("null pointer");
    }
    let click = unsafe { &mut *ptr };
    let gt_str = match unsafe { CStr::from_ptr(gt).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("gt not utf8"),
    };
    let challenge_str = match unsafe { CStr::from_ptr(challenge).to_str() } {
        Ok(s) => s,
        Err(_) => return make_error_return("challenge not utf8"),
    };
    let w_str = if w.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(w).to_str() } {
            Ok(s) => Some(s),
            Err(_) => return make_error_return("w not utf8"),
        }
    };
    match click.get_type(gt_str, challenge_str, w_str) {
        Ok(typ) => {
            make_success_str_return(typ)
        },
        Err(e) => make_error_return(&e),
    }
}

// === Free functions ===
// type_code: 0 = *mut c_char, 1 = GeetestChallenge, 2 = GeetestResult, 3 = GeetestCS, 4 = ArgsBundle, 255 = unknown/none

#[unsafe(no_mangle)]
pub extern "C" fn free_return_value(rv: ReturnValue, ty: u8) {
    if !rv.data.is_null() {
        unsafe {
            match ty {
                0 => {
                    let _ = CString::from_raw(rv.data as *mut c_char);
                }
                1 => {
                    let ch = Box::from_raw(rv.data as *mut GeetestChallenge);
                    if !ch.gt.is_null() {
                        let _ = CString::from_raw(ch.gt);
                    }
                    if !ch.challenge.is_null() {
                        let _ = CString::from_raw(ch.challenge);
                    }
                }
                2 => {
                    let gr = Box::from_raw(rv.data as *mut GeetestResult);
                    if !gr.validate.is_null() {
                        let _ = CString::from_raw(gr.validate);
                    }
                    if !gr.message.is_null() {
                        let _ = CString::from_raw(gr.message);
                    }
                }
                3 => {
                    let cs = Box::from_raw(rv.data as *mut GeetestCS);
                    if !cs.c_ptr.is_null() && cs.c_len > 0 {
                        libc::free(cs.c_ptr as *mut libc::c_void);
                    }
                    if !cs.s.is_null() {
                        let _ = CString::from_raw(cs.s);
                    }
                }
                4 => {
                    let ab = Box::from_raw(rv.data as *mut ArgsBundle);
                    if !ab.c_ptr.is_null() && ab.c_len > 0 {
                        libc::free(ab.c_ptr as *mut libc::c_void);
                    }
                    if !ab.s.is_null() {
                        let _ = CString::from_raw(ab.s);
                    }
                    if !ab.new_challenge.is_null() {
                        let _ = CString::from_raw(ab.new_challenge);
                    }
                    if !ab.full_bg_url.is_null() {
                        let _ = CString::from_raw(ab.full_bg_url);
                    }
                    if !ab.miss_bg_url.is_null() {
                        let _ = CString::from_raw(ab.miss_bg_url);
                    }
                    if !ab.slider_url.is_null() {
                        let _ = CString::from_raw(ab.slider_url);
                    }
                }
                _ => {}
            }
        }
    }
    if !rv.message.is_null() {
        unsafe { let _ = CString::from_raw(rv.message); }
    }
}

// === SlideFFI and ClickFFI struct definitions unchanged ===

#[repr(C)]
pub struct SlideFFI {
    inner: *mut Slide,
}

impl SlideFFI {
    fn new() -> Self {
        SlideFFI {
            inner: Box::into_raw(Box::new(Slide::default())),
        }
    }

    fn drop_inner(&mut self) {
        if !self.inner.is_null() {
            unsafe { let _ = Box::from_raw(self.inner); }
            self.inner = std::ptr::null_mut();
        }
    }

    fn register_test(&mut self, url: &str) -> Result<(String, String), String> {
        unsafe { &mut *self.inner }.register_test(url).map_err(|e| e.to_string())
    }

    fn get_c_s(
        &mut self,
        gt: &str,
        challenge: &str,
        w: Option<&str>,
    ) -> Result<(Vec<u8>, String), String> {
        unsafe { &mut *self.inner }.get_c_s(gt, challenge, w).map_err(|e| e.to_string())
    }

    fn get_type(&self, gt: &str, challenge: &str, w: Option<&str>) -> Result<String, String> {
        match unsafe { &*self.inner }.get_type(gt, challenge, w) {
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
        unsafe { &*self.inner }
            .get_new_c_s_args(gt, challenge)
            .map_err(|e| e.to_string())
    }

    fn verify(&self, gt: &str, challenge: &str, w: Option<&str>) -> Result<(String, String), String> {
        unsafe { &*self.inner }.verify(gt, challenge, w).map_err(|e| e.to_string())
    }

    fn calculate_key(&mut self, args: <Slide as Api>::ArgsType) -> Result<String, String> {
        unsafe { &mut *self.inner }.calculate_key(args).map_err(|e| e.to_string())
    }
    fn generate_w(
        &self,
        key: &str,
        gt: &str,
        challenge: &str,
        c: &[u8],
        s: &str,
    ) -> Result<String, String> {
        unsafe {
            &*self.inner
        }.generate_w(key, gt, challenge, c, s)
            .map_err(|e| e.to_string())
    }

    fn test (&mut self, url: &str) -> Result<String, String> {
        unsafe { &mut *self.inner }.test(url).map_err(|e| e.to_string())
    }
}

#[repr(C)]
pub struct ClickFFI {
    inner: *mut Click,
}

impl ClickFFI {
    fn new() -> Self {
        ClickFFI {
            inner: Box::into_raw(Box::new(Click::default())),
        }
    }

    fn drop_inner(&mut self) {
        if !self.inner.is_null() {
            unsafe { let _ = Box::from_raw(self.inner); }
            self.inner = std::ptr::null_mut();
        }
    }

    fn register_test(&mut self, url: &str) -> Result<(String, String), String> {
        unsafe { &mut *self.inner }.register_test(url).map_err(|e| e.to_string())
    }

    fn get_c_s(
        &mut self,
        gt: &str,
        challenge: &str,
        w: Option<&str>,
    ) -> Result<(Vec<u8>, String), String> {
        unsafe { &mut *self.inner }.get_c_s(gt, challenge, w).map_err(|e| e.to_string())
    }

    fn get_type(&self, gt: &str, challenge: &str, w: Option<&str>) -> Result<String, String> {
        match unsafe { &*self.inner }.get_type(gt, challenge, w) {
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
        unsafe { &*self.inner }
            .get_new_c_s_args(gt, challenge)
            .map_err(|e| e.to_string())
    }

    fn verify(&self, gt: &str, challenge: &str, w: Option<&str>) -> Result<(String, String), String> {
        unsafe { &*self.inner }.verify(gt, challenge, w).map_err(|e| e.to_string())
    }

    fn calculate_key(&mut self, args: <Click as Api>::ArgsType) -> Result<String, String> {
        unsafe { &mut *self.inner }.calculate_key(args).map_err(|e| e.to_string())
    }

    fn generate_w(
        &self,
        key: &str,
        gt: &str,
        challenge: &str,
        c: &[u8],
        s: &str,
    ) -> Result<String, String> {
        unsafe { &*self.inner }
            .generate_w(key, gt, challenge, c, s)
            .map_err(|e| e.to_string())
    }

    fn test (&mut self, url: &str) -> Result<String, String> {
        unsafe { &mut *self.inner }.test(url).map_err(|e| e.to_string())
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe { let _ = CString::from_raw(s); }
}