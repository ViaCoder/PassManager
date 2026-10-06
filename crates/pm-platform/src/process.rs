//! 进程级加固、降权、客户端身份查询。

#[cfg(unix)]
use std::io;

/// 禁用 core dump，禁止同用户进程调试（Linux：PR_SET_DUMPABLE=0）。
pub fn harden_process() {
    #[cfg(unix)]
    {
        let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    }
    #[cfg(target_os = "linux")]
    // SAFETY: prctl 只修改本进程属性。
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// 立即、不可逆地降权到指定用户（macOS 服务在 root 阶段读取设备密钥后调用）。
#[cfg(unix)]
pub fn drop_privileges(user: &str) -> io::Result<()> {
    let u = nix::unistd::User::from_name(user)
        .map_err(io::Error::from)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("user {user} not found")))?;
    let gid = u.gid.as_raw();
    let uid = u.uid.as_raw();
    // SAFETY: 标准降权序列：先清附加组，再 setgid，最后 setuid。
    unsafe {
        let groups = [gid as libc::gid_t];
        if libc::setgroups(1, groups.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setgid(gid as libc::gid_t) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setuid(uid as libc::uid_t) != 0 {
            return Err(io::Error::last_os_error());
        }
        // 必须无法重新取得 root。
        if libc::setuid(0) == 0 || libc::geteuid() == 0 {
            return Err(io::Error::other("privilege drop verification failed"));
        }
    }
    Ok(())
}

/// 当前进程是否以 root/管理员身份运行。
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(windows)]
    {
        win::current_token_elevated().unwrap_or(false)
    }
}

/// 当前用户 SID（Windows）。
#[cfg(windows)]
pub fn current_user_sid() -> Option<String> {
    win::current_user_sid()
}

#[cfg(windows)]
pub mod win {
    use std::ffi::c_void;

    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
    };
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::core::{HSTRING, PWSTR};

    fn token_info(token: HANDLE) -> Option<(bool, String)> {
        // SAFETY: 缓冲区大小由第一次调用返回。
        unsafe {
            let mut elev = TOKEN_ELEVATION::default();
            let mut len = 0u32;
            GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elev as *mut _ as *mut c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            )
            .ok()?;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr() as *mut c_void), len, &mut len).ok()?;
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut s = PWSTR::null();
            ConvertSidToStringSidW(tu.User.Sid, &mut s).ok()?;
            let sid = s.to_string().ok()?;
            let _ = LocalFree(Some(HLOCAL(s.0 as *mut c_void)));
            Some((elev.TokenIsElevated != 0, sid))
        }
    }

    pub fn current_token_elevated() -> Option<bool> {
        current_info().map(|x| x.0)
    }

    pub fn current_user_sid() -> Option<String> {
        current_info().map(|x| x.1)
    }

    fn current_info() -> Option<(bool, String)> {
        // SAFETY: 伪句柄无需关闭；token 句柄使用后关闭。
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
            let r = token_info(token);
            let _ = CloseHandle(token);
            r
        }
    }

    /// 命名管道客户端：(是否提权, 用户 SID)。
    pub fn pipe_client(pipe: HANDLE) -> Option<(bool, String)> {
        // SAFETY: 句柄均在使用后关闭。
        unsafe {
            let mut pid = 0u32;
            GetNamedPipeClientProcessId(pipe, &mut pid).ok()?;
            let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut token = HANDLE::default();
            let ok = OpenProcessToken(proc, TOKEN_QUERY, &mut token).is_ok();
            let r = if ok { token_info(token) } else { None };
            if ok {
                let _ = CloseHandle(token);
            }
            let _ = CloseHandle(proc);
            r
        }
    }

    /// 由 SDDL 构造的安全属性（用于创建命名管道）。
    pub struct SecAttrs {
        pub attrs: SECURITY_ATTRIBUTES,
        sd: PSECURITY_DESCRIPTOR,
    }

    impl SecAttrs {
        pub fn from_sddl(sddl: &str) -> std::io::Result<Self> {
            let mut sd = PSECURITY_DESCRIPTOR::default();
            // SAFETY: 输出的描述符由系统分配，在 Drop 中释放。
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(&HSTRING::from(sddl), SDDL_REVISION_1, &mut sd, None)
                    .map_err(|e| std::io::Error::other(format!("SDDL: {e}")))?;
            }
            Ok(Self {
                attrs: SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: sd.0,
                    bInheritHandle: false.into(),
                },
                sd,
            })
        }

        pub fn as_ptr(&mut self) -> *mut c_void {
            &mut self.attrs as *mut _ as *mut c_void
        }
    }

    impl Drop for SecAttrs {
        fn drop(&mut self) {
            // SAFETY: sd 由 ConvertStringSecurityDescriptorToSecurityDescriptorW 分配。
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.sd.0)));
            }
        }
    }

    // SAFETY: 只在创建管道时读取，不跨线程修改。
    unsafe impl Send for SecAttrs {}
}
