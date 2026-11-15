#ifndef ZCL_PRIVATEFILE_H
#define ZCL_PRIVATEFILE_H

#include <QFileDevice>
#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#endif

// Restrict an OPEN file before writing private bytes. Works on QSaveFile's
// temporary file by handle, so an atomic replacement retains the private ACL.
inline bool makeFileOwnerOnly(QFileDevice& file) {
#ifndef Q_OS_WIN
    return file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#else
    if (!file.isOpen() || file.handle() < 0) return false;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    union {
        TOKEN_USER user;
        BYTE bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } identity;
    DWORD size = 0;
    const BOOL gotUser = GetTokenInformation(token, TokenUser, &identity,
                                            sizeof(identity), &size);
    CloseHandle(token);
    if (!gotUser) return false;
    alignas(DWORD) BYTE bytes[sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE];
    auto acl = reinterpret_cast<PACL>(bytes);
    SECURITY_DESCRIPTOR descriptor;
    if (!InitializeAcl(acl, sizeof(bytes), ACL_REVISION) ||
        !AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, identity.user.User.Sid) ||
        !InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE))
        return false;
    const auto raw = reinterpret_cast<HANDLE>(_get_osfhandle(file.handle()));
    // Request WRITE_DAC on the same file object, not a path that could be replaced.
    HANDLE security = ReOpenFile(raw, WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
    if (security == INVALID_HANDLE_VALUE) return false;
    const BOOL ok = SetKernelObjectSecurity(security,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, &descriptor);
    CloseHandle(security);
    return ok;
#endif
}

#endif
