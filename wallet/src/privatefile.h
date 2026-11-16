// Windows directory-relative open/owner-check portions adapted from Z23.
// Copyright 2026 Rhett Creighton. Licensed under Apache-2.0;
// see ../LICENSE-Z23-APACHE-2.0. Adaptation uses a consent-gated empty-DACL
// repair for a single file; it does not import Z23 consensus or chain state.
#ifndef ZCL_PRIVATEFILE_H
#define ZCL_PRIVATEFILE_H

#include <QFileDevice>
#include <QFileInfo>
#include <QDir>
#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
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

// Older Windows builds can leave a file with an empty DACL (denying everyone).
// Repair only that exact state, only for this process's owner, and never follow
// a reparse point. The caller must obtain the user's consent before repair=true.
inline bool ownerEmptyFileAcl(const QString& path, bool repair = false) {
#ifndef Q_OS_WIN
    Q_UNUSED(path);
    Q_UNUSED(repair);
    return false;
#else
    // Adapted from Z23's native directory-relative open/ownership pattern
    // (platform/modules/platform/src/positioned_file.c and state_root.c).
    // Win32 CreateFile implicitly requests data attributes; an empty DACL denies
    // that even to the owner. NtOpenFile requests only the owner's implicit
    // READ_CONTROL/WRITE_DAC rights, without granting any other account access.
    const QFileInfo target(QDir::cleanPath(path));
    const QString parent = QDir::toNativeSeparators(target.absolutePath());
    HANDLE directory = CreateFileW(reinterpret_cast<LPCWSTR>(parent.utf16()),
        FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (directory == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info;
    bool ok = GetFileInformationByHandle(directory, &info) &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
    typedef NTSTATUS (NTAPI *OpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                       PIO_STATUS_BLOCK, ULONG, ULONG);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto openFile = ntdll ? reinterpret_cast<OpenFile>(GetProcAddress(ntdll, "NtOpenFile")) : nullptr;
    QString leaf = target.fileName();
    ok = ok && openFile && !leaf.isEmpty() && leaf.size() <= 32767;
    HANDLE file = nullptr;
    if (ok) {
        UNICODE_STRING name;
        name.Length = name.MaximumLength = static_cast<USHORT>(leaf.size() * sizeof(WCHAR));
        name.Buffer = reinterpret_cast<PWSTR>(leaf.data());
        OBJECT_ATTRIBUTES attributes;
        // OBJ_DONT_REPARSE: reject links; FILE_NON_DIRECTORY_FILE: reject directories.
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | 0x1000,
                                   directory, nullptr);
        IO_STATUS_BLOCK status = {};
        ok = openFile(&file, READ_CONTROL | (repair ? WRITE_DAC : 0), &attributes,
            &status, FILE_SHARE_READ | FILE_SHARE_WRITE, 0x40 | 0x200000) >= 0;
    }
    CloseHandle(directory);
    if (!ok || !file) return false;
    HANDLE token = nullptr;
    union { TOKEN_USER user; BYTE bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]; } identity;
    DWORD size = 0;
    ok = ok && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    ok = ok && GetTokenInformation(token, TokenUser, &identity, sizeof(identity), &size);
    if (token) CloseHandle(token);
    PSID owner = nullptr;
    PACL oldAcl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD descriptorBytes = 0;
    const DWORD query = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    if (ok) GetKernelObjectSecurity(file, query, nullptr, 0, &descriptorBytes);
    ok = ok && descriptorBytes > 0 && descriptorBytes <= 65536;
    if (ok) descriptor = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LMEM_FIXED, descriptorBytes));
    BOOL defaulted = FALSE, present = FALSE;
    ok = ok && descriptor && GetKernelObjectSecurity(file, query, descriptor,
        descriptorBytes, &descriptorBytes) &&
        GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) &&
        GetSecurityDescriptorDacl(descriptor, &present, &oldAcl, &defaulted) && present;
    ok = ok && owner && EqualSid(owner, identity.user.User.Sid) &&
        oldAcl && IsValidAcl(oldAcl) && oldAcl->AceCount == 0;
    if (ok && repair) {
        alignas(DWORD) BYTE bytes[sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE];
        SECURITY_DESCRIPTOR replacement;
        auto acl = reinterpret_cast<PACL>(bytes);
        ok = InitializeAcl(acl, sizeof(bytes), ACL_REVISION) &&
            AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, identity.user.User.Sid) &&
            InitializeSecurityDescriptor(&replacement, SECURITY_DESCRIPTOR_REVISION) &&
            SetSecurityDescriptorDacl(&replacement, TRUE, acl, FALSE) &&
            SetKernelObjectSecurity(file,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, &replacement);
    }
    if (descriptor) LocalFree(descriptor);
    CloseHandle(file);
    return ok;
#endif
}

#endif
