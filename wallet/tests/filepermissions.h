#ifndef ZCL_TEST_FILEPERMISSIONS_H
#define ZCL_TEST_FILEPERMISSIONS_H

#include <QFile>
#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

// Check the actual platform access policy, not Qt's approximate POSIX flags
// on Windows. SYSTEM/Administrators have root-equivalent access; no other
// principal may read/write/execute the private data or change its access policy.
inline bool testFileIsOwnerOnly(const QString& path) {
#ifndef Q_OS_WIN
    const auto permissions = QFile::permissions(path);
    return permissions.testFlag(QFileDevice::ReadOwner) &&
           permissions.testFlag(QFileDevice::WriteOwner) &&
           !(permissions & (QFileDevice::ReadGroup | QFileDevice::WriteGroup |
                            QFileDevice::ReadOther | QFileDevice::WriteOther |
                            QFileDevice::ExeOwner));
#else
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    union {
        TOKEN_USER user;
        BYTE bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } identity;
    DWORD length = 0;
    const BOOL gotUser = GetTokenInformation(token, TokenUser, &identity,
                                            sizeof(identity), &length);
    CloseHandle(token);
    if (!gotUser) return false;
    BYTE system[SECURITY_MAX_SID_SIZE], admins[SECURITY_MAX_SID_SIZE];
    DWORD systemSize = sizeof(system), adminSize = sizeof(admins);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &systemSize) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins, &adminSize))
        return false;
    const auto name = reinterpret_cast<LPCWSTR>(path.utf16());
    DWORD descriptorSize = 0;
    GetFileSecurityW(name, DACL_SECURITY_INFORMATION, nullptr, 0, &descriptorSize);
    if (!descriptorSize) return false;
    auto descriptor = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LMEM_FIXED, descriptorSize));
    if (!descriptor) return false;
    PACL acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    bool ok = GetFileSecurityW(name, DACL_SECURITY_INFORMATION, descriptor,
                              descriptorSize, &descriptorSize) &&
              GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) &&
              present && acl && IsValidAcl(acl);
    const DWORD privateAccess = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA |
        FILE_EXECUTE | DELETE | WRITE_DAC | WRITE_OWNER |
        GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
    for (DWORD i = 0; ok && i < acl->AceCount; ++i) {
        void* entry = nullptr;
        if (!GetAce(acl, i, &entry)) { ok = false; break; }
        const auto header = static_cast<ACE_HEADER*>(entry);
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) { ok = false; break; }
        const auto allow = static_cast<ACCESS_ALLOWED_ACE*>(entry);
        if (!(allow->Mask & privateAccess)) continue;
        PSID sid = &allow->SidStart;
        ok = IsValidSid(sid) && (EqualSid(sid, identity.user.User.Sid) ||
             EqualSid(sid, system) || EqualSid(sid, admins));
    }
    if (descriptor) LocalFree(descriptor);
    // Also prove this user can read and write; an empty/deny-all ACL is not a pass.
    QFile file(path);
    return ok && file.open(QIODevice::ReadWrite);
#endif
}

#endif
