// Native directory-relative open/ownership pattern adapted from Z23.
// Copyright 2026 Rhett Creighton. Apache-2.0; see ../LICENSE-Z23-APACHE-2.0.
#include "startupaccess.h"
#include <QDir>
#include <QFileInfo>
#ifdef Q_OS_WIN
#include "privatefile.h"
#include <vector>
#include <cstddef>

namespace {
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

struct Walker {
    StartupAccessResult result;
    bool repair;
    std::function<bool(int, int)> progress;
    union { TOKEN_USER user; BYTE bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]; } identity;
    typedef NTSTATUS (NTAPI *OpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                       PIO_STATUS_BLOCK, ULONG, ULONG);
    OpenFile openFile = nullptr;

    bool fail(const QString& path, const QString& reason) {
        result.error = reason + "\n" + QDir::toNativeSeparators(path);
        return false;
    }

    bool initialize() {
        Handle token;
        DWORD size = 0;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value) ||
            !GetTokenInformation(token.value, TokenUser, &identity, sizeof(identity), &size))
            return fail(QString(), QObject::tr("Cannot identify the Windows account."));
        const HMODULE module = GetModuleHandleW(L"ntdll.dll");
        if (module) openFile = reinterpret_cast<OpenFile>(GetProcAddress(module, "NtOpenFile"));
        return openFile || fail(QString(), QObject::tr("Windows file-access inspection is unavailable."));
    }

    bool visit(HANDLE parent, QString leaf, const QString& display, bool directory, int depth) {
        if (progress && !progress(result.checked, result.repaired)) {
            result.cancelled = true;
            return false;
        }
        if (depth > 64 || result.checked >= 100000)
            return fail(display, QObject::tr("The access check reached its safety limit; no data was deleted."));
        if (leaf.isEmpty() || leaf == "." || leaf == ".." || leaf.size() > 32767 ||
            leaf.contains('/') || leaf.contains('\\') || leaf.contains(':'))
            return fail(display, QObject::tr("Unsupported file name; access was not changed."));
        UNICODE_STRING name;
        name.Length = name.MaximumLength = static_cast<USHORT>(leaf.size() * sizeof(WCHAR));
        name.Buffer = reinterpret_cast<PWSTR>(leaf.data());
        OBJECT_ATTRIBUTES attributes;
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | 0x1000,
                                   parent, nullptr); // OBJ_DONT_REPARSE
        IO_STATUS_BLOCK status = {};
        Handle item;
        const NTSTATUS opened = openFile(&item.value, READ_CONTROL,
            &attributes, &status, FILE_SHARE_READ | FILE_SHARE_WRITE,
            0x200000 | (directory ? 0x1 : 0x40)); // OPEN_REPARSE_POINT, DIRECTORY/NON_DIRECTORY
        if (static_cast<ULONG>(opened) == 0xc000050bUL) { // REPARSE_POINT_ENCOUNTERED
            ++result.skippedLinks;
            return true;
        }
        if (opened < 0)
            return fail(display, QObject::tr("Windows would not allow inspection of this existing file."));
        ++result.checked;

        DWORD bytes = 0;
        const DWORD query = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        GetKernelObjectSecurity(item.value, query, nullptr, 0, &bytes);
        if (!bytes || bytes > 65536)
            return fail(display, QObject::tr("Cannot read the existing access rules."));
        std::vector<BYTE> storage(bytes);
        auto sd = reinterpret_cast<PSECURITY_DESCRIPTOR>(storage.data());
        PSID owner = nullptr;
        PACL acl = nullptr;
        BOOL present = FALSE, defaulted = FALSE;
        if (!GetKernelObjectSecurity(item.value, query, sd, bytes, &bytes) ||
            !GetSecurityDescriptorOwner(sd, &owner, &defaulted) ||
            !GetSecurityDescriptorDacl(sd, &present, &acl, &defaulted))
            return fail(display, QObject::tr("Cannot read the existing access rules."));
        // Recognize only the legacy private-directory pattern: owner (+ optional
        // SYSTEM), full access, no inherited/deny/custom ACEs, no inheritance.
        // Without inheritable rights, newly created daemon files get empty ACLs.
        int ownerAce = -1;
        bool missingInheritance = directory && present && acl && IsValidAcl(acl) &&
            acl->AceCount > 0 && acl->AceCount <= 2 && owner && EqualSid(owner, identity.user.User.Sid);
        BYTE system[SECURITY_MAX_SID_SIZE];
        DWORD systemBytes = sizeof(system);
        missingInheritance = missingInheritance && CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &systemBytes);
        for (DWORD i = 0; missingInheritance && i < acl->AceCount; ++i) {
            void* raw = nullptr;
            if (!GetAce(acl, i, &raw)) { missingInheritance = false; break; }
            const auto header = static_cast<ACE_HEADER*>(raw);
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0) {
                missingInheritance = false; break;
            }
            const auto allow = static_cast<ACCESS_ALLOWED_ACE*>(raw);
            if (header->AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8 ||
                !IsValidSid(&allow->SidStart) ||
                GetLengthSid(&allow->SidStart) > header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart) ||
                allow->Mask != FILE_ALL_ACCESS) { missingInheritance = false; break; }
            if (EqualSid(&allow->SidStart, identity.user.User.Sid)) ownerAce = int(i);
            else if (!EqualSid(&allow->SidStart, system)) missingInheritance = false;
        }
        missingInheritance = missingInheritance && ownerAce >= 0;
        const bool emptyAcl = present && acl && IsValidAcl(acl) && acl->AceCount == 0;
        // Null DACLs and arbitrary nonempty policies are left untouched.
        if (emptyAcl || missingInheritance) {
            if (!owner || !EqualSid(owner, identity.user.User.Sid))
                return fail(display, QObject::tr("This blocked file belongs to a different Windows account. Its access was not changed."));
            ++result.repairable;
            if (!repair && emptyAcl) return true; // An inaccessible directory is opaque until consent.
            if (repair) {
            // The first handle pins this directory entry against rename/replacement.
            Handle writable;
            if (openFile(&writable.value, READ_CONTROL | WRITE_DAC, &attributes, &status,
                FILE_SHARE_READ | FILE_SHARE_WRITE, 0x200000 | (directory ? 0x1 : 0x40)) < 0)
                return fail(display, QObject::tr("Windows would not allow this access repair."));
            // Another owner process may change metadata even while the entry is
            // pinned. Stop rather than overwrite a policy changed since inspection.
            std::vector<BYTE> current(storage.size());
            DWORD currentBytes = 0;
            if (!GetKernelObjectSecurity(writable.value, query, current.data(), DWORD(current.size()), &currentBytes) ||
                currentBytes != bytes || memcmp(current.data(), storage.data(), bytes) != 0)
                return fail(display, QObject::tr("Access rules changed during the check. Please try again."));
            std::vector<BYTE> buffer(missingInheritance ? acl->AclSize :
                sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE);
            auto replacement = reinterpret_cast<PACL>(buffer.data());
            bool prepared = false;
            if (missingInheritance) {
                memcpy(replacement, acl, acl->AclSize);
                void* raw = nullptr;
                prepared = GetAce(replacement, DWORD(ownerAce), &raw);
                if (prepared) static_cast<ACE_HEADER*>(raw)->AceFlags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
            } else {
                prepared = InitializeAcl(replacement, DWORD(buffer.size()), ACL_REVISION) &&
                    AddAccessAllowedAceEx(replacement, ACL_REVISION,
                        directory ? OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE : 0,
                        FILE_ALL_ACCESS, identity.user.User.Sid);
            }
            SECURITY_DESCRIPTOR descriptor;
            if (!prepared ||
                !InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
                !SetSecurityDescriptorDacl(&descriptor, TRUE, replacement, FALSE) ||
                !SetKernelObjectSecurity(writable.value,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, &descriptor))
                return fail(display, QObject::tr("Windows could not restore access. File contents were not changed."));
            ++result.repaired;
            }
        }
        if (!directory) return true;

        // Retain the directory handle (no delete sharing) throughout recursion.
        // Every child is opened relative to it, never through a reconstructed path.
        Handle listing;
        if (openFile(&listing.value, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                &attributes, &status, FILE_SHARE_READ | FILE_SHARE_WRITE,
                0x200000 | 0x1 | 0x20) < 0) // Directory, no reparse, synchronous enumeration.
            return fail(display, QObject::tr("Cannot inspect this folder. Custom access rules were left unchanged."));
        std::vector<BYTE> entries(65536);
        bool first = true;
        while (true) {
            if (!GetFileInformationByHandleEx(listing.value,
                    first ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo,
                    entries.data(), DWORD(entries.size()))) {
                if (GetLastError() == ERROR_NO_MORE_FILES) return true;
                return fail(display, QObject::tr("Windows could not finish checking this folder."));
            }
            first = false;
            size_t offset = 0;
            while (true) {
                const size_t prefix = offsetof(FILE_ID_BOTH_DIR_INFO, FileName);
                if (offset > entries.size() - prefix)
                    return fail(display, QObject::tr("Invalid directory information returned by Windows."));
                auto entry = reinterpret_cast<FILE_ID_BOTH_DIR_INFO*>(entries.data() + offset);
                if (entry->FileNameLength % sizeof(WCHAR) || entry->FileNameLength > entries.size() - offset - prefix)
                    return fail(display, QObject::tr("Invalid directory information returned by Windows."));
                const QString child = QString::fromWCharArray(entry->FileName, int(entry->FileNameLength / sizeof(WCHAR)));
                if (child != "." && child != "..") {
                    if (entry->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ++result.skippedLinks;
                    else if (!visit(listing.value, child, display + '/' + child,
                                    entry->FileAttributes & FILE_ATTRIBUTE_DIRECTORY, depth + 1)) return false;
                }
                if (!entry->NextEntryOffset) break;
                if (entry->NextEntryOffset < prefix || entry->NextEntryOffset > entries.size() - offset)
                    return fail(display, QObject::tr("Invalid directory information returned by Windows."));
                offset += entry->NextEntryOffset;
            }
        }
    }

    bool root(const QString& path) {
        const QFileInfo target(QDir::cleanPath(path));
        if (!target.exists() && !target.isSymLink()) return true;
        const QString parentPath = QDir::toNativeSeparators(target.absolutePath());
        Handle parent;
        parent.value = CreateFileW(reinterpret_cast<LPCWSTR>(parentPath.utf16()),
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        BY_HANDLE_FILE_INFORMATION info;
        if (parent.value == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(parent.value, &info) ||
            !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            return fail(path, QObject::tr("Cannot safely inspect the parent of this data folder."));
        return visit(parent.value, target.fileName(), target.absoluteFilePath(), target.isDir(), 0);
    }
};
}
#endif

StartupAccessResult checkStartupAccess(const QStringList& roots, bool repair,
    const std::function<bool(int, int)>& progress) {
#ifdef Q_OS_WIN
    Walker walker;
    walker.repair = repair;
    walker.progress = progress;
    if (walker.initialize()) for (const auto& root : roots) if (!walker.root(root)) break;
    return walker.result;
#else
    Q_UNUSED(roots); Q_UNUSED(repair); Q_UNUSED(progress);
    return {};
#endif
}
