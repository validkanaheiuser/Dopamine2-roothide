#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/runtime.h>
#include <os/log.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/mount.h>

// Diagnostic logger for Apple Unified Logging (idevicesyslog / log stream)
// Uses OS_LOG_TYPE_DEFAULT (<Notice>) with %{public}s to prevent <private> redaction
static inline void rh_log(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "[RHHIDE] %{public}s", buf);
}
#define RH_LOG(fmt, ...) rh_log(fmt, ##__VA_ARGS__)

// BSDPMRHide (0x80600 in blueshield.framework) is a canary/honeypot ObjC class
// designed by Singalarity BlueShield to detect ObjC hook frameworks
// (DOPAMINE_WEAKNESS.md §3A, Layer A).
//
// How detection works:
//   ElleKit / CydiaSubstrate hook ObjC methods by calling class_getInstanceMethod()
//   and class_getClassMethod() to obtain a Method pointer, then calling
//   method_setImplementation() on it. BlueShield compares BSDPMRHide's live IMP
//   table against a reference snapshot; a modified IMP signals a bypass tweak is
//   active and triggers error 505000 (reason=5).
//
// Fix: intercept class_getInstanceMethod and class_getClassMethod for "BSDPMRHide"
//   and return NULL. ElleKit never obtains a Method pointer for the canary class,
//   so method_setImplementation is never called on it and the IMP table stays intact.
//
// Why MSHookFunction (not litehook):
//   litehook performs instruction replacement with NO trampoline, so the hook
//   function cannot call the original. MSHookFunction (provided by ElleKit /
//   CydiaSubstrate) writes a trampoline that lets replaced_* call orig_*.
//   roothidehooks.dylib already links against CydiaSubstrate (see Makefile).
//
// Timing:
//   canaryBypassInit() is called from roothider_main.c's blacklist check block,
//   which runs inside systemhook.dylib's constructor — BEFORE blueshield.framework
//   loads (static deps of the host app initialize after DYLD_INSERT_LIBRARIES dylibs).
//   When ElleKit's _dyld_register_func_for_add_image callback fires for
//   blueshield.framework and tries to hook BSDPMRHide, our hook is already in place.
//   TweakLoader (and the tweaks it loads) also runs after this point.

static Method (*orig_class_getInstanceMethod)(Class cls, SEL sel) = NULL;

static Method replaced_class_getInstanceMethod(Class cls, SEL sel)
{
	if (cls && strcmp(class_getName(cls), "BSDPMRHide") == 0) return NULL;
	return orig_class_getInstanceMethod(cls, sel);
}

static Method (*orig_class_getClassMethod)(Class cls, SEL sel) = NULL;

static Method replaced_class_getClassMethod(Class cls, SEL sel)
{
	if (cls && strcmp(class_getName(cls), "BSDPMRHide") == 0) return NULL;
	return orig_class_getClassMethod(cls, sel);
}

__attribute__((visibility("default"))) void canaryBypassInit(void)
{
	MSHookFunction((void *)class_getInstanceMethod,
	               (void *)replaced_class_getInstanceMethod,
	               (void **)&orig_class_getInstanceMethod);
	MSHookFunction((void *)class_getClassMethod,
	               (void *)replaced_class_getClassMethod,
	               (void **)&orig_class_getClassMethod);
}

// ─── RuntimeHookChecker bypass: method_getImplementation intercept ────────────
//
// _TtC9MBRaspSdk18RuntimeHookChecker (DOPAMINE_WEAKNESS_3.md §B.1) calls
// class_getInstanceMethod + method_getImplementation to read each ObjC method's
// IMP, then checks whether that IMP falls within the __TEXT segment of a
// recognised system framework. Any IMP pointing outside those ranges (e.g. into
// roothidehooks.dylib) triggers reason=5.
//
// We hook via MSHookMessageEx:
//   +[OSLogStore localStoreAndReturnError:]  → replaced_localStoreAndReturnError
//   -[NSFileManager fileExistsAtPath:]       → replaced_fileExistsAtPath
//   -[NSFileManager fileExistsAtPath:isDirectory:] → replaced_fileExistsAtPathIsDirectory
//   -[NSFileManager contentsOfDirectoryAtPath:error:] → replaced_contentsOfDirectoryAtPath
//   -[NSFileManager isReadableFileAtPath:]   → replaced_isReadableFileAtPath
//
// After each MSHookMessageEx the method table entry has our IMP. When
// RuntimeHookChecker calls method_getImplementation(m) for those methods it
// would see our IMP (in roothidehooks.dylib __TEXT) and fire.
//
// Fix: hook method_getImplementation via MSHookFunction to return stored
// original IMPs for methods we have hooked, making RuntimeHookChecker see the
// original Foundation IMP (inside __TEXT of Foundation/libsystem) instead.
//
// Implementation notes:
//   - We record Method → origImp pairs into a small fixed array after each
//     MSHookMessageEx call (Method pointer is stable across the hook).
//   - method_getImplementation hook must be installed BEFORE any MSHookMessageEx
//     call so that it is active when RuntimeHookChecker later queries those methods.
//   - RH_HOOKED_METHOD_MAX = 8 covers all current hooks with headroom.

#define RH_HOOKED_METHOD_MAX 8
static Method  s_rh_methods[RH_HOOKED_METHOD_MAX];
static IMP     s_rh_orig_imps[RH_HOOKED_METHOD_MAX];
static int     s_rh_method_count = 0;

static void rh_record_method(Method m, IMP origImp) {
    if (!m || s_rh_method_count >= RH_HOOKED_METHOD_MAX) return;
    s_rh_methods[s_rh_method_count] = m;
    s_rh_orig_imps[s_rh_method_count] = origImp;
    s_rh_method_count++;
}

static IMP (*orig_method_getImplementation)(Method m) = NULL;

static IMP replaced_method_getImplementation(Method m) {
    if (m) {
        for (int i = 0; i < s_rh_method_count; i++) {
            if (s_rh_methods[i] == m) {
                return s_rh_orig_imps[i];
            }
        }
    }
    return orig_method_getImplementation(m);
}

// ─── BSLogCek + BSZInspection + cekL3Int ObjC-layer bypass ──────────────────
//
// BSLogCek (0x38a00 in blueshield.framework, DOPAMINE_WEAKNESS_2.md reason=0):
//   Uses +[OSLogStore localStoreAndReturnError:] to open the system log store,
//   then iterates log entries checking composedMessage for jailbreak daemon strings.
//   Evidence: blueshield.framework imports _OBJC_CLASS_$_OSLogStore (GOT 0x8d678)
//   and _OBJC_CLASS_$_OSLogEntryLog (GOT 0x8d670); composedMessage selector at
//   0x69974 is used in the BSLogCek.apply function (IDA instance ab0m, base 0x0).
//   Hook: return nil from localStoreAndReturnError: → BSLogCek receives no log
//   store → enumerates zero entries → finds no jailbreak evidence.
//
//   Additional context: iOS sandbox policy restricts third-party apps to reading
//   only their own log entries since iOS 14.5 (requires com.apple.log-utility
//   private entitlement for cross-process log reads). BSLogCek's log scan would
//   likely be empty even without this hook. The hook provides a hard guarantee.
//   OSLogStore availability guard: objc_getMetaClass("OSLogStore") returns NULL
//   on iOS <15 where OSLogStore is absent → MSHookMessageEx skipped safely.
//
// BSZInspection (0x5848 / 0x610c, DOPAMINE_WEAKNESS_2.md reason=0):
//   Scans for Zebra/Zim jailbreak framework files and root partition structure.
//   If it uses NSFileManager.fileExistsAtPath:, these hooks intercept it and
//   return NO for all jailbreak-indicating paths.
//
// cekL3Int (0x32d9c, DOPAMINE_WEAKNESS_2.md reason=0):
//   Reads package manager metadata (dpkg/apt). If it uses NSFileManager for
//   directory/file existence checks (e.g. checking for dpkg status file), these
//   hooks intercept it.
//
// Path pattern rationale: strstr-based matching works for both /var/jb/-prefixed
// paths (bind-mount) and direct jbroot paths (.jbroot-XXXX/var/lib/dpkg/status
// still contains the substring /var/lib/dpkg/). All patterns are jailbreak-
// specific and have no legitimate use in a banking app.
//
// RUNTIME NOTE on stat()/opendir(): NSFileManager internally calls stat64() for
// fileExistsAtPath: on modern iOS. The hooks here intercept the ObjC API layer.
// If BSZInspection or cekL3Int bypass NSFileManager and call access() directly,
// hook_access in roothider_main.c provides POSIX-layer coverage for known paths.
// hook_open() was removed (MSHookFunctionChecker conflict). stat() at the raw
// syscall level is not hooked.

static const char *const kJailbreakPathPatterns[] = {
    "/var/jb/",                    // any /var/jb/ bind-mount path
    "/var/lib/dpkg/",              // dpkg package database (cekL3Int)
    "/var/lib/apt/",               // apt package lists (cekL3Int)
    "/Applications/Cydia.app",     // Cydia package manager
    "/Applications/Zebra.app",     // Zebra package manager
    "/Applications/Sileo.app",     // Sileo package manager
    "/usr/share/zebra/",           // Zebra data directory
    NULL
};

// Exact-match blocklist for Walmart RASP (FraudForce + PerimeterX).
// FraudForce calls fopen() and PerimeterX calls NSFileManager on these paths
// WITHOUT a trailing slash — strstr patterns above do not match them.
// Safe to use strcmp: none of these are legitimate app file I/O targets,
// and ElleKit scans /usr/lib/TweakInject/ subdirs via open()/access(), not fopen().
static const char *const kWalmartBlockedExactPaths[] = {
    "/usr/lib/TweakInject",
    "/usr/lib/substrate",
    "/etc/apt",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/usr/sbin/sshd",
    "/bin/bash",
    "/usr/lib/roothideinit.dylib",
    "/usr/lib/libjailbreak.dylib",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/libcycript.dylib",
    "/usr/sbin/frida-server",
    "/usr/libexec/cydia",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    NULL
};

static bool jailbreakBypassShouldBlockPath(NSString *path) {
    if (!path) return false;
    const char *cpath = [path UTF8String];
    if (!cpath) return false;
    for (int i = 0; kWalmartBlockedExactPaths[i]; i++) {
        if (strcmp(cpath, kWalmartBlockedExactPaths[i]) == 0) return true;
    }
    for (int i = 0; kJailbreakPathPatterns[i]; i++) {
        if (strstr(cpath, kJailbreakPathPatterns[i])) return true;
    }
    return false;
}

static id (*orig_localStoreAndReturnError)(Class cls, SEL sel, NSError **error) = NULL;

static id replaced_localStoreAndReturnError(Class cls, SEL sel, NSError **error) {
    RH_LOG("BSLogCek: OSLogStore.localStore blocked");
    if (error) *error = nil;
    return nil;
}

static BOOL (*orig_fileExistsAtPath)(id self, SEL sel, NSString *path) = NULL;

static BOOL replaced_fileExistsAtPath(id self, SEL sel, NSString *path) {
    if (jailbreakBypassShouldBlockPath(path)) {
        RH_LOG("NSFileMgr.fileExistsAtPath BLOCKED: %s", [path UTF8String] ?: "");
        return NO;
    }
    BOOL ret = orig_fileExistsAtPath(self, sel, path);
    if (ret) RH_LOG("NSFileMgr.fileExistsAtPath PASS(YES): %s", [path UTF8String] ?: "");
    return ret;
}

static BOOL (*orig_fileExistsAtPathIsDirectory)(id self, SEL sel, NSString *path, BOOL *isDirectory) = NULL;

static BOOL replaced_fileExistsAtPathIsDirectory(id self, SEL sel, NSString *path, BOOL *isDirectory) {
    if (jailbreakBypassShouldBlockPath(path)) {
        RH_LOG("NSFileMgr.fileExistsAtPath:isDirectory: BLOCKED: %s", [path UTF8String] ?: "");
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    BOOL ret = orig_fileExistsAtPathIsDirectory(self, sel, path, isDirectory);
    if (ret) RH_LOG("NSFileMgr.fileExistsAtPath:isDir: PASS(YES): %s", [path UTF8String] ?: "");
    return ret;
}

static BOOL (*orig_isReadableFileAtPath)(id self, SEL sel, NSString *path) = NULL;

static BOOL replaced_isReadableFileAtPath(id self, SEL sel, NSString *path) {
    if (jailbreakBypassShouldBlockPath(path)) {
        RH_LOG("NSFileMgr.isReadableFileAtPath BLOCKED: %s", [path UTF8String] ?: "");
        return NO;
    }
    BOOL ret = orig_isReadableFileAtPath(self, sel, path);
    if (ret) RH_LOG("NSFileMgr.isReadableFileAtPath PASS(YES): %s", [path UTF8String] ?: "");
    return ret;
}

// +[MC1 getAllFramworks] (0x20394, blueshield.framework) calls
// -[NSFileManager contentsOfDirectoryAtPath:error:] to list the app's
// /Frameworks directory after c1Available != 0 (detection already fired).
// It collects the result as evidence for the threat payload. Hooking here
// cannot prevent detection (getAllFramworks is called post-detection), but
// filters any jailbreak-named entries from the reported snapshot.
//
// RUNTIME NOTE: Dopamine injects dylibs via DYLD_INSERT_LIBRARIES; they are
// NOT placed in the app's /Frameworks directory. This hook will never filter
// anything in practice (no jailbreak entry exists there). It is defensive only,
// guarding against future injection methods that might use the Frameworks path.
//
// RuntimeHookChecker bypass: this method is also recorded in the
// method_getImplementation registry (rh_record_method) so that RuntimeHookChecker
// sees the original Foundation IMP, not our replacement IMP in roothidehooks.dylib.

// ─── fopen bypass: FraudForce filesystem path checks ─────────────────────────
//
// FraudForce.framework (Walmart v26.34) does NOT import _access. It checks
// jailbreak path existence via fopen(path, "r"). If fopen returns non-NULL,
// the file/dir exists → jailbreak detected.
//
// We hook fopen via MSHookFunction (trampoline needed to call orig for non-blocked
// paths). Blocked paths return NULL with errno=ENOENT, matching what would happen
// on a stock device where these paths do not exist.
//
// Note: fopen on a directory path returns NULL (EISDIR) on stock iOS already;
// blocking it here is consistent behavior and not observable by the app.

static FILE *(*orig_fopen)(const char *path, const char *mode) = NULL;

static FILE *replaced_fopen(const char *path, const char *mode) {
    if (path) {
        for (int i = 0; kWalmartBlockedExactPaths[i]; i++) {
            if (strcmp(path, kWalmartBlockedExactPaths[i]) == 0) {
                RH_LOG("fopen BLOCKED(exact): %s", path);
                errno = ENOENT;
                return NULL;
            }
        }
        for (int i = 0; kJailbreakPathPatterns[i]; i++) {
            if (strstr(path, kJailbreakPathPatterns[i])) {
                RH_LOG("fopen BLOCKED(pattern): %s", path);
                errno = ENOENT;
                return NULL;
            }
        }
    }
    return orig_fopen(path, mode);
}

static NSArray *(*orig_contentsOfDirectoryAtPath)(id self, SEL sel, NSString *path, NSError **err) = NULL;

static NSArray *replaced_contentsOfDirectoryAtPath(id self, SEL sel, NSString *path, NSError **err) {
    NSArray *result = orig_contentsOfDirectoryAtPath(self, sel, path, err);
    RH_LOG("NSFileMgr.contentsOfDirectoryAtPath: %s count=%d", [path UTF8String] ?: "", (int)[result count]);
    if (!result || [result count] == 0) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:[result count]];
    for (NSString *entry in result) {
        if (!jailbreakBypassShouldBlockPath(entry)) {
            [filtered addObject:entry];
        }
    }
    return [filtered copy];
}

__attribute__((visibility("default"))) void logScanBypassInit(void)
{
    RH_LOG("logScanBypassInit called");

    // ── RuntimeHookChecker bypass: install method_getImplementation hook first ──
    // Must be installed before any MSHookMessageEx so it is in place when
    // _TtC9MBRaspSdk18RuntimeHookChecker later calls method_getImplementation.
    // For every method we hook below, we capture the Method pointer before the
    // hook and the original IMP after, then record them with rh_record_method.
    // RuntimeHookChecker sees the original Foundation IMP → valid __TEXT range.
    MSHookFunction((void *)method_getImplementation,
                   (void *)replaced_method_getImplementation,
                   (void **)&orig_method_getImplementation);
    RH_LOG("method_getImplementation hooked (RuntimeHookChecker bypass)");

    // ── FishHookChecker safety note ──────────────────────────────────────────
    // _TtC9MBRaspSdk15FishHookChecker scans __DATA.__la_symbol_ptr and
    // __nl_symbol_ptr for symbol rebinding outside dyld_shared_cache.
    // RUNTIME NOTE: all our hooks use litehook (instruction replacement) or
    // MSHookFunction (trampoline in original function body). Neither approach
    // rebinds lazy or non-lazy symbol pointers in __DATA. FishHookChecker will
    // find no rebound pointers and report clean. No bypass needed.

    // ── Hook +[OSLogStore localStoreAndReturnError:] → nil: disables BSLogCek ─
    Class osLogStoreMeta = objc_getMetaClass("OSLogStore");
    RH_LOG("OSLogStore metaclass=%p", osLogStoreMeta);
    if (osLogStoreMeta) {
        Method m_ols = class_getInstanceMethod(osLogStoreMeta,
                                               @selector(localStoreAndReturnError:));
        MSHookMessageEx(osLogStoreMeta,
                        @selector(localStoreAndReturnError:),
                        (IMP)replaced_localStoreAndReturnError,
                        (IMP *)&orig_localStoreAndReturnError);
        rh_record_method(m_ols, (IMP)orig_localStoreAndReturnError);
        RH_LOG("OSLogStore.localStoreAndReturnError hooked, orig=%p", (void *)orig_localStoreAndReturnError);
    }

    // ── Hook fopen to block FraudForce filesystem checks (Walmart RASP) ─────
    // FraudForce does NOT import access(). It calls fopen(path, "r") on each
    // jailbreak path from its 35-entry blacklist (binary-verified, Walmart v26.34).
    // orig_fopen trampoline forwards non-blocked calls to the real fopen.
    MSHookFunction((void *)fopen,
                   (void *)replaced_fopen,
                   (void **)&orig_fopen);
    RH_LOG("fopen hooked (FraudForce bypass), orig=%p", (void *)orig_fopen);

    // ── Hook NSFileManager file-existence checks ──────────────────────────────
    // Covers BSZInspection Zebra/Zim scan and cekL3Int package metadata reads.
    // Also covers PerimeterX which calls fileExistsAtPath: on Walmart blacklist
    // paths. jailbreakBypassShouldBlockPath now checks kWalmartBlockedExactPaths
    // (exact strcmp) in addition to kJailbreakPathPatterns (strstr).
    {
        Method m_fep = class_getInstanceMethod([NSFileManager class],
                                               @selector(fileExistsAtPath:));
        MSHookMessageEx([NSFileManager class],
                        @selector(fileExistsAtPath:),
                        (IMP)replaced_fileExistsAtPath,
                        (IMP *)&orig_fileExistsAtPath);
        rh_record_method(m_fep, (IMP)orig_fileExistsAtPath);
        RH_LOG("NSFileManager.fileExistsAtPath: hooked, orig=%p", (void *)orig_fileExistsAtPath);
    }
    {
        Method m_fepid = class_getInstanceMethod([NSFileManager class],
                                                 @selector(fileExistsAtPath:isDirectory:));
        MSHookMessageEx([NSFileManager class],
                        @selector(fileExistsAtPath:isDirectory:),
                        (IMP)replaced_fileExistsAtPathIsDirectory,
                        (IMP *)&orig_fileExistsAtPathIsDirectory);
        rh_record_method(m_fepid, (IMP)orig_fileExistsAtPathIsDirectory);
        RH_LOG("NSFileManager.fileExistsAtPath:isDirectory: hooked, orig=%p",
               (void *)orig_fileExistsAtPathIsDirectory);
    }
    // ── Hook NSFileManager isReadableFileAtPath: ──────────────────────────────
    // cekL1Int (BSHasApp) in BlueShield uses an obfuscated NSFileManager selector
    // to check each path in its input array. MBRaspSdk sub_12410 uses the same
    // SCP_StrDeobf pattern with isReadableFileAtPath:. Hooking it here closes the
    // gap: /var/jb/... paths that exist on Dopamine rootless return NO instead of YES.
    {
        Method m_rfap = class_getInstanceMethod([NSFileManager class],
                                               @selector(isReadableFileAtPath:));
        MSHookMessageEx([NSFileManager class],
                        @selector(isReadableFileAtPath:),
                        (IMP)replaced_isReadableFileAtPath,
                        (IMP *)&orig_isReadableFileAtPath);
        rh_record_method(m_rfap, (IMP)orig_isReadableFileAtPath);
        RH_LOG("NSFileManager.isReadableFileAtPath: hooked, orig=%p", (void *)orig_isReadableFileAtPath);
    }

    // ── Hook NSFileManager contentsOfDirectoryAtPath:error: ──────────────────
    // Defensive: +[MC1 getAllFramworks] (0x20394) calls this to list the app's
    // /Frameworks directory after detection. Jailbreak dylibs are NOT in the
    // Frameworks dir (injected via DYLD_INSERT_LIBRARIES), so this will not
    // filter anything in practice. Recorded for RuntimeHookChecker bypass.
    {
        Method m_coddap = class_getInstanceMethod([NSFileManager class],
                                                  @selector(contentsOfDirectoryAtPath:error:));
        MSHookMessageEx([NSFileManager class],
                        @selector(contentsOfDirectoryAtPath:error:),
                        (IMP)replaced_contentsOfDirectoryAtPath,
                        (IMP *)&orig_contentsOfDirectoryAtPath);
        rh_record_method(m_coddap, (IMP)orig_contentsOfDirectoryAtPath);
        RH_LOG("NSFileManager.contentsOfDirectoryAtPath:error: hooked, orig=%p",
               (void *)orig_contentsOfDirectoryAtPath);
    }

    RH_LOG("logScanBypassInit complete, recorded %d methods", s_rh_method_count);
}
