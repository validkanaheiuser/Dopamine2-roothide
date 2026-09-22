#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/runtime.h>
#include <os/log.h>
#include <stdio.h>
#include <stdarg.h>

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
	if (cls && strcmp(class_getName(cls), "BSDPMRHide") == 0) {
		RH_LOG("canary: blocked class_getInstanceMethod(BSDPMRHide, %s)", sel_getName(sel));
		return NULL;
	}
	return orig_class_getInstanceMethod(cls, sel);
}

static Method (*orig_class_getClassMethod)(Class cls, SEL sel) = NULL;

static Method replaced_class_getClassMethod(Class cls, SEL sel)
{
	if (cls && strcmp(class_getName(cls), "BSDPMRHide") == 0) {
		RH_LOG("canary: blocked class_getClassMethod(BSDPMRHide, %s)", sel_getName(sel));
		return NULL;
	}
	return orig_class_getClassMethod(cls, sel);
}

__attribute__((visibility("default"))) void canaryBypassInit(void)
{
	Class bsdCls = objc_getClass("BSDPMRHide");
	RH_LOG("canaryBypassInit: BSDPMRHide=%p (%s)",
	       bsdCls, bsdCls ? "present (MBV Bank)" : "absent");

	MSHookFunction((void *)class_getInstanceMethod,
	               (void *)replaced_class_getInstanceMethod,
	               (void **)&orig_class_getInstanceMethod);
	RH_LOG("canaryBypassInit: class_getInstanceMethod hooked orig=%p",
	       (void *)orig_class_getInstanceMethod);

	MSHookFunction((void *)class_getClassMethod,
	               (void *)replaced_class_getClassMethod,
	               (void **)&orig_class_getClassMethod);
	RH_LOG("canaryBypassInit: class_getClassMethod hooked orig=%p",
	       (void *)orig_class_getClassMethod);
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
                RH_LOG("RuntimeHookChecker: spoofed imp[%d] orig=%p",
                       i, (void *)s_rh_orig_imps[i]);
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

static bool jailbreakBypassShouldBlockPath(NSString *path) {
    if (!path) return false;
    const char *cpath = [path UTF8String];
    if (!cpath) return false;
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

// ─── ZDefend bypass for VP Bank NEO ──────────────────────────────────────────
//
// ZDefend.framework (Zimperium z9 RASP SDK) uses Direct Syscalls (SVC 0x80) for
// all internal checks — openat(#463), readlinkat(#465), stat64(#338) etc. — which
// means POSIX-layer hooks (hook_access, replaced_fopen, NSFileManager hooks) are
// completely ineffective against ZDefend's 284 sensor rules.
//
// However, ZDefend MUST go through the standard ObjC message-passing interface to
// report threats back to the host app (VPBankNEO). The reporting pipeline is:
//   +[ZDefend addDeviceStatusCallback:block] → callback fires → ZDefendManager
//   → sub_1007E2DB4 → ZDefendViewController shown
//
// Fix: hook +[ZDefend addDeviceStatusCallback:] → swallow (drop the block).
//   ZDefend detects threats internally (cannot be prevented without kernel patches),
//   but can never deliver them to VPBankNEO → no ZDefendViewController appears.
//
// Why safe from _integrity_failed:
//   MSHookMessageEx modifies the ObjC method dispatch table in __DATA (method_t.imp).
//   _integrity_failed hashes the __text/__TEXT segment only. Modifying __DATA does
//   NOT affect the text hash → _integrity_failed does not fire.
//
// IDA-confirmed (instance 22ql): _integrity_failed (0x1CEE54) CANNOT crash the process.
//   Import table: ZDefend.framework imports NO termination API — abort(), exit(),
//   _exit(), kill(), raise() are all absent. Only ___cxa_guard_abort (C++ init guard),
//   _objc_sync_exit (@synchronized), and atexit-family registrations appear; none
//   terminate the process. kill() is completely absent.
//   _integrity_failed body: CFF state machine calling only sub_1CFA08 (loads two
//   magic constants into W12/W13, RET — pure obfuscation bookkeeping) and
//   ___stack_chk_fail (stack canary, unreachable on a clean stack). No crash path.
//
// +[ZDefend setTrackingIds:tag2:] is also swallowed to prevent ZDefend from
// registering this device session on the Zimperium cloud backend.

static void replaced_ZDefend_addDeviceStatusCallback(id cls, SEL sel, id block)
{
    RH_LOG("ZDefend.addDeviceStatusCallback: SWALLOWED (threat pipeline cut)");
    // intentionally drop block — VPBankNEO never receives any ZDefend threat event
}

static void replaced_ZDefend_setTrackingIds(id cls, SEL sel, NSArray *ids, id tag2)
{
    RH_LOG("ZDefend.setTrackingIds:tag2: SWALLOWED");
}

__attribute__((visibility("default"))) void zdefendBypassInit(void)
{
    Class zdCls = objc_getClass("ZDefend");
    if (!zdCls) {
        // ZDefend.framework is not present (not VP Bank) — safe no-op
        RH_LOG("zdefendBypassInit: ZDefend class absent, skipping");
        return;
    }
    RH_LOG("zdefendBypassInit: ZDefend found, cutting threat reporting pipeline");

    // Hook +[ZDefend addDeviceStatusCallback:] on the ZDefend metaclass
    Class zdMeta = objc_getMetaClass("ZDefend");

    MSHookMessageEx(zdMeta,
                    @selector(addDeviceStatusCallback:),
                    (IMP)replaced_ZDefend_addDeviceStatusCallback,
                    NULL);
    RH_LOG("zdefendBypassInit: addDeviceStatusCallback: hooked");

    MSHookMessageEx(zdMeta,
                    @selector(setTrackingIds:tag2:),
                    (IMP)replaced_ZDefend_setTrackingIds,
                    NULL);
    RH_LOG("zdefendBypassInit: setTrackingIds:tag2: hooked");
}

__attribute__((visibility("default"))) void logScanBypassInit(void)
{
    RH_LOG("logScanBypassInit called");

    // ── RuntimeHookChecker bypass: install method_getImplementation hook first ──
    // Only needed for MBV Bank: _TtC9MBRaspSdk18RuntimeHookChecker (in MBRaspSdk)
    // reads each method's IMP via method_getImplementation and flags any IMP that
    // points outside a known system-framework __TEXT range. VPBank has no MBRaspSdk.
    //
    // On arm64e (A12+) MSHookFunction on method_getImplementation (arm64e libobjc)
    // corrupts PAC (Pointer Authentication Code) state, crashing VPBankNEO during
    // ZDefend.framework's initializer:
    //   ZDefend ctor → NSFileManager moveItemAtPath: → NSOperation init
    //   → KVO setup → method_t::imp(bool) const +56 → AUTIA trap
    //   → EXC_BREAKPOINT "pointer authentication trap IA"
    // Confirmed: VPBankNEO-2026-09-21-093224.ips frame 0, ESR "pointer auth trap IA".
    //
    // Guard: skip when ZDefend class is registered (= VPBank context).
    // objc_getClass("ZDefend") is valid here: dyld registers ObjC classes during
    // the image-mapping phase, before any constructors run. ZDefend's class is in
    // the runtime hash table even though ZDefend.framework's +initialize has not
    // yet executed. Same invariant used by save_canary_imps() for "BSDPMRHide".
    if (objc_getClass("ZDefend") == NULL) {
        MSHookFunction((void *)method_getImplementation,
                       (void *)replaced_method_getImplementation,
                       (void **)&orig_method_getImplementation);
        RH_LOG("method_getImplementation hooked (RuntimeHookChecker bypass)");
    } else {
        RH_LOG("method_getImplementation hook SKIPPED (ZDefend present, PAC safety)");
    }

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

    // ── Hook NSFileManager file-existence checks ──────────────────────────────
    // Covers BSZInspection Zebra/Zim scan and cekL3Int package metadata reads.
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
