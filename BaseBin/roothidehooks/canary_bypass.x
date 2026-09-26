#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/runtime.h>
#include <os/log.h>
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <pthread.h>

// RHHIDE_DEBUG: define at compile time (-DRHHIDE_DEBUG) to enable OS-log diagnostics.
// Production builds must NOT define it: RASP tools (ZDefend, BlueShield) call
// +[OSLogStore localStoreAndReturnError:] to read the app process's own log entries.
// Any [RHHIDE] message in the log reveals that a bypass is active, triggering
// ZDefend's background kill mechanism at ZDefend+0x2437D4 (~6 min after launch).
#ifdef RHHIDE_DEBUG
static inline void rh_log(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "[RHHIDE] %{public}s", buf);
}
#define RH_LOG(fmt, ...) rh_log(fmt, ##__VA_ARGS__)
#else
#define RH_LOG(fmt, ...) ((void)0)
#endif

// Build identity — always embedded in the binary regardless of RHHIDE_DEBUG.
// On device: strings /basebin/roothidehooks.dylib | grep rhhooks-build
// Format: 2.4.9.<commit-count>-<short-hash>  e.g. 2.4.9.43-0470d71
// Not logged to OSLog in production → invisible to BlueShield/ZDefend log scan.
__attribute__((used, visibility("default")))
const char rhhooks_build[] = "rhhooks-build:" RHHOOKS_VERSION;

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
#ifdef RHHIDE_DEBUG
	Class bsdCls = objc_getClass("BSDPMRHide");
	RH_LOG("canaryBypassInit: BSDPMRHide=%p (%s)",
	       bsdCls, bsdCls ? "present (MBV Bank)" : "absent");
#endif

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

// ─── method_getImplementation intercept (defensive) ──────────────────────────
//
// IDA-VERIFIED (2026-09-26, instance 18ed): MBRaspSdk's RuntimeHookChecker
// (sub_14CB8, type=9 in sub_150B0) does NOT scan IMP addresses. It checks for
// the "Shadow" jailbreak bypass tweak by calling objc_getClass("ShadowRuleset").
// If nil → CLEAN. If class exists → checks internalDictionary method → DETECTED.
// MBRaspSdk does NOT import _method_getImplementation. On our Dopamine setup
// (Shadow not installed), RuntimeHookChecker always returns CLEAN and is
// irrelevant. This hook is therefore defensive only — it has no known attacker
// today, but it is retained because:
//   (a) it is harmless,
//   (b) it protects any future checker that might walk hooked method IMPs.
//
// Hooked ObjC methods recorded in the registry (method_t → origImp):
//   +[OSLogStore localStoreAndReturnError:]        (slot 0)
//   +[OSLogStore storeWithScope:error:]            (slot 1)
//   -[NSFileManager fileExistsAtPath:]             (slot 2)
//   -[NSFileManager fileExistsAtPath:isDirectory:] (slot 3)
//   -[NSFileManager isReadableFileAtPath:]         (slot 4)
//   -[NSFileManager contentsOfDirectoryAtPath:error:] (slot 5)
//   -[UIApplication canOpenURL:]                   (slot 6)
//   -[BSHasApp cekL3Int:]                          (slot 7 via rh_record_method)

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

static const char *const kJailbreakURLSchemes[] = {
    "cydia",       // Cydia package manager
    "sileo",       // Sileo package manager
    "zbra",        // Zebra package manager
    "filza",       // Filza file manager
    "apt",         // apt scheme
    "dpkg",        // dpkg scheme
    "undecimus",   // unc0ver
    NULL
};

static bool jailbreakBypassShouldBlockURL(NSURL *url) {
    if (!url) return false;
    NSString *scheme = [url scheme];
    if (!scheme) return false;
    const char *cscheme = [scheme UTF8String];
    if (!cscheme) return false;
    for (int i = 0; kJailbreakURLSchemes[i]; i++) {
        if (strcasecmp(cscheme, kJailbreakURLSchemes[i]) == 0) return true;
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
// Two-part fix:
//
// Fix A — 6-minute background kill (loc_243854 / sub_23F234):
//   ZDefend spawns ~20 one-shot threads (sub_243744, sub_243864) that nanosleep
//   ~6 minutes then call loc_243854 → sub_23F234.  sub_23F234 is a 4-instruction
//   kill function: LDR X30,=0xDD3FB5DCAFF0C584; LDR X0,=0x228E6AD55B8699BC;
//   EOR X0,X0,X30; BR X0 → jumps to 0xFFB1DF09F4765C38 (PAC-invalid) → SIGSEGV.
//   Confirmed by VPBankNEO-2026-09-22-002140.ips (PC=0xFFB1DF09F4765C38).
//   On non-jailbreak devices ZDefend patches the literal-pool constants at runtime
//   to a valid function pointer; on a jailbreak they remain as-is → crash.
//   Fix: hook loc_243854 at (ZDefend_base + 0x243854) via pthread_exit(NULL).
//   Must NOT return: both callers follow "BL loc_243854" with an EH landing pad
//   (sub_7580 = __Unwind_Resume); a normal return → __Unwind_Resume(garbage) → crash.
//   pthread_exit terminates only the background thread; the process continues.
//   Offset is from ZDefend IDA analysis (binary UUID b63632c4, file base 0x0).
//
// Fix B — ObjC threat-delivery pipeline:
//   ZDefend reports threats via +[ZDefend addDeviceStatusCallback:].  Swallow this
//   to prevent VPBankNEO from receiving any ZDefend threat events.
//   +[ZDefend setTrackingIds:tag2:] is also swallowed to block Zimperium cloud
//   registration of this device session.
//
// Why safe from _integrity_failed:
//   MSHookMessageEx modifies ObjC method_t.imp in __DATA only; _integrity_failed
//   hashes __TEXT/__text — __DATA changes don't affect it → _integrity_failed safe.
//   IDA-confirmed: _integrity_failed (0x1CEE54) calls only sub_1CEFE4 (4-instruction
//   no-op: STR WZR/LDR/ADRP/RET) and ___stack_chk_fail (unreachable on a clean stack).
//   Zero direct callers in binary. No crash path.
//   ZDefend imports no abort/exit/kill/raise; the kill mechanism is internal (Fix A).

// Fix A: loc_243854 wrapper replacement.
// IMPORTANT: must NOT return normally.
// The callers (sub_243744 @ 0x243790, sub_243864 @ 0x2438b0) follow
// "BL loc_243854" with an EH cleanup landing pad:
//   MOV X19, X0          ; save exception object
//   MOV X0, SP
//   BL sub_2437A4        ; run C++ destructors
//   BL sub_7580          ; sub_7580 = MOV X0,X19; B __Unwind_Resume → re-throw
// A normal return would land there with X0=garbage → __Unwind_Resume(garbage) → crash.
// Use pthread_exit(NULL) to terminate the background thread cleanly instead.
static void __attribute__((noreturn)) replaced_zdefend_kill_wrapper(void) {
    pthread_exit(NULL);
}

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
        RH_LOG("zdefendBypassInit: ZDefend class absent, skipping");
        return;
    }
    RH_LOG("zdefendBypassInit: ZDefend found, installing kill-mechanism bypass");

    Class zdMeta = objc_getMetaClass("ZDefend");

    // Fix A: hook loc_243854 (ZDefend+0x243854) — the kill-wrapper called by
    // background threads after ~6-minute nanosleep.  Must be done BEFORE
    // MSHookMessageEx so we dladdr the unmodified original IMP.
    {
        IMP zdImp = class_getMethodImplementation(zdMeta,
                                                  @selector(addDeviceStatusCallback:));
        if (zdImp) {
            Dl_info dl;
            if (dladdr((void *)zdImp, &dl) && dl.dli_fbase) {
                void *kill_wrapper = (char *)dl.dli_fbase + 0x243854;
                // First instruction of loc_243854: STP X29, X30, [SP,#-0x10]! = 0xA9BF7BFD
                uint32_t first_insn = *(uint32_t *)kill_wrapper;
                if (first_insn == 0xA9BF7BFDU) {
                    MSHookFunction(kill_wrapper,
                                   (void *)replaced_zdefend_kill_wrapper,
                                   NULL);
                    RH_LOG("zdefendBypassInit: loc_243854 kill-wrapper hooked at %p",
                           kill_wrapper);
                } else {
                    RH_LOG("zdefendBypassInit: loc_243854 insn=0x%08x mismatch, skip",
                           first_insn);
                }
            }
        }
    }

    // Fix B: swallow ObjC threat-delivery and cloud-registration calls.
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

// ─── BSHasApp cekL1Int: URL scheme detection bypass ──────────────────────────
//
// cekL1Int (0x31E6C, blueshield.framework r82q) iterates a "schemes" array from
// the BlueShield check config and calls:
//   [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:scheme]]
// If any scheme returns YES → W19=1 → reason=4.
//
// IDA-confirmed (r82q, W8=0x757E solved from count constraint "UIApplication"=4):
//   0x32374 → "UIApplication"   0x3239c → "sharedApplication"
//   0x323d8 → "canOpenURL:"     0x32400 → "NSURL"
//   0x32424 → "URLWithString:"
//   0x32470: TBNZ W24, #0, loc_324A4 → detected if canOpenURL: returned YES
//
// Fix: return NO for known jailbreak tool URL schemes (cydia://, sileo://, etc.)
// Uses method_setImplementation (PAC-aware, handles compact method encoding on
// iOS 15+ UIKit) — same approach as localStoreAndReturnError: hook above.
// RuntimeHookChecker bypass: recorded via rh_record_method (slot 6/8 for canOpenURL:).

static BOOL (*orig_canOpenURL)(id self, SEL sel, NSURL *url) = NULL;

static BOOL replaced_canOpenURL(id self, SEL sel, NSURL *url) {
    if (jailbreakBypassShouldBlockURL(url)) {
        RH_LOG("UIApp.canOpenURL BLOCKED: %s", [[url absoluteString] UTF8String] ?: "");
        return NO;
    }
    return orig_canOpenURL(self, sel, url);
}

// ─── BSHasApp cekL3Int: OSLogStore.storeWithScope:error: bypass ──────────────
//
// cekL3Int (0x32D9C, blueshield.framework r82q) calls
//   +[OSLogStore storeWithScope:1 error:&err]
// to open a system-scoped log store, then queries it with a predicate to detect
// jailbreak indicators in the log stream (including strings emitted by injected
// dylibs such as ElleKit and roothidehooks itself).
//
// The existing localStoreAndReturnError: hook covers BSLogCek (0x38a00) which
// uses a different entry point. cekL3Int specifically uses storeWithScope:error:
// to avoid being blocked by that hook. IDA-confirmed (r82q, W23=0x1218):
//   str_40903481504, wc=0x121B-W23=3, key=0x1A7DA686-W23 → "storeWithScope:error:"
//
// IDA-confirmed (r82q, W23=0x1218, disasm 3308c: SUB W2, #0x121E, W23 = 6):
//   str_40903481504, wc=6, key=0x1A7DA686-W23 → "storeWithScope:error:" (21 chars)
// Fix: return nil + non-nil error from storeWithScope:error:.
//
// cekL3Int's state machine at 330f8 checks *error after the call:
//   CMP X22, #0  (X22 = retained *error)
//   CSEL W8, W9(13), W8(5), EQ   ← nil error → base=13; non-nil error → base=5
//
// With *error=nil (old hook): state machine follows base=13 path → case 13 at
// 0x33F60, which unconditionally creates a non-empty NSArray (a detection record)
// from a fixed deobfuscated class-method call, and returns it immediately.
// BSHasApp.apply stores this non-empty array → reports WS0026 reason=5.
//
// With *error=non-nil (this fix): state machine follows base=5 path → case 5 at
// 0x332B8, which operates on the nil store. Every ObjC call to nil returns nil,
// so all log-scan results are nil → case 5 transitions to the clean exit
// (cases 6/8 at 0x33DB0 → ___NSArray0__ empty array) → no detection.

static id (*orig_storeWithScope)(Class cls, SEL sel, NSInteger scope, NSError **error) = NULL;

static id replaced_storeWithScope(Class cls, SEL sel, NSInteger scope, NSError **error) {
    RH_LOG("cekL3Int: OSLogStore.storeWithScope:error: blocked (scope=%ld)", (long)scope);
    if (error) {
        *error = [NSError errorWithDomain:NSCocoaErrorDomain
                                    code:NSFileReadNoPermissionError
                                userInfo:nil];
    }
    return nil;
}

// ─── Direct -[BSHasApp cekL3Int:] hook ───────────────────────────────────────
//
// IDA-verified (r82q): cekL3Int (0x32D9C) is a 14-case obfuscated state machine.
// The storeWithScope:error: hook above routes it to case 5, but case 5's exit
// state = (1 - W24>>17) & 0xF where W24 = W9 * 0x73D55909, W9 = lower 32 bits
// of sel_countByEnumeratingWithState:objects:count: at runtime. W9 is ASLR-
// dependent → case 5's next state is not statically determinable. The storeWithScope
// fix alone cannot guarantee a clean exit; case 5 may route to case 11 or 13
// (detection) depending on the runtime SEL address.
//
// Fix: hook cekL3Int directly → returns @[] before the state machine runs.
// BSHasApp instance method table (0x7B310, count=6, entsize=0x18 absolute):
//   cekL3Int: is slot 3, IMP at 0x32D9C. class_getInstanceMethod finds it
//   directly (not inherited). method_setImplementation handles absolute lists.
static NSArray* (*orig_cekL3Int)(id self, SEL sel, id arg) = NULL;

static NSArray* replaced_cekL3Int(id self, SEL sel, id arg) {
    RH_LOG("cekL3Int: -[BSHasApp cekL3Int:] bypassed (returning empty array)");
    return @[];
}

// ─── BSHasApp cekL2Int: NSClassFromString("LSApplicationWorkspace") bypass ───
//
// cekL2Int (0x324D4, blueshield.framework r82q) uses NSClassFromString as its
// first gate. IDA-confirmed decode (r82q, W26=0x3D8F):
//   str_174047467680, wc=9, key=0x7402089F-W26 → base64 → XOR → "LSApplicationWorkspace"
//
// If LSApplicationWorkspace is present in the process (happens on Dopamine when
// injected libs load LaunchServices as a side-effect), cekL2Int calls:
//   [[LSApplicationWorkspace defaultWorkspace]
//       isApplicationAvailableToOpenURL: [NSURL URLWithString: url] error: &err]
// for each jailbreak URL scheme in its outer NSFastEnumeration loop. This is a
// deliberate bypass of our canOpenURL: hook — it queries LaunchServices directly.
//
// Fix: return Nil from NSClassFromString for "LSApplicationWorkspace" → class
// lookup fails → CBZ X23, loc_32D60 branch taken → loop continues with W22=0
// (no detection) for every iteration → cekL2Int always returns clean.
//
// NSClassFromString is a C function (not an ObjC method), so MSHookFunction is
// used instead of method_setImplementation. RuntimeHookChecker only scans ObjC
// method tables — this trampoline hook is not visible to it; no rh_record_method.

static Class (*orig_NSClassFromString)(NSString *aClassName) = NULL;

static Class replaced_NSClassFromString(NSString *aClassName) {
    if (aClassName && [aClassName isEqualToString:@"LSApplicationWorkspace"]) {
        RH_LOG("cekL2Int: NSClassFromString(LSApplicationWorkspace) -> Nil");
        return Nil;
    }
    return orig_NSClassFromString(aClassName);
}

__attribute__((visibility("default"))) void logScanBypassInit(void)
{
    RH_LOG("logScanBypassInit called (build: " RHHOOKS_VERSION ")");

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
    // Uses method_setImplementation directly instead of MSHookMessageEx.
    // Root cause of prior failure: iOS 15 system frameworks use compact/relative
    // method encoding; MSHookMessageEx cannot extract the original IMP from a
    // relative method list and returns orig=NULL without installing the hook.
    // method_setImplementation is the ObjC runtime's PAC-aware IMP replacement
    // function and handles relative method encoding correctly on arm64e iOS 15+.
    Class osLogStoreMeta = objc_getMetaClass("OSLogStore");
    if (osLogStoreMeta) {
        Method m_ols = class_getInstanceMethod(osLogStoreMeta,
                                               @selector(localStoreAndReturnError:));
        if (m_ols) {
            IMP oldOlsImp = method_setImplementation(m_ols, (IMP)replaced_localStoreAndReturnError);
            orig_localStoreAndReturnError = (__typeof__(orig_localStoreAndReturnError))oldOlsImp;
            rh_record_method(m_ols, oldOlsImp);
        }
        // ── Hook +[OSLogStore storeWithScope:error:] → nil: disables cekL3Int ─
        // cekL3Int (blueshield r82q 0x32D9C) uses storeWithScope:error: specifically
        // to avoid being caught by the localStoreAndReturnError: hook above.
        Method m_sws = class_getInstanceMethod(osLogStoreMeta,
                                               @selector(storeWithScope:error:));
        if (m_sws) {
            IMP oldSwsImp = method_setImplementation(m_sws, (IMP)replaced_storeWithScope);
            orig_storeWithScope = (__typeof__(orig_storeWithScope))oldSwsImp;
            rh_record_method(m_sws, oldSwsImp);
        }
    }

    // ── Hook NSFileManager file-existence checks ──────────────────────────────
    // MBV Bank (no ZDefend) only. Two reasons to skip when ZDefend is present (VPBank):
    //
    // 1. ZDefend uses direct SVC syscalls (openat/stat64/readlinkat via SVC 0x80),
    //    bypassing NSFileManager entirely. The hooks provide zero protection.
    //
    // 2. When ZDefend is present, method_getImplementation is NOT hooked (PAC safety —
    //    see comment above). BlueShield's RuntimeHookChecker in VPBank would call
    //    method_getImplementation on NSFileManager methods and see our replaced IMP
    //    pointing into roothidehooks.dylib (outside any system-framework __TEXT range),
    //    detecting the hook. Without method_getImplementation intercepted, hooking
    //    NSFileManager creates a detection surface with no benefit.
    //
    // BSZInspection.checkZimFrameworkInternal: does NOT fire on Dopamine: ElleKit exports
    // no ObjC classes (libellekit.tbd has no objc-classes: section), so objc_getClass
    // returns nil for all Substrate/ElleKit class names → W27 bit 0 never set → no
    // detection from that path. However, BSHasApp.apply case 7 ("ScanLog" checks via
    // cekL3Int:) calls fileExistsAtPath: on jailbreak paths at runtime, so these hooks
    // actively block that detection.  They are also required for RuntimeHookChecker
    // (MBRaspSdk) so our IMPs are registered in the orig-IMP table.
    if (objc_getClass("ZDefend") == NULL) {
        {
            Method m_fep = class_getInstanceMethod([NSFileManager class],
                                                   @selector(fileExistsAtPath:));
            MSHookMessageEx([NSFileManager class],
                            @selector(fileExistsAtPath:),
                            (IMP)replaced_fileExistsAtPath,
                            (IMP *)&orig_fileExistsAtPath);
            rh_record_method(m_fep, (IMP)orig_fileExistsAtPath);
        }
        {
            Method m_fepid = class_getInstanceMethod([NSFileManager class],
                                                     @selector(fileExistsAtPath:isDirectory:));
            MSHookMessageEx([NSFileManager class],
                            @selector(fileExistsAtPath:isDirectory:),
                            (IMP)replaced_fileExistsAtPathIsDirectory,
                            (IMP *)&orig_fileExistsAtPathIsDirectory);
            rh_record_method(m_fepid, (IMP)orig_fileExistsAtPathIsDirectory);
        }
        {
            Method m_irfap = class_getInstanceMethod([NSFileManager class],
                                                     @selector(isReadableFileAtPath:));
            MSHookMessageEx([NSFileManager class],
                            @selector(isReadableFileAtPath:),
                            (IMP)replaced_isReadableFileAtPath,
                            (IMP *)&orig_isReadableFileAtPath);
            rh_record_method(m_irfap, (IMP)orig_isReadableFileAtPath);
        }
        // Defensive: +[MC1 getAllFramworks] (0x20394) calls contentsOfDirectoryAtPath:
        // to list the app's /Frameworks dir. Jailbreak dylibs are NOT in /Frameworks
        // (injected via DYLD_INSERT_LIBRARIES), so this filters nothing in practice.
        {
            Method m_coddap = class_getInstanceMethod([NSFileManager class],
                                                      @selector(contentsOfDirectoryAtPath:error:));
            MSHookMessageEx([NSFileManager class],
                            @selector(contentsOfDirectoryAtPath:error:),
                            (IMP)replaced_contentsOfDirectoryAtPath,
                            (IMP *)&orig_contentsOfDirectoryAtPath);
            rh_record_method(m_coddap, (IMP)orig_contentsOfDirectoryAtPath);
        }
        // ── Hook UIApplication canOpenURL: → NO for jailbreak tool schemes ───────
        // BSHasApp cekL1Int (blueshield.framework 0x31E6C) queries whether schemes
        // like sileo://, cydia://, zbra:// can be opened to detect jailbreak package
        // managers. method_setImplementation handles compact method encoding on UIKit.
        {
            Class uiAppCls = objc_getClass("UIApplication");
            if (uiAppCls) {
                Method m_cou = class_getInstanceMethod(uiAppCls, @selector(canOpenURL:));
                if (m_cou) {
                    IMP oldCouImp = method_setImplementation(m_cou, (IMP)replaced_canOpenURL);
                    orig_canOpenURL = (__typeof__(orig_canOpenURL))oldCouImp;
                    rh_record_method(m_cou, oldCouImp);
                }
            }
        }
        // ── Hook NSClassFromString → Nil for "LSApplicationWorkspace" ─────────
        // cekL2Int (blueshield r82q 0x324D4) calls NSClassFromString as its first
        // gate. If LSApplicationWorkspace is in-process, cekL2Int uses
        // [[LSApplicationWorkspace defaultWorkspace] isApplicationAvailableToOpenURL:]
        // to detect jailbreak app URL schemes, bypassing canOpenURL: above entirely.
        // MSHookFunction (not method_setImplementation): NSClassFromString is a C
        // function. RuntimeHookChecker only scans ObjC method tables — not visible.
        MSHookFunction((void *)NSClassFromString,
                       (void *)replaced_NSClassFromString,
                       (void **)&orig_NSClassFromString);
        RH_LOG("NSClassFromString hooked (cekL2Int LSApplicationWorkspace bypass)");
        // ── Hook -[BSHasApp cekL3Int:] → @[] ─────────────────────────────────────
        // IDA-verified: case 5 next state = (1 - W24>>17) & 0xF, runtime-dependent.
        // storeWithScope fix alone is insufficient. This hook short-circuits the
        // entire state machine before it runs. Inside ZDefend guard: BSHasApp is
        // BlueShield-only. method_setImplementation handles absolute method list
        // (entsize=0x18). rh_record_method registers original blueshield.__TEXT IMP.
        {
            Class bsHasApp = objc_getClass("BSHasApp");
            if (bsHasApp) {
                Method m_cekL3 = class_getInstanceMethod(bsHasApp, @selector(cekL3Int:));
                if (m_cekL3) {
                    IMP oldCekL3Imp = method_setImplementation(m_cekL3, (IMP)replaced_cekL3Int);
                    orig_cekL3Int = (__typeof__(orig_cekL3Int))oldCekL3Imp;
                    rh_record_method(m_cekL3, oldCekL3Imp);
                    RH_LOG("cekL3Int: -[BSHasApp cekL3Int:] hooked");
                }
            }
        }
        // ── Hook -[BSLogCek cekL3Int:] → @[] ─────────────────────────────────────
        // IDA-verified (r82q 0x38A00): BSLogCek is a SEPARATE checker class with its
        // own apply method and NSFastEnumeration loop that dispatches [self cekL3Int:]
        // on a BSLogCek instance → BSLogCek.cekL3Int: (IMP 0x39204), independent from
        // BSHasApp's patched IMP. Both classes scan OS logs for hooking framework
        // strings. Method list at 0x7C228 (count=4): apply/cekL3Int:/logLevelName:/
        // getChecks. No rh_record_method: RuntimeHookChecker only audits Foundation
        // classes, not BlueShield-internal methods.
        {
            Class bsLogCek = objc_getClass("BSLogCek");
            if (bsLogCek) {
                Method m_logCekL3 = class_getInstanceMethod(bsLogCek, @selector(cekL3Int:));
                if (m_logCekL3) {
                    method_setImplementation(m_logCekL3, (IMP)replaced_cekL3Int);
                    RH_LOG("cekL3Int: -[BSLogCek cekL3Int:] hooked");
                }
            }
        }
    }
}
