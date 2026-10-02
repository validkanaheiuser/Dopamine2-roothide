#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/runtime.h>
#include <os/log.h>
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>

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
// -[NSFileManager contentsOfDirectoryAtPath:error:] to list the app bundle's
// /Frameworks directory. It is called BY +[MC1 isFrameworkAvailable] (0x20790)
// as part of the MC1 detection scan (NOT post-detection).
//
// IDA-verified (r82q strings at 0x6c5b0-0x6c718): MC1 uses NSFileManager
// (NOT _dyld_image_count/_dyld_get_image_name — those are MWkpr/reason=4 only).
// MC1 scans @executable_path/Frameworks for:
//   (a) presence of mobilebankingx.framework (bundle-id canary MUST exist)
//   (b) absence of hooking frameworks (ElleKit.framework, CydiaSubstrate.framework)
//
// RUNTIME NOTE: Dopamine injects dylibs via DYLD_INSERT_LIBRARIES at /var/jb/
// rootless paths; they are NOT placed in the app bundle's /Frameworks directory.
// The MC1 filesystem check therefore PASSES naturally for Dopamine/RootHide —
// the canary is present and no hooking framework appears in /Frameworks.
// This hook filters nothing in practice but is retained for correctness.
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
        RH_LOG("canOpenURL: BLOCKED %s", [[url absoluteString] UTF8String] ?: "");
        return NO;
    }
    BOOL result = orig_canOpenURL(self, sel, url);
    RH_LOG("canOpenURL: PASS %s -> %d", [[url absoluteString] UTF8String] ?: "", result);
    return result;
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
    RH_LOG("cekL3Int: -[%s cekL3Int:] bypassed arg=%s",
           class_getName(object_getClass(self)),
           [[arg description] UTF8String] ?: "(nil)");
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
    if (!aClassName) return Nil;
    if ([aClassName isEqualToString:@"LSApplicationWorkspace"]) {
        RH_LOG("NSClassFromString: BLOCKED %s", [aClassName UTF8String]);
        return Nil;
    }
    Class result = orig_NSClassFromString(aClassName);
    RH_LOG("NSClassFromString: %s -> %s", [aClassName UTF8String], result ? class_getName(result) : "(nil)");
    return result;
}

// ─── BSZInspection.apply call-through trampoline ─────────────────────────────
static IMP s_bsz_apply_orig = NULL;

// ─── openURL:options:completionHandler: Promon Shield / BlueShield redirect block
//
// IDA-verified (2qvw / mobilebankingx.framework = Promon Shield):
//   +[PRMShieldEventManager load] (0x82C45C) → sub_75680 → sub_73430 →
//   sub_6A358 (160KB CFF state machine; reads dyld_all_image_infos directly,
//   detects roothide/ellekit injection → MOV W0,#4 at 0x71B44) →
//   sub_2E4400 (calls UIApplicationMain + schedules dispatch_async block) →
//   dispatch_main_queue_callback_4CF fires sub_2E582C (block invoke) →
//   sub_2E505C (URL builder + openURL caller at 0x2E556C) →
//   [[UIApplication sharedApplication] openURL:threatURL
//                                       options:@{} completionHandler:block]
//   where threatURL = https://pro-threats.nbowree.com/threats?reason=4...
//
// Root cause of crash: Promon's openURL completion block calls exit() regardless
// of the BOOL result — calling handler(YES) OR handler(NO) both trigger exit().
// bshield-1.log confirmed: app crashed immediately after THREAT_REDIRECT BLOCKED
// (handler(NO) was called → Promon's block invoked synchronously → exit()).
//
// Correct behavior: do NOT invoke the completion handler at all. Promon's block
// is never called from our hook, so exit() is not triggered here. The engine-level
// hooks (sub_6A358, sub_4F1DE8, sub_27B1A8) are the primary fix — they prevent
// sub_2E4400 from ever being called, so this hook should never fire in practice.
// This hook is a last-resort URL block only; it must not call handler.
//
// Production: no RH_LOG. BSLogCek/cekL3Int scan the OS log for [RHHIDE] strings.
static IMP s_orig_openURL_opts = NULL;

static void replaced_openURL_opts(id self, SEL sel, NSURL *url,
                                  NSDictionary *opts, void(^handler)(BOOL))
{
    NSString *urlStr = [url absoluteString];
    if (urlStr && [urlStr containsString:@"nbowree"]) {
#ifdef RHHIDE_DEBUG
        RH_LOG("THREAT_REDIRECT BLOCKED url=%s", [urlStr UTF8String]);
        NSArray *stack = [NSThread callStackSymbols];
        NSUInteger lim = MIN([stack count], 30U);
        for (NSUInteger i = 0; i < lim; i++) {
            RH_LOG("THREAT_STACK[%02lu]: %s", (unsigned long)i,
                   [[stack objectAtIndex:i] UTF8String]);
        }
#endif
        // Do NOT call handler — invoking it triggers Promon's exit() block.
        return;
    }
    ((void (*)(id, SEL, NSURL *, NSDictionary *, void(^)(BOOL)))s_orig_openURL_opts)(
        self, sel, url, opts, handler);
}

// ─── Promon Shield sub_6A358 (core detection CFF engine) no-op hook ─────────
//
// IDA-verified (2qvw): sub_6A358 at file offset 0x6A358 is the 160KB CFF state
// machine that:
//   (a) reads dyld_all_image_infos directly — bypasses all Fix B API hooks, and
//   (b) calls sub_2E4400(4, data) at 0x71B48 when it finds injected dylibs.
//
// Returning 0 immediately prevents the entire detection loop from running.
// We never call orig_promon_scanner / orig_promon_scanner2 — that is intentional.
static intptr_t (*orig_promon_scanner)(intptr_t, intptr_t, intptr_t, intptr_t) = NULL;
static intptr_t (*orig_promon_scanner2)(intptr_t, intptr_t, intptr_t, intptr_t) = NULL;
static intptr_t (*orig_promon_scanner3)(intptr_t, intptr_t, intptr_t, intptr_t) = NULL;
static intptr_t replaced_promon_scanner(intptr_t a1, intptr_t a2, intptr_t a3, intptr_t a4) {
    return 0;
}

// ─── BShield (build-info.framework) Core RASP & Crash Fix Hooks ───────────────
//
// build-info.framework (BShield RASP Core v2.7.0 in TCBRetail):
//   1. sub_34340 (offset 0x34340): Early integrity check loop inside InitFunc_0.
//      Bypassing it prevents background checkers from running during library load.
//   2. sub_E970 (offset 0xE970): Checks *(a1 + 128) & 1. If database pointer a1
//      is NULL, dereferencing offset 0x80 triggers EXC_BAD_ACCESS (SIGSEGV 11).
//      Null-guard ensures it safely returns 0 if a1 == NULL.
//   3. sub_40D734 (offset 0x40D734): Checker 442 function that invokes sub_E970.
static int64_t replaced_buildinfo_sub_34340(int64_t a1, int64_t a2) {
    RH_LOG("build-info: sub_34340 bypassed (InitFunc_0 check loop blocked)");
    return 0;
}

static uint8_t replaced_buildinfo_sub_E970(void *a1) {
    if (!a1) return 0;
    return *(uint8_t *)((uintptr_t)a1 + 128) & 1;
}

static int64_t replaced_buildinfo_sub_40D734(void) {
    RH_LOG("build-info: sub_40D734 bypassed (Checker 442 blocked)");
    return 0;
}

static void replaced_tcbretail_noop(void) {
    // No-op to safely skip broken/swizzling +load routines in TCBRetail
}

// Version-agnostic Pattern Scanner (finds byte signature in Mach-O __TEXT segment)
static void *find_pattern_in_image(void *base, size_t fallback_max, const uint8_t *pat, size_t pat_len) {
    if (!base || !pat || pat_len == 0) return NULL;
    size_t scan_size = fallback_max;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)base;
    if (mh->magic == MH_MAGIC_64) {
        const uint8_t *cmd_ptr = (const uint8_t *)(mh + 1);
        for (uint32_t i = 0; i < mh->ncmds; i++) {
            const struct load_command *lc = (const struct load_command *)cmd_ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (strncmp(seg->segname, "__TEXT", 6) == 0) {
                    if (seg->vmsize > 0) {
                        scan_size = (size_t)seg->vmsize;
                    }
                    break;
                }
            }
            cmd_ptr += lc->cmdsize;
        }
    }
    if (scan_size < pat_len) return NULL;
    const uint8_t *ptr = (const uint8_t *)base;
    for (size_t i = 0; i <= scan_size - pat_len; i += 4) { // ARM64 instructions are 4-byte aligned
        if (memcmp(ptr + i, pat, pat_len) == 0) {
            return (void *)(ptr + i);
        }
    }
    return NULL;
}

// ─── Diagnostic: objc_getClass hook (RHHIDE_DEBUG only) ──────────────────────
// Reveals what ObjC class names BlueShield/BSZInspection probes for via
// SCP_StrDeobf. Only installed in RHHIDE_DEBUG builds — too noisy/slow for
// production. Caller-filtered to blueshield.framework via dladdr; the +0x<offset>
// can be cross-referenced directly in IDA (r82q, file base 0x0).
#ifdef RHHIDE_DEBUG
static Class (*orig_objc_getClass_fn)(const char *name) = NULL;
static Class replaced_objc_getClass_fn(const char *name) {
    Class result = orig_objc_getClass_fn(name);
    // dladdr caller filter was removed: MSHookFunction trampolines sit in anonymous
    // mmap pages so __builtin_return_address(0) resolves to the trampoline, not the
    // caller library — making any "blueshield" dladdr filter always fail (0 entries).
    // Log all hits (non-nil results) — noisy but captures every class BlueShield finds.
    if (result) {
        Dl_info dl;
        void *ret = __builtin_return_address(0);
        const char *lib = "(?)";
        if (dladdr(ret, &dl) && dl.dli_fname) lib = dl.dli_fname;
        RH_LOG("objc_getClass[HIT]: %s  caller=%s", name ?: "(nil)", lib);
    }
    return result;
}
#endif


// ─── BShield P_TRACED bypass: sysctl hook ────────────────────────────────────
//
// build-info.framework InitFunc_0 → sub_ED38 (AEAD decryptor, offset 0xED38):
//   reads kp_proc.p_flag via sysctl([CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()])
//   If P_TRACED (0x800) is set → corrupts ChaCha20 S-Box → Poly1305 MAC fails
//   → Master Database empty → sub_9F2E8 throws → var_1A0 uninit → sub_E970(NULL)
//   → LDRB W8,[X8,#0x80] → SIGSEGV at 0x80.
//
// Hook mechanism: inline 4-instruction absolute trampoline (litehook pattern).
//   MSHookFunction (ElleKit) FAILS: it allocates a new JIT executable page for the
//   trampoline thunk. vm_allocate+vm_protect(EXEC) → pmap_enter failure because
//   TCBRetail has no JIT entitlement. Confirmed: build 3cb46bf pid=1110, ktriageinfo
//   ×5 pmap_enter failures; "sysctl hook installed" logged but replaced_sysctl never
//   called (ElleKit sets orig before the page-alloc attempt, so orig is non-NULL).
//   litehook (used by systemhook for hook_access/fork/csops) writes only to EXISTING
//   shared cache code pages via mprotect — no new executable page needed. Dopamine's
//   kernel patches allow mprotect(RWX) on shared cache pages. sysctl is in
//   libsystem_c.dylib (dyld shared cache, hundreds of instructions → hookable).
//   replaced_sysctl calls __sysctl directly — same pattern as
//   __sysctl_hook in roothider_common.c — no trampoline back to original needed.

// Write LDR X16,[PC+8]; BR X16; .quad addr to target's first 16 bytes.
static bool hook_function_abs(void *target, void *replacement) {
    uintptr_t t = (uintptr_t)target;
    size_t ps = getpagesize();
    if (ps == 0) ps = 0x4000;

    uint32_t patch[4] = {
        0x58000050u,                                // LDR X16, [PC+8]
        0xD61F0200u,                                // BR X16
        (uint32_t)((uintptr_t)replacement),         // low 32 bits of replacement addr
        (uint32_t)(((uintptr_t)replacement) >> 32), // high 32 bits
    };

    uintptr_t page = t & ~(uintptr_t)(ps - 1);
    size_t map_size = ps;
    if ((t & (ps - 1)) + sizeof(patch) > ps)
        map_size += ps;

    if (mprotect((void *)page, map_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        RH_LOG("hook_function_abs: mprotect RWX errno=%d", errno);
        return false;
    }
    __asm__ volatile("dmb ishst" ::: "memory");
    memcpy((void *)t, patch, sizeof(patch));
    __asm__ volatile("dc cvau, %0" : : "r"(t) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    __asm__ volatile("ic ivau, %0" : : "r"(t) : "memory");
    __asm__ volatile("dsb ish\n\tisb" ::: "memory");
    mprotect((void *)page, map_size, PROT_READ | PROT_EXEC);
    return true;
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
            RH_LOG("OSLogStore.localStoreAndReturnError: hooked imp=%p", (void *)oldOlsImp);
        } else {
            RH_LOG("OSLogStore.localStoreAndReturnError: method MISSING");
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
            RH_LOG("OSLogStore.storeWithScope:error: hooked imp=%p", (void *)oldSwsImp);
        } else {
            RH_LOG("OSLogStore.storeWithScope:error: method MISSING");
        }
    } else {
        RH_LOG("OSLogStore metaclass NOT FOUND");
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
    // BSZInspection is NOT the reason=5 trigger — confirmed by c0444b6 runtime
    // log: BSZInspection.apply was hooked but NEVER fired before detection.
    // BSZInspection.checkZimFrameworkInternal: hook is still kept (belt-and-
    // suspenders, no cost). The NSFileManager hooks below remain for BSHasApp.apply
    // case 7 ("ScanLog" checks via cekL3Int:) and for RuntimeHookChecker (MBRaspSdk)
    // so our IMPs are registered in the orig-IMP table.
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
                    RH_LOG("UIApplication.canOpenURL: hooked imp=%p", (void *)oldCouImp);
                } else {
                    RH_LOG("UIApplication.canOpenURL: method MISSING");
                }
            } else {
                RH_LOG("UIApplication class NOT FOUND");
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
                    RH_LOG("cekL3Int: -[BSHasApp cekL3Int:] hooked imp=%p", (void *)oldCekL3Imp);
                } else {
                    RH_LOG("cekL3Int: BSHasApp found but cekL3Int: method MISSING");
                }
            } else {
                RH_LOG("cekL3Int: BSHasApp class NOT FOUND");
            }
        }
        // ── Hook -[BSZInspection checkZimFrameworkInternal:] → NO ───────────────
        // IDA-verified (r82q 0x610C): BSZInspection checks for hooking framework
        // ObjC class names via SCP_StrDeobf (runtime-seeded XOR, undecodable
        // statically). We assumed it doesn't fire because ElleKit has no ObjC
        // classes, but runtime evidence shows detection fires before cekL3Int:/
        // canOpenURL:/storeWithScope: are ever called — BSZInspection is the only
        // known early-running path. Force-return NO to block it.
        {
            Class bsZInspection = objc_getClass("BSZInspection");
            if (bsZInspection) {
                Method m_czfi = class_getInstanceMethod(bsZInspection,
                                    @selector(checkZimFrameworkInternal:));
                if (m_czfi) {
                    method_setImplementation(m_czfi, imp_implementationWithBlock(
                        ^BOOL(id _self, id arg) {
                            RH_LOG("BSZInspection.checkZimFrameworkInternal: BLOCKED arg=%s",
                                   [[arg description] UTF8String] ?: "(nil)");
                            return NO;
                        }
                    ));
                    RH_LOG("BSZInspection.checkZimFrameworkInternal: hooked");
                } else {
                    RH_LOG("BSZInspection: checkZimFrameworkInternal: method MISSING");
                }
#ifdef RHHIDE_DEBUG
                // enumerate all instance methods — reveals selectors beyond checkZimFrameworkInternal:
                {
                    unsigned int mc = 0;
                    Method *ms = class_copyMethodList(bsZInspection, &mc);
                    RH_LOG("BSZInspection: %u instance methods", mc);
                    for (unsigned int i = 0; i < mc; i++) {
                        RH_LOG("  BSZInspection[%u]: %s imp=%p", i,
                               sel_getName(method_getName(ms[i])),
                               (void *)method_getImplementation(ms[i]));
                    }
                    if (ms) free(ms);
                }
#endif
                // ── Also hook BSZInspection.apply → log entry/exit ────────────────
                // checkZimFrameworkInternal: already returns NO; calling through to
                // the original apply is safe. Logging confirms whether apply runs at
                // all before detection fires, and what the state machine produces.
                {
                    Method m_bsza = class_getInstanceMethod(bsZInspection,
                                                            @selector(apply));
                    if (m_bsza) {
                        s_bsz_apply_orig = method_setImplementation(m_bsza,
                            imp_implementationWithBlock(^(id _self) {
                                RH_LOG("BSZInspection.apply: ENTRY");
                                if (s_bsz_apply_orig)
                                    ((void (*)(id, SEL))s_bsz_apply_orig)(
                                        _self, @selector(apply));
                                RH_LOG("BSZInspection.apply: EXIT");
                            }));
                        RH_LOG("BSZInspection.apply: hooked imp=%p",
                               (void *)s_bsz_apply_orig);
                    } else {
                        RH_LOG("BSZInspection: apply method MISSING");
                    }
                }
            } else {
                RH_LOG("BSZInspection class NOT FOUND");
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
                    IMP oldLogCekL3Imp = method_setImplementation(m_logCekL3, (IMP)replaced_cekL3Int);
                    (void)oldLogCekL3Imp;
                    RH_LOG("cekL3Int: -[BSLogCek cekL3Int:] hooked imp=%p", (void *)oldLogCekL3Imp);
                } else {
                    RH_LOG("cekL3Int: BSLogCek found but cekL3Int: method MISSING");
                }
            } else {
                RH_LOG("cekL3Int: BSLogCek class NOT FOUND");
            }
        }
        // ── TCBRetail: Hook build-info.framework + [ShieldAPI getShieldCode] ────
        // build-info.framework IS BShield RASP Core v2.7.0 (7.7 MB, camouflaged).
        // 1. Dynamic pattern scan for sub_34340, sub_E970, and sub_40D734 (version-agnostic)
        //    to prevent the early static constructor crash during dyld image initialization.
        // 2. Hook +[ShieldAPI getShieldCode] at build-info:0x1615C to return 0.
        {
            Class shieldAPIMeta = objc_getMetaClass("ShieldAPI");
            if (shieldAPIMeta) {
                Method m_gsc = class_getInstanceMethod(shieldAPIMeta,
                                                       @selector(getShieldCode));
                if (m_gsc) {
                    IMP imp = method_getImplementation(m_gsc);
                    Dl_info dli = {0};
                    if (dladdr((void *)imp, &dli) && dli.dli_fbase) {
                        uintptr_t base = (uintptr_t)dli.dli_fbase;
                        RH_LOG("build-info framework base found at %p", (void *)base);

                        // Signature 1: sub_E970 (LDRB W8,[X8,#0x80] ; AND W0,W8,#1 ; ADD SP,SP,#0x10 ; RET)
                        static const uint8_t pat_e970[] = {
                            0x08, 0x01, 0x42, 0x39, 0x00, 0x01, 0x00, 0x12, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6
                        };
                        void *loc_e970 = find_pattern_in_image((void *)base, 0x500000, pat_e970, sizeof(pat_e970));
                        if (loc_e970) {
                            // Target is the start of sub_E970 (20 bytes before LDRB)
                            void *fn_e970 = (void *)((uintptr_t)loc_e970 - 20);
                            hook_function_abs(fn_e970, (void *)replaced_buildinfo_sub_E970);
                            RH_LOG("build-info: sub_E970 dynamic pattern hooked at %p", fn_e970);
                        } else {
                            // Fallback to offset 0xE970
                            hook_function_abs((void *)(base + 0xE970), (void *)replaced_buildinfo_sub_E970);
                            RH_LOG("build-info: sub_E970 fallback offset hooked at %p", (void *)(base + 0xE970));
                        }

                        // Signature 2: sub_34340 (Check loop in InitFunc_0)
                        static const uint8_t pat_34340[] = {
                            0xff, 0x03, 0x02, 0xd1, 0xfd, 0x7b, 0x07, 0xa9, 0xfd, 0xc3, 0x01, 0x91,
                            0xa0, 0x83, 0x1f, 0xf8, 0xa1, 0x03, 0x1f, 0xf8, 0xa8, 0x83, 0x5f, 0xf8,
                            0x00, 0x21, 0x00, 0x91
                        };
                        void *loc_34340 = find_pattern_in_image((void *)base, 0x500000, pat_34340, sizeof(pat_34340));
                        if (loc_34340) {
                            // Target is the start of sub_34340 (8 bytes before SUB SP,SP,#0x80)
                            void *fn_34340 = (void *)((uintptr_t)loc_34340 - 8);
                            hook_function_abs(fn_34340, (void *)replaced_buildinfo_sub_34340);
                            RH_LOG("build-info: sub_34340 dynamic pattern hooked at %p", fn_34340);
                        } else {
                            // Fallback to offset 0x34340
                            hook_function_abs((void *)(base + 0x34340), (void *)replaced_buildinfo_sub_34340);
                            RH_LOG("build-info: sub_34340 fallback offset hooked at %p", (void *)(base + 0x34340));
                        }

                        // Signature 3: sub_40D734 (Checker 442)
                        static const uint8_t pat_40d734[] = {
                            0xe8, 0x77, 0x00, 0xf9, 0x48, 0x37, 0x80, 0x52, 0xe8, 0xe3, 0x00, 0xb9
                        };
                        void *loc_40d734 = find_pattern_in_image((void *)base, 0x500000, pat_40d734, sizeof(pat_40d734));
                        if (loc_40d734) {
                            // Target is start of sub_40D734 (56 bytes before MOV W8,#0x1BA)
                            void *fn_40d734 = (void *)((uintptr_t)loc_40d734 - 56);
                            hook_function_abs(fn_40d734, (void *)replaced_buildinfo_sub_40D734);
                            RH_LOG("build-info: sub_40D734 dynamic pattern hooked at %p", fn_40d734);
                        } else {
                            // Fallback to offset 0x40D734
                            hook_function_abs((void *)(base + 0x40D734), (void *)replaced_buildinfo_sub_40D734);
                            RH_LOG("build-info: sub_40D734 fallback offset hooked at %p", (void *)(base + 0x40D734));
                        }
                    }

                    method_setImplementation(m_gsc, imp_implementationWithBlock(
                        ^int(id _cls) {
                            RH_LOG("ShieldAPI.getShieldCode: intercepted -> return 0");
                            return 0;
                        }
                    ));
                    RH_LOG("ShieldAPI.getShieldCode: hooked → 0 (TCBRetail BShield)");
                } else {
                    RH_LOG("ShieldAPI.getShieldCode: method MISSING");
                }
            }

            // ── TCBRetail: Fix missing libdispatch stubs & TAGManager in main binary ──
            // On iOS 15.3, dyld binds stripped lazy dispatch stubs in TCBRetail to
            // _dyld_missing_symbol_abort, crashing in +[TAGManager subscribeToAppNotifications].
            // Fix: intercept +[TAGManager subscribeToAppNotifications] and populate
            // __la_symbol_ptr dispatch entries directly.
            Class tagManagerMeta = objc_getMetaClass("TAGManager");
            if (tagManagerMeta) {
                Method m_sub = class_getInstanceMethod(tagManagerMeta, @selector(subscribeToAppNotifications));
                if (m_sub) {
                    method_setImplementation(m_sub, imp_implementationWithBlock(^(id _cls) {
                        RH_LOG("TAGManager.subscribeToAppNotifications intercepted (no-op)");
                    }));
                    RH_LOG("TAGManager.subscribeToAppNotifications hooked");
                }
            }

            Class uiVcCls = objc_getClass("UIViewController");
            if (uiVcCls) {
                Method m_uivc_load = class_getClassMethod(uiVcCls, @selector(load));
                if (m_uivc_load) {
                    method_setImplementation(m_uivc_load, imp_implementationWithBlock(^(id _cls) {
                        RH_LOG("UIViewController(APMScreenClassName).load intercepted (no-op)");
                    }));
                    RH_LOG("UIViewController.load hooked");
                }
            }

            Class afUtilsMeta = objc_getMetaClass("AppsFlyerUtils");
            if (afUtilsMeta) {
                Method m_jb = class_getInstanceMethod(afUtilsMeta, @selector(isJailbrokenWithSkipAdvancedJailbreakValidation:));
                if (m_jb) {
                    method_setImplementation(m_jb, imp_implementationWithBlock(^BOOL(id _cls, BOOL skip) {
                        RH_LOG("AppsFlyerUtils.isJailbrokenWithSkipAdvancedJailbreakValidation: intercepted -> NO");
                        return NO;
                    }));
                    RH_LOG("AppsFlyerUtils.isJailbrokenWithSkipAdvancedJailbreakValidation: hooked");
                }
            }

            const struct mach_header *mainHeader = _dyld_get_image_header(0);
            if (mainHeader) {
                uintptr_t main_base = (uintptr_t)mainHeader;

                // Hook all +load methods in TCBRetail directly to prevent PAC / GULSwizzler crashes
                hook_function_abs((void *)(main_base + 0x17CAB4), (void *)replaced_tcbretail_noop); // UIViewController(APMScreenClassName) +load
                hook_function_abs((void *)(main_base + 0x1873C4), (void *)replaced_tcbretail_noop); // TAGManager +load
                hook_function_abs((void *)(main_base + 0x1873C8), (void *)replaced_tcbretail_noop); // TAGManager subscribeToAppNotifications
                hook_function_abs((void *)(main_base + 0x114364), (void *)replaced_tcbretail_noop); // APMMeasurement +load
                hook_function_abs((void *)(main_base + 0xD4F14), (void *)replaced_tcbretail_noop);  // FIRAnalyticsConnector +load
                hook_function_abs((void *)(main_base + 0xDA780), (void *)replaced_tcbretail_noop);  // APMAnalytics +load
                RH_LOG("TCBRetail: all 5 +load methods safely neutralized");
                // Fix all 21 libdispatch stubs in TCBRetail __la_symbol_ptr
                *(void **)(main_base + 0xE67B08) = (void *)dispatch_once;
                *(void **)(main_base + 0xE67B10) = (void *)dispatch_once_f;
                *(void **)(main_base + 0xE67B18) = (void *)dispatch_queue_create;
                *(void **)(main_base + 0xE67B20) = (void *)dispatch_queue_get_label;
                *(void **)(main_base + 0xE67B28) = (void *)dispatch_get_specific;
                *(void **)(main_base + 0xE67B30) = (void *)dispatch_queue_set_specific;
                *(void **)(main_base + 0xE67B38) = (void *)dispatch_source_create;
                *(void **)(main_base + 0xE67B40) = (void *)dispatch_source_set_timer;
                *(void **)(main_base + 0xE67B48) = (void *)dispatch_semaphore_create;
                *(void **)(main_base + 0xE67B50) = (void *)dispatch_semaphore_signal;
                *(void **)(main_base + 0xE67B58) = (void *)dispatch_semaphore_wait;
                *(void **)(main_base + 0xE67B60) = (void *)dispatch_sync;
                *(void **)(main_base + 0xE67B68) = (void *)dispatch_async;
                *(void **)(main_base + 0xE67B70) = (void *)dispatch_source_set_event_handler;
                *(void **)(main_base + 0xE67B78) = (void *)dispatch_resume;
                *(void **)(main_base + 0xE67B80) = (void *)dispatch_suspend;
                *(void **)(main_base + 0xE67B88) = (void *)dispatch_source_cancel;
                *(void **)(main_base + 0xE67B90) = (void *)dispatch_source_testcancel;
                *(void **)(main_base + 0xE67B98) = (void *)dispatch_get_global_queue;
                *(void **)(main_base + 0xE67BA0) = (void *)dispatch_time;
                *(void **)(main_base + 0xE67BA8) = (void *)dispatch_after;

                // Also hook stubs directly in __stubs via hook_function_abs
                hook_function_abs((void *)(main_base + 0xBB8320), (void *)dispatch_once);
                hook_function_abs((void *)(main_base + 0xBB832C), (void *)dispatch_once_f);
                hook_function_abs((void *)(main_base + 0xBB8338), (void *)dispatch_queue_create);
                hook_function_abs((void *)(main_base + 0xBB8344), (void *)dispatch_queue_get_label);
                hook_function_abs((void *)(main_base + 0xBB8350), (void *)dispatch_get_specific);
                hook_function_abs((void *)(main_base + 0xBB835C), (void *)dispatch_queue_set_specific);
                hook_function_abs((void *)(main_base + 0xBB8368), (void *)dispatch_source_create);
                hook_function_abs((void *)(main_base + 0xBB8374), (void *)dispatch_source_set_timer);
                hook_function_abs((void *)(main_base + 0xBB8380), (void *)dispatch_semaphore_create);
                hook_function_abs((void *)(main_base + 0xBB838C), (void *)dispatch_semaphore_signal);
                hook_function_abs((void *)(main_base + 0xBB8398), (void *)dispatch_semaphore_wait);
                hook_function_abs((void *)(main_base + 0xBB83A4), (void *)dispatch_sync);
                hook_function_abs((void *)(main_base + 0xBB83B0), (void *)dispatch_async);
                hook_function_abs((void *)(main_base + 0xBB83BC), (void *)dispatch_source_set_event_handler);
                hook_function_abs((void *)(main_base + 0xBB83C8), (void *)dispatch_resume);
                hook_function_abs((void *)(main_base + 0xBB83D4), (void *)dispatch_suspend);
                hook_function_abs((void *)(main_base + 0xBB83E0), (void *)dispatch_source_cancel);
                hook_function_abs((void *)(main_base + 0xBB83EC), (void *)dispatch_source_testcancel);
                hook_function_abs((void *)(main_base + 0xBB83F8), (void *)dispatch_get_global_queue);
                hook_function_abs((void *)(main_base + 0xBB8404), (void *)dispatch_time);
                hook_function_abs((void *)(main_base + 0xBB8410), (void *)dispatch_after);

                // Fix Foundation, Security, SystemConfiguration & UIKit stubs
                void *fn_nsClassFromString = (void *)NSClassFromString;
                void *fn_nsLog = (void *)NSLog;
                void *fn_nsLogv = (void *)NSLogv;
                void *fn_nsSearchPath = (void *)NSSearchPathForDirectoriesInDomains;
                void *fn_nsSelectorFromString = (void *)NSSelectorFromString;
                void *fn_nsStringFromSelector = (void *)NSStringFromSelector;
                void *fn_scReachCreate = dlsym(RTLD_DEFAULT, "SCNetworkReachabilityCreateWithName");
                void *fn_scReachSetCb = dlsym(RTLD_DEFAULT, "SCNetworkReachabilitySetCallback");
                void *fn_scReachSetQ = dlsym(RTLD_DEFAULT, "SCNetworkReachabilitySetDispatchQueue");
                void *fn_secDelete = dlsym(RTLD_DEFAULT, "SecItemDelete");
                void *fn_secCopy = dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
                void *fn_secAdd = dlsym(RTLD_DEFAULT, "SecItemAdd");
                void *fn_secUpdate = dlsym(RTLD_DEFAULT, "SecItemUpdate");
                void *fn_uiBeginImg = dlsym(RTLD_DEFAULT, "UIGraphicsBeginImageContextWithOptions");
                void *fn_uiGetImg = dlsym(RTLD_DEFAULT, "UIGraphicsGetImageFromCurrentImageContext");
                void *fn_uiEndImg = dlsym(RTLD_DEFAULT, "UIGraphicsEndImageContext");
                void *fn_uiGetCtx = dlsym(RTLD_DEFAULT, "UIGraphicsGetCurrentContext");
                void *fn_blockCopy = dlsym(RTLD_DEFAULT, "_Block_copy");
                void *fn_blockRel = dlsym(RTLD_DEFAULT, "_Block_release");
                void *fn_dladdr = (void *)dladdr;

                if (fn_nsClassFromString) *(void **)(main_base + 0xE675D8) = fn_nsClassFromString;
                if (fn_nsLog) *(void **)(main_base + 0xE675E0) = fn_nsLog;
                if (fn_nsLogv) *(void **)(main_base + 0xE675E8) = fn_nsLogv;
                if (fn_nsSearchPath) *(void **)(main_base + 0xE675F0) = fn_nsSearchPath;
                if (fn_nsSelectorFromString) *(void **)(main_base + 0xE675F8) = fn_nsSelectorFromString;
                if (fn_nsStringFromSelector) *(void **)(main_base + 0xE67608) = fn_nsStringFromSelector;
                if (fn_scReachCreate) *(void **)(main_base + 0xE67618) = fn_scReachCreate;
                if (fn_scReachSetCb) *(void **)(main_base + 0xE67620) = fn_scReachSetCb;
                if (fn_scReachSetQ) *(void **)(main_base + 0xE67628) = fn_scReachSetQ;
                if (fn_secDelete) *(void **)(main_base + 0xE67638) = fn_secDelete;
                if (fn_secCopy) *(void **)(main_base + 0xE67640) = fn_secCopy;
                if (fn_secAdd) *(void **)(main_base + 0xE67648) = fn_secAdd;
                if (fn_secUpdate) *(void **)(main_base + 0xE67650) = fn_secUpdate;
                if (fn_uiBeginImg) *(void **)(main_base + 0xE67680) = fn_uiBeginImg;
                if (fn_uiGetImg) *(void **)(main_base + 0xE67690) = fn_uiGetImg;
                if (fn_uiEndImg) *(void **)(main_base + 0xE67698) = fn_uiEndImg;
                if (fn_uiGetCtx) *(void **)(main_base + 0xE676A0) = fn_uiGetCtx;
                if (fn_blockCopy) *(void **)(main_base + 0xE676B8) = fn_blockCopy;
                if (fn_blockRel) *(void **)(main_base + 0xE676C0) = fn_blockRel;
                if (fn_dladdr) *(void **)(main_base + 0xE67BD0) = fn_dladdr;

                // Also hook directly in __stubs for maximum safety
                if (fn_nsClassFromString) hook_function_abs((void *)(main_base + 0xBB7B1C), fn_nsClassFromString);
                if (fn_nsLog) hook_function_abs((void *)(main_base + 0xBB7B28), fn_nsLog);
                if (fn_nsLogv) hook_function_abs((void *)(main_base + 0xBB7B34), fn_nsLogv);
                if (fn_nsSearchPath) hook_function_abs((void *)(main_base + 0xBB7B40), fn_nsSearchPath);
                if (fn_nsSelectorFromString) hook_function_abs((void *)(main_base + 0xBB7B4C), fn_nsSelectorFromString);
                if (fn_nsStringFromSelector) hook_function_abs((void *)(main_base + 0xBB7B64), fn_nsStringFromSelector);
                if (fn_scReachCreate) hook_function_abs((void *)(main_base + 0xBB7B7C), fn_scReachCreate);
                if (fn_scReachSetCb) hook_function_abs((void *)(main_base + 0xBB7B88), fn_scReachSetCb);
                if (fn_scReachSetQ) hook_function_abs((void *)(main_base + 0xBB7B94), fn_scReachSetQ);
                if (fn_secDelete) hook_function_abs((void *)(main_base + 0xBB7BAC), fn_secDelete);
                if (fn_secCopy) hook_function_abs((void *)(main_base + 0xBB7BB8), fn_secCopy);
                if (fn_secAdd) hook_function_abs((void *)(main_base + 0xBB7BC4), fn_secAdd);
                if (fn_secUpdate) hook_function_abs((void *)(main_base + 0xBB7BD0), fn_secUpdate);
                if (fn_uiBeginImg) hook_function_abs((void *)(main_base + 0xBB7C18), fn_uiBeginImg);
                if (fn_uiGetImg) hook_function_abs((void *)(main_base + 0xBB7C30), fn_uiGetImg);
                if (fn_uiEndImg) hook_function_abs((void *)(main_base + 0xBB7C3C), fn_uiEndImg);
                if (fn_uiGetCtx) hook_function_abs((void *)(main_base + 0xBB7C48), fn_uiGetCtx);
                if (fn_blockCopy) hook_function_abs((void *)(main_base + 0xBB7C6C), fn_blockCopy);
                if (fn_blockRel) hook_function_abs((void *)(main_base + 0xBB7C78), fn_blockRel);
                if (fn_dladdr) hook_function_abs((void *)(main_base + 0xBB841C), fn_dladdr);

                RH_LOG("TCBRetail: extended Foundation/Security/SystemConfiguration stubs mapped and fixed at main_base=%p", (void *)main_base);
            }
        }
        // ── Hook +[MC1 isFrameworkAvailable] → NO ────────────────────────────────
        // IDA-verified (r82q): MC1.isFrameworkAvailable (0x20790) uses NSFileManager
        // contentsOfDirectoryAtPath:error: (via getAllFramworks 0x20394) to scan the
        // app bundle's /Frameworks directory — NOT dyld image list APIs. Fix B
        // (_dyld_image_count hooks) is for MWkpr/reason=4; it does not affect MC1.
        //
        // MC1 detection conditions (505000 → reason=5):
        //   (a) mobilebankingx.framework absent or tampered (canary missing)
        //   (b) ElleKit.framework or CydiaSubstrate.framework found in /Frameworks
        //   (c) BSDPMRHide honeypot triggered (separate check in doMC1)
        //
        // For Dopamine/RootHide: conditions (a) and (b) NATURALLY PASS — canary IS
        // in the IPA, and rootless-path dylibs never appear in the app bundle's
        // /Frameworks. This hook is belt-and-suspenders against edge cases.
        {
            Class mc1Meta = objc_getMetaClass("MC1");
            if (mc1Meta) {
#ifdef RHHIDE_DEBUG
                {
                    unsigned int mc = 0;
                    Method *ms = class_copyMethodList(mc1Meta, &mc);
                    RH_LOG("MC1: %u class methods", mc);
                    for (unsigned int i = 0; i < mc; i++) {
                        RH_LOG("  MC1[%u]: +%s imp=%p", i,
                               sel_getName(method_getName(ms[i])),
                               (void *)method_getImplementation(ms[i]));
                    }
                    if (ms) free(ms);
                }
#endif
                Method m_ifa = class_getInstanceMethod(mc1Meta,
                                   @selector(isFrameworkAvailable));
                if (m_ifa) {
                    method_setImplementation(m_ifa, imp_implementationWithBlock(
                        ^BOOL(id _cls) {
                            RH_LOG("MC1.isFrameworkAvailable: BLOCKED → NO");
                            return NO;
                        }
                    ));
                    RH_LOG("MC1.isFrameworkAvailable: hooked");
                } else {
                    RH_LOG("MC1: isFrameworkAvailable method MISSING");
                }
            } else {
                RH_LOG("MC1 metaclass NOT FOUND");
            }
        }
        // ── Hook openURL:options:completionHandler: → block nbowree redirects ──────
        // Promon Shield fires reason=4 before BlueShield's checkTrustedEnv ever
        // runs. sub_2E4400 schedules sub_2E582C on _dispatch_main_q; when the
        // block fires it calls sub_2E505C which calls openURL with the nbowree URL.
        // Returning handler(NO) prevents Promon's completion block from calling
        // exit(). Production: no RH_LOG (BSLogCek can find no bypass evidence).
        // Installed before the objc_getClass tracer so UIApplication lookup is quiet.
        {
            Class uiAppCls = objc_getClass("UIApplication");
            if (uiAppCls) {
                Method m_ouo = class_getInstanceMethod(uiAppCls,
                                    @selector(openURL:options:completionHandler:));
                if (m_ouo) {
                    s_orig_openURL_opts = method_setImplementation(
                        m_ouo, (IMP)replaced_openURL_opts);
                    RH_LOG("openURL:opts:handler: hooked (Promon/nbowree redirect block)");
                } else {
                    RH_LOG("openURL:opts:handler: method MISSING");
                }
            }
        }
        // ── Hook Promon Shield sub_6A358 → no-op ─────────────────────────────────
        // sub_6A358 (mobilebankingx.framework file offset 0x6A358) reads
        // dyld_all_image_infos directly (bypassing Fix B API hooks) and calls
        // sub_2E4400(4, ...) when it detects roothideinit.dylib / roothidehooks.dylib
        // / libellekit.dylib. Hook it to return 0 immediately.
        // Base computed via dladdr on the +[PRMShieldEventManager load] IMP, which
        // lives in mobilebankingx's __TEXT. Installed before +load fires.
        {
            Class prmCls = objc_getClass("PRMShieldEventManager");
            if (prmCls) {
                Method loadM = class_getClassMethod(prmCls, @selector(load));
                if (loadM) {
                    IMP loadImp = method_getImplementation(loadM);
                    Dl_info dlInfo = {0};
                    if (dladdr((void*)loadImp, &dlInfo) && dlInfo.dli_fbase) {
                        uintptr_t base = (uintptr_t)dlInfo.dli_fbase;
                        // Hook 1: sub_6A358 — CFF engine A, dispatches reason=4 at 0x71B48
                        void *target = (void*)(base + 0x6A358);
                        MSHookFunction(target, (void*)replaced_promon_scanner,
                                       (void**)&orig_promon_scanner);
                        RH_LOG("Promon sub_6A358 hooked base=%p target=%p",
                               (void*)base, target);
                        // Hook 2: sub_4F1DE8 — CFF engine B, also dispatches reason=4 at 0x4F7ED4.
                        // IDA-verified: same prologue/structure as sub_6A358, same module pattern,
                        // also called via function pointer from Promon's module system.
                        void *target2 = (void*)(base + 0x4F1DE8);
                        MSHookFunction(target2, (void*)replaced_promon_scanner,
                                       (void**)&orig_promon_scanner2);
                        RH_LOG("Promon sub_4F1DE8 hooked base=%p target=%p",
                               (void*)base, target2);
                        // Hook 3: sub_27B1A8 — CFF engine C, dispatches reason=5 at 0x27BE04.
                        // IDA-verified (2qvw): single call to sub_2E4400(5,...) at 0x27BE04.
                        // Called from sub_70ACA8 (direct BL at 0x70ACF0) and also stored as
                        // function pointer in sub_4FC800. Runtime log confirmed firing (bshield-1.log).
                        void *target3 = (void*)(base + 0x27B1A8);
                        MSHookFunction(target3, (void*)replaced_promon_scanner,
                                       (void**)&orig_promon_scanner3);
                        RH_LOG("Promon sub_27B1A8 hooked base=%p target=%p",
                               (void*)base, target3);
                    } else {
                        RH_LOG("Promon sub_6A358/sub_4F1DE8/sub_27B1A8: dladdr failed");
                    }
                } else {
                    RH_LOG("Promon engines: PRMShieldEventManager +load MISSING");
                }
            }
        }
#ifdef RHHIDE_DEBUG
        // ── Debug: hook objc_getClass → log all non-nil class lookups ────────────
        // Caller filter removed (see comment in replaced_objc_getClass_fn above).
        // Installed LAST so we don't log our own init-time objc_getClass calls above.
        MSHookFunction((void *)objc_getClass,
                       (void *)replaced_objc_getClass_fn,
                       (void **)&orig_objc_getClass_fn);
        RH_LOG("objc_getClass hooked (class hit tracer)");
#endif
    }
}
