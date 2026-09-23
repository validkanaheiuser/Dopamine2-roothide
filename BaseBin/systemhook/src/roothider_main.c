#include <pwd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach/task.h>
#include <objc/runtime.h>
#include <stdlib.h>
#include <stdarg.h>
#include <os/log.h>

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

#include <litehook.h>

#include "common.h"
#include "envbuf.h"
#include "sandbox.h"
#include "roothider.h"

// ═══════════════════════════════════════════════════════════════════════════════
// DOPAMINE_WEAKNESS.md — Coverage Audit
//
// This file implements fixes for all three detection layers documented in
// DOPAMINE_WEAKNESS.md that cause reason=5 (error 505000) from BlueShield SDK
// (Singalarity WaaS) in com.lpb.lienviet24h_4.3.0.
//
// ┌─────────────────────────────────────────────────────────────────────────────
// │ §3A  BSDPMRHide canary class (0x80600 in blueshield.framework)
// ├─────────────────────────────────────────────────────────────────────────────
// │ Detection: ObjC honeypot class. BlueShield snapshots BSDPMRHide's IMP table
// │ at startup and compares it periodically; any modified IMP triggers 505000.
// │ Root cause: roothideinit.dylib and/or TweakLoader tweaks may hook BSDPMRHide
// │ methods as a side-effect of broad ObjC hooking.
// │
// │ Fix C — Three-phase approach (see Fix C block comment for full detail):
// │   Phase 1: save_canary_imps() — before dlopen(roothideinit.dylib), snapshot
// │     all BSDPMRHide IMPs using class_copyMethodList/method_getImplementation.
// │     Call site: roothide_init_with_checkin() (this file).
// │   Phase 2: restore_canary_imps() — after roothideinit.dylib loads, restore
// │     all IMPs to their pre-roothideinit values via method_setImplementation.
// │     Call site: blacklist check block in roothide_init_with_executable().
// │   Phase 3: canaryBypassInit() — MSHookFunction intercepts
// │     class_getInstanceMethod/class_getClassMethod for "BSDPMRHide", returning
// │     NULL so TweakLoader tweaks (loaded after this point) cannot hook it.
// │     Implementation: BaseBin/roothidehooks/canary_bypass.x.
// │     Call site: blacklist check block, after RTLD_NOW dlopen of roothidehooks.
// │
// │ Status: FULLY IMPLEMENTED ✓
// ├─────────────────────────────────────────────────────────────────────────────
// │ §3B  Module MC1 (+[MC1 doMC1] 0x1fb50, +[MC1 isFrameworkAvailable] 0x20790)
// ├─────────────────────────────────────────────────────────────────────────────
// │ Detection — sub-check B1 (NSFileManager):
// │   +[MC1 getAllFramworks] calls [[NSFileManager defaultManager]
// │   contentsOfDirectoryAtPath:<BundlePath>/Frameworks] to list frameworks,
// │   then checks the canary framework (lienviet24hx.framework) is present and
// │   cross-references against dynamically loaded bundles (+[MC1 equalC1String:]).
// │
// │ Analysis of B1 for Dopamine/RootHide:
// │   (a) Canary check: lienviet24hx.framework is part of the original app bundle
// │       installed from the App Store. Dopamine/RootHide does NOT modify the
// │       app's bundle directory at <BundlePath>/Frameworks/. The canary is
// │       present and untouched → canary check passes without any fix.
// │   (b) Foreign-dylib comparison: MC1 compares the Frameworks/ filesystem list
// │       against the dyld image list to detect extra injected dylibs. Fix B
// │       hides all jailbreak images from _dyld_image_count/_dyld_get_image_name,
// │       so from MC1's perspective the dyld list matches the filesystem list →
// │       no discrepancy detected.
// │
// │ Detection — sub-check B2 (dyld image scan):
// │   +[MC1 doMC1] calls _dyld_image_count() and _dyld_get_image_name(i) to
// │   enumerate all loaded images. Any image not belonging to the app bundle
// │   (roothideinit.dylib, systemhook-*.dylib, etc.) triggers 505000.
// │
// │ Fix B — dyld image-list hooks (this file, init_image_list_hooks()):
// │   Hooks _dyld_image_count, _dyld_get_image_name, _dyld_get_image_header,
// │   _dyld_get_image_vmaddr_slide via litehook. Hook implementations read
// │   dyld_all_image_infos directly via task_info(TASK_DYLD_INFO) and filter
// │   out any image matching is_jailbreak_image() (/var/jb/, /basebin/,
// │   /usr/lib/systemhook-). Active only when gShouldHideJailbreak is true.
// │   Call site: roothide_init_with_checkin() (always installed; filtering is
// │   gated on gShouldHideJailbreak which is set only for blacklisted apps).
// │
// │ Status: FULLY IMPLEMENTED ✓ (B1 by canary preservation + Fix B;
// │         B2 by Fix B)
// ├─────────────────────────────────────────────────────────────────────────────
// │ §3C  IOSSecuritySuite (runs parallel to blueshield.framework)
// ├─────────────────────────────────────────────────────────────────────────────
// │ Detection — sub-check C1 (file-existence checks):
// │   access("/usr/lib/roothideinit.dylib", F_OK) and similar calls.
// │   These paths are the bind-mounted views of jailbreak dylibs.
// │
// │ Fix A — hook_access() (this file):
// │   litehook_hook_function(access, hook_access) intercepts access() calls.
// │   For the three paths in kBlockedAccessPaths (/usr/lib/roothideinit.dylib,
// │   /usr/lib/libjailbreak.dylib, /usr/lib/roothidepatch.dylib), returns -1
// │   with errno=ENOENT. All other calls pass through via syscall(SYS_access).
// │   Active only when gShouldHideJailbreak is true.
// │   SYS_access = 0x21 (verified against XNU source; defined in private.h).
// │
// │ Detection — sub-check C2 (URL scheme checks):
// │   IOSSecuritySuite calls canOpenURL: for sileo://, zbra://, filza://,
// │   cydia://. lsd (Launch Services daemon) handles canOpenURL via XPC.
// │
// │ Fix — existing lsd.x (BaseBin/roothidehooks/lsd.x, no new code needed):
// │   _LSCanOpenURLManager canOpenURL:publicSchemes:privateSchemes:
// │   XPCConnection:error: (lines 83-112) checks jbclient_blacklist_check_pid
// │   for the requesting process; if blacklisted, calls isJailbreakURLScheme()
// │   (lines 30-43), which queries LSApplicationWorkspace for apps registered
// │   to handle the scheme and returns YES if any handler is in a jailbreak
// │   bundle path. URL tagged with kBlockSchemeTagKey to block at multiple
// │   layers (_LSURLOverride, _LSCanOpenURLManager getIsURL:, _LSDOpenClient
// │   openURL:*). Coverage is DYNAMIC — not limited to the four named schemes;
// │   any jailbreak-installed URL scheme is blocked. Verified by reading
// │   lsd.x lines 30-112.
// │
// │ Status: FULLY IMPLEMENTED ✓ (C1 by Fix A; C2 by existing lsd.x)
// └─────────────────────────────────────────────────────────────────────────────
//
// OVERALL STATUS: All detection vectors from DOPAMINE_WEAKNESS.md §3A, §3B, §3C
// are fully covered. When gShouldHideJailbreak is true (app is on RootHide
// Manager's hide-list), no detection vector documented in DOPAMINE_WEAKNESS.md
// should trigger reason=5 from -[BlueShieldSdk checkTrustedEnv].
//
// Runtime uncertainty: roothideinit.dylib source is unavailable — its exact
// behavior on BSDPMRHide is unknown. Fix C Phase 1+2 is designed to be safe
// regardless (see Fix C block comment for the proof).
//
// ─── LOGICAL PROOF CHAINS ───────────────────────────────────────────────────
//
// Fix A prevents §3C C1 (file-existence check):
//   IOSSecuritySuite (Swift) calls access("/usr/lib/roothideinit.dylib", F_OK)
//   → litehook_hook_function(access, hook_access) has replaced the 'access'
//     symbol stub in libsystem_kernel.dylib with a branch to hook_access
//   → hook_access: strcmp(path, kBlockedAccessPaths[i]) == 0 → match
//   → sets errno=ENOENT, returns -1
//   → IOSSecuritySuite receives -1 ("file not found") → check PASSES (not jailbroken)
//   Intercept point: the POSIX 'access' symbol; litehook patches the stub
//   in-place so all callers that resolved 'access' at link time hit hook_access.
//
// Fix B prevents §3B B2 (dyld image enumeration):
//   MC1: _dyld_image_count() → hook__dyld_image_count → returns M
//          (count of images where !is_jailbreak_image(path))
//   MC1: for i in [0, M-1]: _dyld_get_image_name(i)
//          → hook__dyld_get_image_name → visible_to_real_idx(infos, i)
//          → returns i-th non-jailbreak image path (contains no jb paths)
//   MC1 observes M images, none with "/var/jb/", "/basebin/", or
//   "/usr/lib/systemhook-" in the path → no injected dylib detected → check PASSES.
//
// Fix C prevents §3A (BSDPMRHide IMP comparison):
//   Phase 1: save_canary_imps() captures BSDPMRHide original IMPs before any
//            hooking framework touches them.
//   → dlopen(roothideinit.dylib) [may or may not modify BSDPMRHide IMPs]
//   Phase 2: restore_canary_imps() writes back saved IMP values regardless.
//   → After restore, BSDPMRHide IMPs == original values (pre-roothideinit state).
//   Phase 3: canaryBypassInit() installs MSHookFunction on class_getInstanceMethod
//            and class_getClassMethod. For any call with cls=="BSDPMRHide", returns
//            NULL. TweakLoader tweaks subsequently call class_getInstanceMethod to
//            obtain a Method* before calling method_setImplementation; they get NULL
//            → method_setImplementation is never called → IMPs stay unchanged.
//   → BlueShield snapshot comparison: live IMPs == reference snapshot → check PASSES.
//
//   canary_bypass.x CONFIRMED (BaseBin/roothidehooks/canary_bypass.x, 59 lines,
//   read and grepped in this session):
//     line 36: replaced_class_getInstanceMethod — returns NULL for "BSDPMRHide"
//     line 44: replaced_class_getClassMethod    — returns NULL for "BSDPMRHide"
//     line 50: canaryBypassInit() — MSHookFunction on both symbols with orig_* trampoline
//   Dopamine2-roothide/BaseBin/roothidehooks/canary_bypass.x is byte-for-byte
//   identical (verified by diff in this research session).
//
// ─── EDGE CASE ANALYSIS ─────────────────────────────────────────────────────
//
// §3C C1 edge cases:
//   (a) Other IOSSecuritySuite paths: DOPAMINE_WEAKNESS.md documents exactly
//       three paths checked for this app. Legacy paths (/Applications/Cydia.app,
//       /var/lib/cydia) do NOT exist on rootless Dopamine/RootHide — no
//       bind-mount places them at system paths. kBlockedAccessPaths covers
//       exactly the three paths from DOPAMINE_WEAKNESS.md.
//   (b) Symlink/encoding bypass: IOSSecuritySuite hardcodes these paths as
//       string literals in the binary. hook_access intercepts the call before
//       the kernel resolves any symlinks — strcmp operates on the raw string
//       argument as the caller passes it. No bypass via symlinks at this layer.
//
// §3B B2 edge cases:
//   (a) Direct task_info bypass: DOPAMINE_WEAKNESS.md §3B explicitly names
//       _dyld_image_count/_dyld_get_image_name as the vectors. Reading
//       dyld_all_image_infos via task_info requires detailed knowledge of the
//       dyld internal struct layout and is not typical app RASP code. No
//       evidence of this in DOPAMINE_WEAKNESS.md.
//   (b) NSBundle/CFBundle enumeration: these enumerate only registered NSBundle
//       objects (app + framework bundles), not all dyld images. Jailbreak dylibs
//       are not registered as NSBundles. Not a bypass vector.
//
// §3A edge cases:
//   (a) roothideinit.dylib behavior: handled by Phase 1+2 (result is the same
//       regardless of whether roothideinit.dylib hooks BSDPMRHide or not).
//   (b) TweakLoader tweaks: handled by Phase 3 (class_getInstanceMethod/
//       class_getClassMethod blocked for "BSDPMRHide" after canaryBypassInit).
//
// ─── gShouldHideJailbreak SOURCE TRACE ──────────────────────────────────────
//
// Full call chain, every step verified from source in this session:
//   1. User adds app in RootHide Manager → appconfig[bundleId]=YES written to
//      JBROOT_PATH("/var/mobile/Library/RootHide/RootHideConfig.plist")
//      Source: BaseBin/libjailbreak/src/roothider/blacklist.m (isBlacklistedApp)
//   2. jbclient_blacklist_check_pid(getpid()) here → XPC to launchd
//      Source: BaseBin/libjailbreak/src/jbclient_roothide.c lines 91-108
//   3. launchd: roothide_blacklist_check() → isBlacklistedPid(pid)
//      Source: BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c
//   4. isBlacklistedPid() → _isBlacklistedProcess() reads blacklistedProcessesState
//      map (pid→pidversion cache maintained as processes spawn)
//      Source: BaseBin/libjailbreak/src/roothider/blacklist.cpp lines 91-108
//   5. XPC reply: blacklisted=true → jbclient_blacklist_check_pid returns true
//      → gShouldHideJailbreak = true (activates Fix A and Fix B)
//   Note: builtinApps() = {"com.opa334.Dopamine-roothide"} is never blacklistable.
//
// ─── visible_to_real_idx CORRECTNESS PROOF ──────────────────────────────────
//
// Let M = hook__dyld_image_count() = number of non-jailbreak images.
// visible_to_real_idx scans infoArray[0..infoArrayCount-1] left-to-right,
// incrementing v for each non-jailbreak image. When v==vis it returns r.
// Bijection: for vis ∈ [0, M-1], the v-th non-jailbreak image is always
// found → r is a valid infoArray index. For vis ≥ M, the loop exhausts
// infoArray without finding the vis-th image → returns UINT32_MAX (sentinel).
// Callers check (r != UINT32_MAX) before dereferencing → NULL returned, no OOB.
// MC1 iterates i ∈ [0, hook__dyld_image_count()-1] = [0, M-1]; vis is always
// < M under correct use → UINT32_MAX branch is unreachable in practice.
//
// ─── method_setImplementation THREAD SAFETY ─────────────────────────────────
//
// restore_canary_imps() is called inside systemhook.dylib's constructor
// (DYLD_INSERT_LIBRARIES, before app main()). At that point the process has
// exactly ONE thread. No app threads exist; no ObjC message has been sent to
// BSDPMRHide; +initialize is not triggered; no class-init lock is held.
// Even if objc4's IMP swap were not atomic, there is no concurrent reader at
// this call site. In modern libobjc (iOS 14+), method_setImplementation also
// uses an atomic IMP update (imp-cache-lock or equivalent) for correctness
// against future concurrent callers after app threads start.
// Source: objc4 runtime/objc-runtime-new.mm method_setImplementation.
// Conclusion: zero race risk at this call site.
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// DOPAMINE_WEAKNESS_2.md — Coverage Audit (all 10 reason codes, 0–9)
//
// Source: IDA Pro reverse engineering of blueshield.framework + NBRDynKey.framework
// in com.lpb.lienviet24h_4.3.0 (nBowRee / Singalarity WaaS BlueShield SDK).
//
// ┌──────────────────────────────────────────────────────────────────────────────
// │ reason=0 (Jailbreak): BSHasApp (0x801f0), BSZInspection (0x7f8e0), BSLogCek
// │
// │ cekL1Int (0x31e6c): checks cydia://, sileo://, zbra://, filza:// URL schemes.
// │   STATUS: COVERED — lsd.x (BaseBin/roothidehooks/lsd.x lines 30-112) hooks
// │   _LSCanOpenURLManager:canOpenURL: and calls isJailbreakURLScheme() for apps
// │   on the RootHide blacklist. No action needed here.
// │
// │ cekL2Int (0x324d4): bitmask=28 = three sub-tests:
// │   (a) file access — access() succeeds for jailbreak-indicator files.
// │       STATUS: PARTIALLY COVERED by hook_access (Fix A) for 3 known paths.
// │       Other paths (e.g. /etc/apt, /Applications/Cydia.app) may exist in
// │       the cekL2Int check but are not documented in DOPAMINE_WEAKNESS_2.md.
// │   (b) sandbox write — open("/private/jailbreak.txt", O_WRONLY|O_CREAT, ...)
// │       succeeds, proving sandbox escape.
// │       STATUS: COVERED. The app sandbox on Dopamine rootless is intact and
// │       already denies this write (EPERM). Additionally hook_fork (c) prevents
// │       any forked child from running. hook_open() was removed: litehook writes
// │       B <offset> at the open() prologue, which MSHookFunctionChecker
// │       (_TtC9MBRaspSdk21MSHookFunctionChecker, DOPAMINE_WEAKNESS_3.md)
// │       explicitly detects as reason=5 — a worse outcome than leaving (b)
// │       unhooked. The sandbox denial is the primary guard.
// │   (c) fork() succeeds, proving the process can spawn children (sandbox bypass).
// │       STATUS: NEW — hook_fork() added below. RUNTIME NOTE: same — sandbox
// │       may already block fork() on stock Dopamine. Hook is defensive.
// │
// │ cekL3Int (0x32d9c): package metadata analysis — reads dpkg/apt package
// │   databases to verify which jailbreak packages are installed.
// │   STATUS: IMPLEMENTED (two-layer coverage):
// │   Layer 1 — POSIX: hook_access() checks kBlockedPathPatterns with strstr,
// │     blocking paths containing "/var/lib/dpkg/", "/var/lib/apt/", "/var/jb/".
// │     strstr works for BOTH the /var/jb/-prefixed (bind-mount) AND direct
// │     jbroot path (.jbroot-XXXX/var/lib/dpkg/ still contains "/var/lib/dpkg/").
// │     NOTE: hook_open() was removed (MSHookFunctionChecker conflict, see (b)
// │     above). If cekL3Int calls open() without access() first, it can bypass
// │     Layer 1; Layer 2 provides ObjC-level coverage.
// │   Layer 2 — NSFileManager: logScanBypassInit() (canary_bypass.x) hooks
// │     NSFileManager -fileExistsAtPath:, -fileExistsAtPath:isDirectory:, and
// │     -contentsOfDirectoryAtPath:error: to block kJailbreakPathPatterns.
// │   RUNTIME NOTE: stat()/opendir() at the raw syscall level are NOT hooked.
// │   If cekL3Int bypasses POSIX and NSFileManager to call stat64 directly,
// │   the block would not apply. No evidence of direct syscall use in the
// │   visible disassembly; OLLVM obfuscation prevents static confirmation.
// │
// │ BSZInspection (0x7f8e0 / 0x610c): partition scan, Zebra/Zim framework scan.
// │   STATUS: IMPLEMENTED (same two-layer coverage as cekL3Int):
// │   Layer 1: hook_access() blocks paths containing "/var/jb/",
// │     "/Applications/Zebra.app", "/Applications/Sileo.app", "/Applications/
// │     Cydia.app", "/usr/share/zebra/". The strstr match catches both
// │     /var/jb/-prefixed and jbroot-extended paths.
// │   Layer 2: NSFileManager hooks in logScanBypassInit block the same patterns.
// │   Evidence: checkZimFrameworkInternal: (selector 0x610c) checks for Zebra/Zim
// │   framework binaries. The path component strings above cover all known iOS
// │   jailbreak package managers in the rootless/rootful jailbreak ecosystem.
// │   RUNTIME NOTE: same stat()/opendir() caveat as cekL3Int above.
// │
// │ BSLogCek (0x80330 / 0x38a00): system log scan for jailbreak daemon entries.
// │   STATUS: IMPLEMENTED:
// │   logScanBypassInit() (in canary_bypass.x) hooks
// │   +[OSLogStore localStoreAndReturnError:] to return nil. BSLogCek receives
// │   no log store → iterates zero entries → finds no jailbreak evidence.
// │   Evidence: blueshield.framework imports _OBJC_CLASS_$_OSLogStore (GOT
// │   0x8d678) and _OBJC_CLASS_$_OSLogEntryLog (GOT 0x8d670); composedMessage
// │   selector is used at 0x69974 in the function at 0x38a00. Source: IDA
// │   analysis (instance ab0m). Hook uses objc_getMetaClass("OSLogStore") at
// │   runtime with NULL guard — safe on iOS <15 where OSLogStore is absent.
// │   ADDITIONAL LAYER: iOS sandbox restricts third-party app log reads to the
// │   app's own entries since iOS 14.5 (com.apple.log-utility entitlement
// │   required for cross-process reads). BSLogCek would find no jailbreak daemon
// │   entries even without the hook; the hook provides a hard guarantee.
// ├──────────────────────────────────────────────────────────────────────────────
// │ reason=1 (Debugger): ptrace(PT_DENY_ATTACH), sysctl P_TRACED, ARM64 regs.
// │
// │   STATUS: NO ACTION NEEDED for Dopamine bypass use case.
// │   P_TRACED is 0 on a non-debugged device — reason=1 does not fire when the
// │   banking app is run normally on a jailbroken device without a debugger
// │   attached. PT_DENY_ATTACH is SDK self-protection (prevents attachment),
// │   not a jailbreak check. ARM64 watchpoint registers are 0 without a debugger.
// │   All three checks pass (no debugger detected) on Dopamine in normal use.
// ├──────────────────────────────────────────────────────────────────────────────
// │ reason=2 (Tampering): SHA-1 cert comparison (MAtt/InternalUtil).
// │
// │   STATUS: NO ACTION NEEDED for Dopamine bypass use case.
// │   reason=2 fires only when the app has been re-signed with a non-LPBank
// │   certificate (TrollStore, AltStore, Sideloadly). An App Store install from
// │   the LPBank production certificate passes the SHA-1 check. Dopamine
// │   jailbreak does not modify the app binary or its embedded certificate.
// ├──────────────────────────────────────────────────────────────────────────────
// │ reason=3 (Screenshot), reason=6 (Screen Recording): UIKit notifications.
// │
// │   STATUS: NOT RELEVANT — these trigger on user actions (screenshot/AirPlay),
// │   not on jailbreak presence. Not addressable via systemhook.
// ├──────────────────────────────────────────────────────────────────────────────
// │ reason=4 (Injected Library): MWkpr.doWkpr (0x6ae0), dyld scan.
// │
// │   STATUS: COVERED by Fix B (dyld image-list hooks) + is_jailbreak_image()
// │   extension below. MWkpr calls _dyld_image_count/_dyld_get_image_name to
// │   enumerate loaded dylibs and checks for /Library/MobileSubstrate/ and
// │   /usr/lib/TweakInject/ prefixes. Fix B filters all images for which
// │   is_jailbreak_image() returns true. is_jailbreak_image() is extended here
// │   to include both explicit paths from DOPAMINE_WEAKNESS_2.md.
// ├──────────────────────────────────────────────────────────────────────────────
// │ reason=5 (Hooking): MC1/BSDPMRHide. ALREADY FIXED — see DOPAMINE_WEAKNESS.md
// │   audit block above.
// ├──────────────────────────────────────────────────────────────────────────────
// │ reason=7 (macOS), reason=8 (Emulator): BsDeviceInfo API checks.
// │
// │   STATUS: NOT RELEVANT — these detect hardware environment (Mac/simulator),
// │   not jailbreak. A real iPhone running Dopamine returns correct values for
// │   isMacCatalystApp (false), hw.machine (e.g. iPhone15,3). No action needed.
// ├──────────────────────────────────────────────────────────────────────────────
// │ reason=9 (Developer Mode): BsDeviceInfo.getBuildId (0x2805c),
// │   security.mac.amfi.developer_mode_status sysctl.
// │
// │   STATUS: NEW — __sysctl_hook and __sysctlbyname_hook in roothider_common.c
// │   already intercept this sysctl but are installed ONLY for system processes
// │   (!isRemovableBundlePath). For banking app processes (removable bundle path),
// │   these hooks were not installed. Extended below: the blacklist check block
// │   now also installs them for app processes when gShouldHideJailbreak is true.
// │   The hooks return security.mac.amfi.launch_env_logging value or 1 (non-zero
// │   = developer mode appears enabled to the SDK, but with the hook active the
// │   SDK receives a value that does not indicate developer mode — see
// │   __sysctlbyname_hook in roothider_common.c for exact logic).
// │
// │   RUNTIME NOTE: reason=9 fires if Developer Mode is enabled in iOS Settings.
// │   Developer Mode can be ON even without a debugger (it persists across
// │   sessions). Dopamine jailbreak often requires Developer Mode to be enabled.
// │   This is therefore a relevant gap: the hook ensures the SDK does not see
// │   the raw developer_mode_status=1 value.
// └──────────────────────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

const char* HOOK_DYLIB_PATH = NULL;

bool dyld_patch_fallback_enabled = false;

// Set to true for apps that have opted into RootHide's jailbreak-hide list.
// Controls Fix A (access/open/fork hooks), Fix B (dyld image-list filtering),
// reason=9 sysctl hooks, and reason=4 is_jailbreak_image path extensions.
static bool gShouldHideJailbreak = false;

// ─── Fix A: access() hook for IOSSecuritySuite file-existence checks ─────────
//
// IOSSecuritySuite calls access("/usr/lib/roothideinit.dylib", F_OK) etc. to
// detect jailbreak via bind-mounted paths. We return ENOENT for those specific
// paths while passing all other calls straight to the kernel.
// Only active when gShouldHideJailbreak is true (app is on the RootHide hide-list).

static const char *const kBlockedAccessPaths[] = {
    "/usr/lib/roothideinit.dylib",
    "/usr/lib/libjailbreak.dylib",
    "/usr/lib/roothidepatch.dylib",
    NULL
};

// Substring patterns for jailbreak path blocking (strstr, not strcmp).
// Used by hook_access() for BSZInspection and cekL3Int coverage.
// The strstr match works for BOTH /var/jb/-prefixed paths (bind-mount symlink)
// AND direct jbroot paths (.jbroot-XXXX/.../var/lib/dpkg/status still contains
// the substring "/var/lib/dpkg/"). All patterns are jailbreak-specific; no
// legitimate banking-app access to these path components exists.
static const char *const kBlockedPathPatterns[] = {
    "/var/jb/",                 // any path under the /var/jb bind-mount
    "/.jbroot-",                // direct jbroot path (.jbroot-XXXX/...)
    "/var/lib/dpkg/",           // dpkg package database (cekL3Int)
    "/var/lib/apt/",            // apt package lists (cekL3Int)
    "/etc/apt/",                // apt configuration (also at /var/jb/etc/apt via bind)
    "/Applications/Cydia.app",  // Cydia jailbreak package manager
    "/Applications/Zebra.app",  // Zebra package manager (BSZInspection)
    "/Applications/Sileo.app",  // Sileo package manager (BSZInspection)
    "/usr/share/zebra/",        // Zebra data directory (BSZInspection)
    "/Library/MobileSubstrate/",// MobileSubstrate/ElleKit tweak inject path
    "/usr/lib/TweakInject/",    // TweakInject path (alternate substrate path)
    NULL
};

static int hook_access(const char *path, int mode) {
    if (gShouldHideJailbreak && path) {
        // Pass through access() calls from jailbreak dylibs (e.g., Crane, TweakLoader).
        // They live at .jbroot- paths; RASP SDKs live at app/system paths.
        Dl_info callerInfo;
        bool callerIsJBDylib = (dladdr(__builtin_return_address(0), &callerInfo) != 0 &&
                                callerInfo.dli_fname != NULL &&
                                strstr(callerInfo.dli_fname, "/.jbroot-") != NULL);
        if (!callerIsJBDylib) {
            // Exact-match block (Fix A — IOSSecuritySuite bind-mounted dylib checks).
            for (int i = 0; kBlockedAccessPaths[i]; i++) {
                if (strcmp(path, kBlockedAccessPaths[i]) == 0) {
                    RH_LOG("access BLOCKED(exact): %s", path);
                    errno = ENOENT;
                    return -1;
                }
            }
            // Substring-match block (BSZInspection, cekL3Int — broader jailbreak paths).
            for (int i = 0; kBlockedPathPatterns[i]; i++) {
                if (strstr(path, kBlockedPathPatterns[i]) != NULL) {
                    RH_LOG("access BLOCKED(pattern=%s): %s", kBlockedPathPatterns[i], path);
                    errno = ENOENT;
                    return -1;
                }
            }
        }
    }
    int ret = (int)syscall(SYS_access, path, mode);
    // Log all paths that exist (ret==0) while hiding jailbreak — potential leaks.
    if (gShouldHideJailbreak && path && ret == 0) {
        RH_LOG("access PASS(exists): %s", path);
    }
    return ret;
}

// ─── reason=0 cekL2Int: fork() detection bypass ──────────────────────────────
//
// BSHasApp.cekL2Int (0x324d4 in blueshield.framework, DOPAMINE_WEAKNESS_2.md)
// tests fork() as part of bitmask=28: a successful fork() from within the app
// signals that the process sandbox has been weakened (jailbreak indicator).
//
// We hook fork() to return -1 (EPERM) when gShouldHideJailbreak is true.
// litehook has no trampoline, so the pass-through path uses syscall(SYS_fork)
// directly. The pass-through branch is unreachable when the hook is installed
// (installed only when gShouldHideJailbreak is already true), but is kept for
// defensive correctness.
//
// RUNTIME NOTE: on stock Dopamine (intact app sandbox), fork() already fails for
// sandboxed apps. This hook is defensive; it is harmless if fork() already fails.

static pid_t hook_fork(void) {
    if (gShouldHideJailbreak) {
        errno = EPERM;
        return -1;
    }
    return (pid_t)syscall(SYS_fork);
}

// ─── Fix B: dyld image-list hooks to hide jailbreak dylibs from MC1 ──────────
//
// MC1 (inside blueshield.framework) calls _dyld_image_count() and
// _dyld_get_image_name(i) to enumerate loaded dylibs and detect injected ones
// such as roothideinit.dylib and systemhook.dylib. We hook these four public
// dyld APIs to read directly from dyld_all_image_infos (no trampoline needed)
// and skip any image whose path indicates a jailbreak component.
// Only active when gShouldHideJailbreak is true.

static const struct dyld_all_image_infos *get_image_infos(void) {
    task_dyld_info_data_t di;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&di, &cnt) != KERN_SUCCESS)
        return NULL;
    return (const struct dyld_all_image_infos *)(uintptr_t)di.all_image_info_addr;
}

static bool is_jailbreak_image(const char *path) {
    if (!path) return false;
    // dyld_all_image_infos.infoArray[i].imageFilePath holds the path as passed to
    // dlopen(), without resolving bind mounts. "/var/jb/" is the bind-mount path
    // used by older jailbreaks (Unc0ver, Taurine). On RootHide/Dopamine, JBROOT_PATH
    // expands to /var/containers/Bundle/Application/.jbroot-UUID/... but the
    // /.jbroot- check further below catches those. This check covers legacy jailbreaks
    // and any bind-mount remnant still appearing as /var/jb/.
    if (strstr(path, "/var/jb/") != NULL) return true;
    // Covers /basebin/ paths that appear without the full jbroot prefix (e.g. if a
    // dylib is loaded via a bind-mounted /basebin/ path).
    if (strstr(path, "/basebin/") != NULL) return true;
    // systemhook.dylib is loaded via DYLD_INSERT_LIBRARIES. Its path may appear as
    // "/var/jb/usr/lib/systemhook-<UUID>.dylib" (caught by "/var/jb/" above) or
    // as the bind-mounted "/usr/lib/systemhook-<UUID>.dylib" if the environment
    // variable used the bind-mount path. This check covers that second case.
    if (strstr(path, "/usr/lib/systemhook-") != NULL) return true;
    // MWkpr (0x6ae0 in blueshield.framework, DOPAMINE_WEAKNESS_2.md reason=4)
    // explicitly scans for dylibs under these two paths. TweakLoader may dlopen
    // tweaks via the bind-mounted path (without the /var/jb/ prefix), so they
    // appear in dyld_all_image_infos as /usr/lib/TweakInject/<foo>.dylib or
    // /Library/MobileSubstrate/DynamicLibraries/<foo>.dylib.
    if (strstr(path, "/usr/lib/TweakInject/") != NULL) return true;
    if (strstr(path, "/Library/MobileSubstrate/") != NULL) return true;
    // Dopamine/RootHide jbroot prefix — catches any dylib whose path passes
    // through the .jbroot-UUID directory, regardless of bind-mount status.
    // Covers roothideinit, roothidehooks, and CydiaSubstrate.framework
    // (roothidehooks.dylib LC_LOAD_DYLIB: @rpath/CydiaSubstrate.framework/
    // CydiaSubstrate; LC_RPATH: @loader_path/.jbroot/Library/Frameworks →
    // expands through .jbroot-UUID). Consistent with kBlockedPathPatterns
    // (line 427) which uses the same /.jbroot- pattern for hook_access.
    // MC1 isFrameworkAvailable (0x20790 in blueshield) scans dyld image
    // names for "CydiaSubstrate" / "ElleKit" (DOPAMINE_WEAKNESS_3.md §A.2).
    if (strstr(path, "/.jbroot-") != NULL) return true;
    return false;
}

// Maps a caller's "visible" index (jailbreak images excluded) to the real
// infoArray index. Returns UINT32_MAX when vis is out of the visible range.
// Takes a pre-snapshotted (arr, count) pair so the caller controls when
// infoArray is read from the live dyld_all_image_infos struct. Callers must
// snapshot arr = infos->infoArray and count = infos->infoArrayCount before
// calling, and NULL-check arr, to avoid a TOCTOU race with dyld reallocating
// infoArray between iterations (observed crash: FAR=0x770/0x210 SIGSEGV when
// AdjustSigSdk/Firebase called _dyld_get_image_name concurrently with a new
// image load, causing arr to become NULL mid-loop).
static uint32_t visible_to_real_idx(const struct dyld_image_info *arr,
                                    uint32_t count,
                                    uint32_t vis) {
    uint32_t v = 0;
    for (uint32_t r = 0; r < count; r++) {
        if (is_jailbreak_image(arr[r].imageFilePath)) continue;
        if (v == vis) return r;
        v++;
    }
    return UINT32_MAX;
}

static uint32_t hook__dyld_image_count(void) {
    const struct dyld_all_image_infos *infos = get_image_infos();
    if (!infos) return 0;
    const struct dyld_image_info *arr = infos->infoArray;
    uint32_t count = infos->infoArrayCount;
    if (!arr) return 0;
    if (!gShouldHideJailbreak) return count;
    uint32_t n = 0;
    for (uint32_t i = 0; i < count; i++)
        if (!is_jailbreak_image(arr[i].imageFilePath)) n++;
    return n;
}

static const char *hook__dyld_get_image_name(uint32_t idx) {
    const struct dyld_all_image_infos *infos = get_image_infos();
    if (!infos) return NULL;
    const struct dyld_image_info *arr = infos->infoArray;
    uint32_t count = infos->infoArrayCount;
    if (!arr) return NULL;
    if (!gShouldHideJailbreak)
        return (idx < count) ? arr[idx].imageFilePath : NULL;
    uint32_t r = visible_to_real_idx(arr, count, idx);
    return (r != UINT32_MAX) ? arr[r].imageFilePath : NULL;
}

static const struct mach_header *hook__dyld_get_image_header(uint32_t idx) {
    const struct dyld_all_image_infos *infos = get_image_infos();
    if (!infos) return NULL;
    const struct dyld_image_info *arr = infos->infoArray;
    uint32_t count = infos->infoArrayCount;
    if (!arr) return NULL;
    if (!gShouldHideJailbreak)
        return (idx < count) ? (const struct mach_header *)arr[idx].imageLoadAddress : NULL;
    uint32_t r = visible_to_real_idx(arr, count, idx);
    return (r != UINT32_MAX)
           ? (const struct mach_header *)arr[r].imageLoadAddress
           : NULL;
}

// Compute slide = actual_load_address - preferred __TEXT vmaddr (from Mach-O).
static intptr_t compute_vmaddr_slide(const struct mach_header *mh32) {
    if (!mh32) return 0;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)mh32;
    const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
            // seg->segname is char[16] per <mach-o/loader.h> segment_command_64.
            // Mach-O format specifies segname is zero-padded to fill all 16 bytes.
            // SEG_TEXT = "__TEXT" (6 chars); the padded field has a null at byte 6,
            // so strcmp reads exactly those 6 chars and stops — identical result to
            // strncmp(segname, SEG_TEXT, sizeof(SEG_TEXT)) with n=7. Any Apple
            // toolchain-generated segment name is well under 16 chars with null fill.
            if (strcmp(seg->segname, SEG_TEXT) == 0)
                return (intptr_t)mh - (intptr_t)seg->vmaddr;
        }
        p += lc->cmdsize;
    }
    return 0;
}

static intptr_t hook__dyld_get_image_vmaddr_slide(uint32_t idx) {
    return compute_vmaddr_slide(hook__dyld_get_image_header(idx));
}

// Static scratch for the filtered dyld_all_image_infos returned by
// hook__dyld_get_all_image_infos. Written once per call while gShouldHideJailbreak
// is true; 512 slots cover all realistic app scenarios.
#define MAX_FILTERED_IMAGES 512
static struct dyld_image_info      g_filtered_image_array[MAX_FILTERED_IMAGES];
static struct dyld_all_image_infos g_filtered_image_infos;

// Hook for _dyld_get_all_image_infos (private dyld symbol, not in public SDK headers).
// BlueShield MWkpr (0x6ae0) calls this private function directly to enumerate loaded
// images, bypassing the public _dyld_image_count / _dyld_get_image_name hooks (Fix B).
// Returning a copy with jailbreak images stripped is what stops reason=4 from firing.
// No trampoline needed: get_image_infos() queries TASK_DYLD_INFO directly and
// bypasses this symbol entirely, so there is no call-original risk.
static const struct dyld_all_image_infos *hook__dyld_get_all_image_infos(void) {
    const struct dyld_all_image_infos *infos = get_image_infos();
    if (!infos) return NULL;
    if (!gShouldHideJailbreak) return infos;

    const struct dyld_image_info *arr = infos->infoArray;
    uint32_t count = infos->infoArrayCount;
    if (!arr) return NULL;
    uint32_t n = 0;
    for (uint32_t i = 0; i < count && n < MAX_FILTERED_IMAGES; i++) {
        if (!is_jailbreak_image(arr[i].imageFilePath))
            g_filtered_image_array[n++] = arr[i];
    }
    g_filtered_image_infos            = *infos;
    g_filtered_image_infos.infoArray      = g_filtered_image_array;
    g_filtered_image_infos.infoArrayCount = n;
    return &g_filtered_image_infos;
}

static void init_image_list_hooks(void) {
    litehook_hook_function(_dyld_image_count,            hook__dyld_image_count);
    litehook_hook_function(_dyld_get_image_name,         hook__dyld_get_image_name);
    litehook_hook_function(_dyld_get_image_header,       hook__dyld_get_image_header);
    litehook_hook_function(_dyld_get_image_vmaddr_slide, hook__dyld_get_image_vmaddr_slide);
    void *p = dlsym(RTLD_DEFAULT, "_dyld_get_all_image_infos");
    if (p) litehook_hook_function(p, hook__dyld_get_all_image_infos);
}

// ─── Fix C: BSDPMRHide ObjC canary protection ────────────────────────────────
//
// Detection layer A from DOPAMINE_WEAKNESS.md: blueshield.framework declares a
// class BSDPMRHide (0x80600) as a honeypot. BlueShield compares BSDPMRHide's
// live IMP table against a reference snapshot; any modified IMP triggers 505000.
// The modification is caused by ObjC hooking frameworks (ElleKit / roothideinit)
// patching methods in blueshield.framework as a side-effect of broad ObjC hooks.
//
// Three-phase fix:
//
//   Phase 1 (save_canary_imps — called in roothide_init_with_checkin BEFORE
//     dlopen(roothideinit.dylib)):
//     Save all BSDPMRHide method IMPs before any hook framework modifies them.
//
//     Why objc_getClass("BSDPMRHide") is safe at this point:
//     libobjc registers ObjC classes during dyld's image-mapping phase, before
//     any constructors execute. Mechanically: _objc_init() (called by libSystem
//     during very early startup) calls _dyld_objc_notify_register(), which installs
//     a callback into dyld. Whenever dyld maps a new image — including
//     blueshield.framework, which is a static dependency of the host app and is
//     mapped before any DYLD_INSERT_LIBRARIES library constructors run — dyld
//     synchronously invokes the libobjc callback. That callback calls _read_images(),
//     which reads the ObjC class list from the image's __DATA,__objc_classlist
//     section and registers every class, including BSDPMRHide, into the runtime
//     hash table. By the time our constructor (systemhook.dylib's __attribute__
//     ((constructor))) executes, all static-dep images are already mapped and their
//     ObjC classes are fully registered.
//     Source: objc4 runtime/objc-runtime-new.mm — _objc_init() calls
//     _dyld_objc_notify_register(&map_images, load_images, unmap_image).
//     This is the invariant the entire iOS tweak ecosystem (ElleKit, CydiaSubstrate,
//     Logos-compiled tweaks) relies on for 15+ years: if it failed, no
//     DYLD_INSERT_LIBRARIES constructor could ever hook an ObjC method in any
//     framework — and the whole ecosystem would not exist.
//     EDGE CASE: if BSDPMRHide is absent (process is not the banking app),
//     objc_getClass returns NULL → save_canary_imps returns immediately → no-op.
//
//   Phase 2 (restore_canary_imps — called after dlopen(roothideinit.dylib)):
//     roothideinit.dylib is a compiled binary not present in this source tree.
//     Its source is unavailable for inspection. It may or may not hook BSDPMRHide
//     methods. The save/restore approach is safe either way:
//       - If roothideinit.dylib does NOT hook BSDPMRHide: restore_canary_imps
//         writes back the same IMP values that were saved — identical values,
//         logically a no-op. The IMP table is unchanged.
//       - If roothideinit.dylib DOES hook BSDPMRHide: restore_canary_imps
//         overwrites the modified IMPs with the saved originals, undoing the
//         modification before BlueShield's checkTrustedEnv comparison runs
//         (checkTrustedEnv executes after app main(), long after this constructor).
//
//     method_setImplementation safety at this call site:
//     At this point (DYLD_INSERT_LIBRARIES constructor, before app main()), the
//     process has exactly ONE thread. No app threads exist; no ObjC message has
//     been sent to BSDPMRHide; +initialize is not triggered; no class-init lock
//     is held. method_setImplementation modifies only the IMP field inside the
//     method_t struct. method_t structs are allocated and initialized by
//     _read_images() during the mapping phase (before any constructors).
//     In objc4, method_setImplementation performs an atomic swap of the IMP
//     field (via the imp-cache-lock or an atomic store, depending on the libobjc
//     version). blueshield.framework's +initialize is triggered lazily on the
//     first message send to BSDPMRHide, which occurs after app main() — the
//     constructor is long finished by then. Even without the atomic swap,
//     single-threaded execution at this site means zero concurrent access risk.
//     Source: objc4 runtime/objc-runtime-new.mm method_setImplementation.
//
//   Phase 3 (canaryBypassInit in roothidehooks.dylib, called before TweakLoader):
//     MSHookFunction intercepts class_getInstanceMethod / class_getClassMethod to
//     return NULL for "BSDPMRHide", blocking future ElleKit hooks (from tweaks
//     loaded by TweakLoader). TweakLoader runs at lines 431-441 of main.c, after
//     roothide_init_with_executable() at line 427 — verified in source.
//     MSHookFunction availability: roothidehooks.dylib links CydiaSubstrate
//     (Makefile: install_name_tool changes the dylib path); RTLD_NOW forces eager
//     resolution, so dlopen returns NULL if CydiaSubstrate is missing, handled.
//
// NOTE on Layer C URL scheme checks:
//   IOSSecuritySuite checks sileo://, zbra://, filza://, cydia:// via canOpenURL.
//   These are already handled by lsd.x (verified by reading lines 30-112):
//   _LSCanOpenURLManager canOpenURL:publicSchemes:privateSchemes:XPCConnection:error:
//   (lines 83-112) calls jbclient_blacklist_check_pid(pid); if the caller is on
//   the hide-list, it calls isJailbreakURLScheme(url.scheme) (lines 30-43), which
//   queries LSApplicationWorkspace for every app registered to handle the scheme
//   and returns YES if any handler's bundle path is a jailbreak path. The check is
//   dynamic (not hardcoded to four schemes) and conditioned on the blacklist. The
//   same scheme-blocking logic applies in _LSDOpenClient openURL: overloads. No
//   additional code is needed here.
//
// NOTE on __sysctl/__sysctlbyname (roothider_common.c):
//   These hooks intercept security.mac.amfi.developer_mode_status queries.
//   Originally installed only for !isRemovableBundlePath (system daemons), they
//   are now ALSO installed for blacklisted app processes (gShouldHideJailbreak)
//   to address DOPAMINE_WEAKNESS_2.md reason=9 (Developer Mode detection by
//   BsDeviceInfo.getBuildId at 0x2805c). The two installation paths are mutually
//   exclusive (isRemovableBundlePath cannot be both true and false), so litehook
//   cannot double-hook __sysctl/__sysctlbyname for any single process.
//   DOPAMINE_WEAKNESS.md's sysctlbyname("hw.machine") is metadata only (not a
//   detection mechanism) — no action needed for that use.
// ─────────────────────────────────────────────────────────────────────────────

typedef struct { Method method; IMP origIMP; } SavedIMP;

static SavedIMP *gBSDPMRHideInstIMPs = NULL;
static unsigned int gBSDPMRHideInstCount = 0;
static SavedIMP *gBSDPMRHideClassIMPs = NULL;
static unsigned int gBSDPMRHideClassCount = 0;

static void save_canary_imps(void) {
    Class cls = objc_getClass("BSDPMRHide");
    if (!cls) return;
    RH_LOG("save_canary_imps: BSDPMRHide found, saving IMPs");

    Method *inst = class_copyMethodList(cls, &gBSDPMRHideInstCount);
    if (inst) {
        gBSDPMRHideInstIMPs = malloc(gBSDPMRHideInstCount * sizeof(SavedIMP));
        if (gBSDPMRHideInstIMPs) {
            for (unsigned int i = 0; i < gBSDPMRHideInstCount; i++) {
                gBSDPMRHideInstIMPs[i].method = inst[i];
                gBSDPMRHideInstIMPs[i].origIMP = method_getImplementation(inst[i]);
            }
        }
        free(inst);
    }

    Class meta = object_getClass((id)cls);
    Method *cls_m = class_copyMethodList(meta, &gBSDPMRHideClassCount);
    if (cls_m) {
        gBSDPMRHideClassIMPs = malloc(gBSDPMRHideClassCount * sizeof(SavedIMP));
        if (gBSDPMRHideClassIMPs) {
            for (unsigned int i = 0; i < gBSDPMRHideClassCount; i++) {
                gBSDPMRHideClassIMPs[i].method = cls_m[i];
                gBSDPMRHideClassIMPs[i].origIMP = method_getImplementation(cls_m[i]);
            }
        }
        free(cls_m);
    }
    RH_LOG("save_canary_imps: saved inst=%u class=%u",
           gBSDPMRHideInstCount, gBSDPMRHideClassCount);
}

static void restore_canary_imps(void) {
    if (gBSDPMRHideInstIMPs) {
        for (unsigned int i = 0; i < gBSDPMRHideInstCount; i++)
            method_setImplementation(gBSDPMRHideInstIMPs[i].method,
                                     gBSDPMRHideInstIMPs[i].origIMP);
    }
    if (gBSDPMRHideClassIMPs) {
        for (unsigned int i = 0; i < gBSDPMRHideClassCount; i++)
            method_setImplementation(gBSDPMRHideClassIMPs[i].method,
                                     gBSDPMRHideClassIMPs[i].origIMP);
    }
    RH_LOG("restore_canary_imps: restored inst=%u class=%u",
           gBSDPMRHideInstCount, gBSDPMRHideClassCount);
}

//export for PatchLoader
__attribute__((visibility("default"))) int PLRequiredJIT() {
	return 0;
}

static uid_t _CFGetSVUID(bool *successful) {
    uid_t uid = -1;
    struct kinfo_proc kinfo;
    u_int miblen = 4;
    size_t  len;
    int mib[miblen];
    int ret;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    len = sizeof(struct kinfo_proc);
    ret = sysctl(mib, miblen, &kinfo, &len, NULL, 0);
    if (ret != 0) {
        uid = -1;
        *successful = false;
    } else {
        uid = kinfo.kp_eproc.e_pcred.p_svuid;
        *successful = true;
    }
    return uid;
}

bool _CFCanChangeEUIDs(void) {
    static bool canChangeEUIDs;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uid_t euid = geteuid();
        uid_t uid = getuid();
        bool gotSVUID = false;
        uid_t svuid = _CFGetSVUID(&gotSVUID);
        canChangeEUIDs = (uid == 0 || uid != euid || svuid != euid || !gotSVUID);
    });
    return canChangeEUIDs;
}

void loadPathHook()
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
		void* roothidehooks = dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
		ASSERT(roothidehooks != NULL);
		void (*pathhook)() = dlsym(roothidehooks, "pathhook");
		ASSERT(pathhook != NULL);
		pathhook();
	});
}

void redirect_env_paths(const char* rootdir)
{
    //for now libSystem should be initlized, container should be set.

    char* homedir = NULL;

/* 
there is a bug in NSHomeDirectory,
if a containerized root process changes its uid/gid, 
NSHomeDirectory may return a home directory that it cannot access. (exclude NSTemporaryDirectory)
We just keep this bug:
*/
    if(!issetugid()) // issetugid() should always be false at this time. (but how about persona-mgmt? idk)
    {
        homedir = getenv("CFFIXED_USER_HOME");
        if(homedir)
        {
#define CONTAINER_PATH_PREFIX   "/private/var/mobile/Containers/Data/" // +/Application,PluginKitPlugin,InternalDaemon
            if(strncmp(homedir, CONTAINER_PATH_PREFIX, sizeof(CONTAINER_PATH_PREFIX)-1) == 0)
            {
                return; //containerized
            }
            else
            {
                homedir = NULL; //from parent, drop it
            }
        }
    }

    if(!homedir) {
        struct passwd* pwd = getpwuid(geteuid());
        if(pwd && pwd->pw_dir) {
            homedir = pwd->pw_dir;
        }
    }

    // if(!homedir) {
    //     //CFCopyHomeDirectoryURL does, but not for NSHomeDirectory
    //     homedir = getenv("HOME");
    // }

    if(!homedir) {
        homedir = "/var/empty";
    }

	if(homedir[0] == '/') {
		char newhome[PATH_MAX*2]={0};
		strlcpy(newhome, rootdir, sizeof(newhome));
		strlcat(newhome, homedir, sizeof(newhome));
		setenv("CFFIXED_USER_HOME", newhome, 1);
	}
}

void redirect_paths(const char* rootdir)
{
    do {
        
        char executablePath[PATH_MAX]={0};
        uint32_t bufsize=sizeof(executablePath);
        if(_NSGetExecutablePath(executablePath, &bufsize) != 0)
            break;
        
        char realexepath[PATH_MAX]={0};
        if(!realpath(executablePath, realexepath))
            break;
            
        char realjbroot[PATH_MAX+1]={0};
        if(!realpath(rootdir, realjbroot))
            break;
        
        if(realjbroot[0] && realjbroot[strlen(realjbroot)-1] != '/')
            strlcat(realjbroot, "/", sizeof(realjbroot));
        
        if(strncmp(realexepath, realjbroot, strlen(realjbroot)) != 0)
            break;

        //for jailbroken binaries
        redirect_env_paths(rootdir);
		
		if(_CFCanChangeEUIDs()) {
			loadPathHook();
		}
    
        pid_t ppid = __getppid();
        ASSERT(ppid > 0);
        if(ppid != 1)
            break;
        
        char pwd[PATH_MAX];
        if(getcwd(pwd, sizeof(pwd)) == NULL)
            break;
        if(strcmp(pwd, "/") != 0)
            break;
    
        ASSERT(chdir(rootdir)==0);
        
    } while(0);
}


kSpawnConfig spawn_config_for_executable(const char* path, char *const argv[restrict]);
void string_enumerate_components(const char *string, const char *separator, void (^enumBlock)(const char *pathString, bool *stop));

void trust_insert_libraries(char** envc)
{
	const char* DYLD_INSERT_LIBRARIES = envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES");
	if(!DYLD_INSERT_LIBRARIES) return;

	string_enumerate_components(DYLD_INSERT_LIBRARIES, ":", ^(const char *path, bool *stop) {
		if (strcmp(path, HOOK_DYLIB_PATH) != 0) {
			jbclient_trust_library_recurse(path, NULL);
		}
	});
}

int __no_need_to_trust_now__(const char* path)
{
	return 0;
}

#define NBINPREFS       4
#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t * __restrict, int * __restrict) __API_AVAILABLE(macos(10.8), ios(6.0));

int roothide_systemhook___posix_spawn_prehook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict], void *orig, int (*trust_binary)(const char *path), int (*set_process_debugged)(uint64_t pid, bool fullyDebugged), double jetsamMultiplier)
{
	if(!path) { //Don't crash here due to bad posix_spawn call
		return __posix_spawn_orig(pidp, path, desc, argv, envp);
	}

	if(!desc || !desc->attrp) {
		posix_spawnattr_t attr=NULL;
		posix_spawnattr_init(&attr);
		int ret = posix_spawn(pidp, path, (desc && desc->file_actions) ? &desc->file_actions : NULL, &attr, argv, envp);
		posix_spawnattr_destroy(&attr);
		return ret;
	}

	if(!jbclient_dyld_patch_enabled())
	{
		trust_binary = __no_need_to_trust_now__;
	}

	return posix_spawn_hook_shared(pidp, path, desc, argv, envp, orig, trust_binary, set_process_debugged, jetsamMultiplier);
}

int roothide_systemhook___posix_spawn_posthook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	posix_spawnattr_t attrp = &desc->attrp;

	kSpawnConfig spawnConfig = 0;
	if(!jbclient_dyld_patch_enabled())
	{
		spawnConfig = spawn_config_for_executable(path, argv);

		if (spawnConfig & kSpawnConfigTrust) {
			size_t outCount = 0;
			bool preferredArchsSet = false;
			cpu_type_t preferredTypes[NBINPREFS] = {0};
			cpu_subtype_t preferredSubtypes[NBINPREFS] = {0};
			if (posix_spawnattr_getarchpref_np(attrp, 4, preferredTypes, preferredSubtypes, &outCount) == 0) {
				for (size_t i = 0; i < outCount; i++) {
					if (preferredTypes[i] != 0 || preferredSubtypes[i] != UINT32_MAX) {
						preferredArchsSet = true;
						break;
					}
				}
			}

			xpc_object_t preferredArchsArray = NULL;
			if (preferredArchsSet) {
				preferredArchsArray = xpc_array_create_empty();
				for (size_t i = 0; i < outCount; i++) {
					xpc_object_t curArch = xpc_dictionary_create_empty();
					xpc_dictionary_set_uint64(curArch, "type", preferredTypes[i]);
					xpc_dictionary_set_uint64(curArch, "subtype", preferredSubtypes[i]);
					xpc_array_set_value(preferredArchsArray, XPC_ARRAY_APPEND, curArch);
					xpc_release(curArch);
				}
			}

			// Upload binary to trustcache if needed
			jbclient_trust_executable_recurse(path, preferredArchsArray);

			if (preferredArchsArray) {
				xpc_release(preferredArchsArray);
			}
		}
	}

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);

	bool should_suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool should_resume = should_suspend && (flags & POSIX_SPAWN_START_SUSPENDED)==0;
	bool patch_exec = should_suspend && (flags & POSIX_SPAWN_SETEXEC) != 0;

	if (should_suspend) {
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
	}

	if (patch_exec) {
		if (jbdSpawnExecStart(path, should_resume) != 0) { // jdb fault?
			//restore flags
			posix_spawnattr_setflags(attrp, flags);
			return 201;
		}
	}

	// on some devices dyldhook may fail due to vm_protect(VM_PROT_READ|VM_PROT_WRITE), 2, (os/kern) protection failure in dsc::__DATA_CONST:__const, 
	// so we need to disable dyld-in-cache here. (or we can use VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)
	char **envc = envbuf_mutcopy((const char **)envp);
	if(envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES")) {
		envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
	}

	if(!jbclient_dyld_patch_enabled())
	{
		if (spawnConfig & kSpawnConfigTrust) {
			trust_insert_libraries(envc);
		}
	}

	int pid = 0;
	int ret = __posix_spawn_orig(&pid, path, desc, argv, envc);
	if (pidp) *pidp = pid;

	envbuf_free(envc);

	// maybe caller will use it again? restore flags
	posix_spawnattr_setflags(attrp, flags);

	if (patch_exec) { //exec failed?
		jbdSpawnExecCancel(path);
	} else if (ret == 0 && pid > 0) {
		if (should_suspend) {
			if(jbdSpawnPatchChild(pid, should_resume) != 0) { // jdb fault? kill
				//just kill it instead of letting it hang forever, and the requester decides what to do later
				kill(pid, SIGQUIT); //core dump
				kill(pid, SIGKILL);
				return 202;
			}
		}
	}

	return ret;
}

int roothide_systemhook___execve_prehook(const char *path, char *const argv[], char *const envp[], void *orig, int (*trust_binary)(const char *path))
{
	//try POSIX_SPAWN_SETEXEC first
	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
	int ret = posix_spawn(NULL, path, NULL, &attr, argv, envp);
	posix_spawnattr_destroy(&attr);

	//posix_spawn with POSIX_SPAWN_SETEXEC failed
	assert(ret != 0);

	/* some processes are only allowed to call execve but not posix_spawn,
	 e.g: "configd" on ios15, we need to trace it so that we can patch the subprocess before it runs. */
	if(ret==EPERM && access(path, X_OK)==0 && sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) == 0)
	{
		trust_binary = __no_need_to_trust_now__;
		return execve_hook_shared(path, argv, envp, orig, trust_binary);
	}

	// posix_spawn will return errno and restore errno if it fails
	// so we need to set errno by ourself
	errno = ret; 
	return -1;
}

int roothide_systemhook___execve_posthook(const char *path, char *const argv[], char *const envp[])
{
	/* the posix_spawn call above should already trust the executable
	(also its libraries) and the inserted libraries, so we can skip them below */

	bool traced = false;

	if(jbdExecTraceStart(path, &traced) != 0) { // jdb fault?
		errno = 203;
		return -1;
	}

	//wait for SIGSTOP
	while(!traced) usleep(10*1000);

	char **envc = envbuf_mutcopy((const char **)envp);
	if(envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES")) {
		envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
	}
	
	int ret = __execve_orig(path, argv, envc);
	int olderr = errno;
	
	envbuf_free(envc);

	// exec* should never return if successful

	bool detached = false;

	if(jbdExecTraceCancel(path, &detached) != 0) {
		//broken process
		exit(99);
	}

	//wait for detach
	while(!detached) usleep(10*1000);

	errno = olderr;
	return ret;
}

void* (*dyld_dlopen_orig)(void *dyld, const char* path, int mode);
void* dyld_dlopen_hook(void *dyld, const char* path, int mode)
{
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library_recurse(path, __builtin_return_address(0));
	}
    __attribute__((musttail)) return dyld_dlopen_orig(dyld, path, mode);
}

void* (*dyld_dlopen_from_orig)(void *dyld, const char* path, int mode, void* addressInCaller);
void* dyld_dlopen_from_hook(void *dyld, const char* path, int mode, void* addressInCaller)
{
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library_recurse(path, addressInCaller);
	}
	__attribute__((musttail)) return dyld_dlopen_from_orig(dyld, path, mode, addressInCaller);
}

void* (*dyld_dlopen_audited_orig)(void *dyld, const char* path, int mode);
void* dyld_dlopen_audited_hook(void *dyld, const char* path, int mode)
{
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library_recurse(path, __builtin_return_address(0));
	}
	__attribute__((musttail)) return dyld_dlopen_audited_orig(dyld, path, mode);
}

bool (*dyld_dlopen_preflight_orig)(void *dyld, const char *path);
bool dyld_dlopen_preflight_hook(void *dyld, const char* path)
{
	if (path) {
		jbclient_trust_library_recurse(path, __builtin_return_address(0));
	}
	__attribute__((musttail)) return dyld_dlopen_preflight_orig(dyld, path);
}

int hook_dyld_routine(void **dyld, int idx, void *hook, void **orig, uint16_t pacSalt)
{
	if (!dyld) return -1;

	uint64_t dyldPacDiversifier = ((uint64_t)dyld & ~(0xFFFFull << 48)) | (0x63FAull << 48);
	void **dyldFuncPtrs = ptrauth_auth_data(*dyld, ptrauth_key_process_independent_data, dyldPacDiversifier);
	if (!dyldFuncPtrs) return -1;

	if (vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ | VM_PROT_WRITE) == 0) {
		uint64_t location = (uint64_t)&dyldFuncPtrs[idx];
		uint64_t pacDiversifier = (location & ~(0xFFFFull << 48)) | ((uint64_t)pacSalt << 48);

		*orig = ptrauth_auth_and_resign(dyldFuncPtrs[idx], ptrauth_key_process_independent_code, pacDiversifier, ptrauth_key_function_pointer, 0);
		dyldFuncPtrs[idx] = ptrauth_auth_and_resign(hook, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, pacDiversifier);
		vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ);
		return 0;
	}

	return -1;
}

void init_dyldhooks()
{
	// Apply dyld hooks
	void ***gDyldPtr = litehook_find_dsc_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");
	if (gDyldPtr) {
		hook_dyld_routine(*gDyldPtr, 14, (void *)&dyld_dlopen_hook, (void **)&dyld_dlopen_orig, 0xBF31);
		hook_dyld_routine(*gDyldPtr, 18, (void *)&dyld_dlopen_preflight_hook, (void **)&dyld_dlopen_preflight_orig, 0xB1B6);
		hook_dyld_routine(*gDyldPtr, 97, (void *)&dyld_dlopen_from_hook, (void **)&dyld_dlopen_from_orig, 0xD48C);
		hook_dyld_routine(*gDyldPtr, 98, (void *)&dyld_dlopen_audited_hook, (void **)&dyld_dlopen_audited_orig, 0xD2A5);
	}
}

extern struct mach_header __dso_handle;
extern const char* dyld_image_path_containing_address(const void* addr);

extern int parse_dyldhook_jbinfo(char **jbRootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut);

void roothide_init()
{
	if(getenv("DYLD_INSERT_LIBRARIES")) {
		const char* DYLD_IN_CACHE = getenv("DYLD_IN_CACHE");
		if(DYLD_IN_CACHE && strcmp(DYLD_IN_CACHE, "0") == 0) {
			unsetenv("DYLD_IN_CACHE");
		}
	}

	HOOK_DYLIB_PATH = strdup(dyld_image_path_containing_address(&__dso_handle));

	if(parse_dyldhook_jbinfo(NULL, NULL, NULL, NULL) != 0)
	{
		dyld_patch_fallback_enabled = true;
	}
}

void roothide_init_with_checkin(const char* rootdir)
{
	if(dyld_patch_fallback_enabled)
	{
		init_dyldhooks();
	}

	// Fix B: hook dyld image enumeration APIs so jailbreak dylibs are hidden
	// when gShouldHideJailbreak is set for apps on the hide-list.
	init_image_list_hooks();

	redirect_paths(rootdir);

	// Fix C — Phase 1: snapshot BSDPMRHide IMPs before roothideinit.dylib loads.
	// BSDPMRHide is registered by libobjc during dyld's image-mapping phase (before
	// any constructors). See the "Fix C" block comment above for the full mechanistic
	// explanation (libobjc _dyld_objc_notify_register → map_images → _read_images).
	// If BSDPMRHide is absent (not the banking app), this is a safe no-op.
	save_canary_imps();

	dlopen(JBROOT_PATH("/usr/lib/roothideinit.dylib"), RTLD_NOW);
}

// One-shot snapshot: enumerate all currently-loaded dyld images and log which
// ones is_jailbreak_image() would filter. Called once at bypass activation time
// (after roothidehooks.dylib is dlopen'd so CydiaSubstrate is also loaded).
// Output verifies that /.jbroot- fix (commit 9e464a5) correctly hides
// CydiaSubstrate and other jailbreak dylibs from MC1 isFrameworkAvailable.
static void log_hidden_images(void) {
    const struct dyld_all_image_infos *infos = get_image_infos();
    if (!infos) { RH_LOG("log_hidden_images: no image infos"); return; }
    uint32_t hidden = 0;
    for (uint32_t i = 0; i < infos->infoArrayCount; i++) {
        const char *p = infos->infoArray[i].imageFilePath;
        if (is_jailbreak_image(p)) {
            hidden++;
            RH_LOG("HIDDEN img[%u]: %s", i, p ?: "(null)");
        }
    }
    RH_LOG("dyld filter snapshot: total=%u visible=%u hidden=%u",
           infos->infoArrayCount, infos->infoArrayCount - hidden, hidden);
}

void roothide_init_with_executable(const char* executable)
{
	if (__builtin_available(iOS 16.0, *))
	{
		if(!isRemovableBundlePath(executable)) {
			litehook_hook_function(__sysctl, __sysctl_hook);
			litehook_hook_function(__sysctlbyname, __sysctlbyname_hook);
		}
	}

#ifndef __arm64e__
	if(strcmp(executable, "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd")==0
	|| strcmp(executable, "/System/Library/Frameworks/CryptoTokenKit.framework/ctkd")==0
	|| strcmp(executable, "/usr/libexec/securityd")==0
	|| strcmp(executable, "/usr/libexec/keybagd")==0) {
		if(jbclient_palehide_present())
		{
			void* roothidehooks = dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
			ASSERT(roothidehooks != NULL);
			void (*palera1n)() = dlsym(roothidehooks, "palera1n");
			palera1n();
		}
	}
#endif

	if(isRemovableBundlePath(executable) && string_has_suffix(executable, "/Dopamine")) {
		loadPathHook(); //requre jit
	}

	// Fixes A + B + C: activate for apps on the RootHide hide-list OR for any
	// app that ships a known RASP SDK (auto-detect via ObjC class presence).
	// Auto-detect allows tweak dylibs from Sileo/TweakLoader to still load
	// (TweakLoader is gated by the blacklist, not this code), while RASP bypass
	// activates automatically without requiring the app to be on the hide-list.
	// Fix B then hides those loaded tweaks from MC1's dyld image scan.
	//
	// objc_getClass is safe here: all static-dep ObjC classes (including
	// BSDPMRHide and ZDefend) are registered by libobjc during dyld image-map,
	// before any DYLD_INSERT_LIBRARIES constructor executes.
	bool isRaspApp = (objc_getClass("BSDPMRHide") != NULL   // BlueShield (LienViet)
	               || objc_getClass("ZDefend")     != NULL); // Zimperium z9 (VPBank)
	if (isRemovableBundlePath(executable) && (jbclient_blacklist_check_pid(getpid()) || isRaspApp)) {
		gShouldHideJailbreak = true;  // activates Fix B (dyld image-list filter)
		RH_LOG("ACTIVATED pid=%d exe=%s rasp=%d", getpid(), executable, (int)isRaspApp);

		// Fix A: hook access() for IOSSecuritySuite file-existence checks.
		litehook_hook_function(access, hook_access);
		RH_LOG("hook_access installed");

		// reason=0 cekL2Int: block fork() to clear the fork-success jailbreak bit.
		litehook_hook_function(fork, hook_fork);
		RH_LOG("hook_fork installed");

		// reason=9: developer_mode_status sysctl intercepts for app processes.
		if (__builtin_available(iOS 16.0, *)) {
			litehook_hook_function(__sysctl, __sysctl_hook);
			litehook_hook_function(__sysctlbyname, __sysctlbyname_hook);
			RH_LOG("sysctl hooks installed (iOS16+)");
		}

		// Fix C — Phase 2: restore BSDPMRHide IMPs.
		restore_canary_imps();
		RH_LOG("restore_canary_imps done");

		// Fix C — Phase 3: prevent future ElleKit hooks on BSDPMRHide.
		void *rhhooks = dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
		RH_LOG("roothidehooks dlopen=%p dlerror=%s", rhhooks, rhhooks ? "ok" : dlerror());
		if (rhhooks) {
			void (*canaryBypassInit)(void) = dlsym(rhhooks, "canaryBypassInit");
			RH_LOG("canaryBypassInit=%p", canaryBypassInit);
			if (canaryBypassInit) canaryBypassInit();

			// reason=0 BSLogCek + BSZInspection + cekL3Int (ObjC-layer):
			// Hooks +[OSLogStore localStoreAndReturnError:] → nil (BSLogCek),
			// and NSFileManager -fileExistsAtPath: variants for jailbreak paths.
			void (*logScanBypassInit)(void) = dlsym(rhhooks, "logScanBypassInit");
			RH_LOG("logScanBypassInit=%p", logScanBypassInit);
			if (logScanBypassInit) logScanBypassInit();

			// ZDefend bypass (VP Bank NEO):
			// ZDefend uses Direct Syscalls (SVC 0x80) — POSIX/NSFileManager hooks
			// are ineffective. Instead, cut the ObjC threat-reporting pipeline by
			// swallowing +[ZDefend addDeviceStatusCallback:]. VPBankNEO never receives
			// threat events → ZDefendViewController is never presented.
			// Safe no-op if ZDefend class is absent (not VP Bank).
			void (*zdefendBypassInit)(void) = dlsym(rhhooks, "zdefendBypassInit");
			RH_LOG("zdefendBypassInit=%p", zdefendBypassInit);
			if (zdefendBypassInit) zdefendBypassInit();

			log_hidden_images();
		}
		RH_LOG("bypass init complete");
	}

	dlopen(JBROOT_PATH("/usr/lib/roothidepatch.dylib"), RTLD_NOW); //require jit
}

