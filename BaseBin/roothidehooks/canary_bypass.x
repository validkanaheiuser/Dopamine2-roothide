#import <Foundation/Foundation.h>
#import <substrate.h>
#import <objc/runtime.h>
#import <syslog.h>

#define RH_LOG(fmt, ...) syslog(LOG_WARNING, "[RHHIDE] " fmt, ##__VA_ARGS__)

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
// If BSZInspection or cekL3Int bypass NSFileManager and call stat/opendir
// directly (via POSIX), the hook_access/hook_open extensions in roothider_main.c
// provide POSIX-layer coverage. stat() at the raw syscall level is not hooked.

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

__attribute__((visibility("default"))) void logScanBypassInit(void)
{
    RH_LOG("logScanBypassInit called");

    // Hook +[OSLogStore localStoreAndReturnError:] → nil: disables BSLogCek.
    Class osLogStoreMeta = objc_getMetaClass("OSLogStore");
    RH_LOG("OSLogStore metaclass=%p", osLogStoreMeta);
    if (osLogStoreMeta) {
        MSHookMessageEx(osLogStoreMeta,
                        @selector(localStoreAndReturnError:),
                        (IMP)replaced_localStoreAndReturnError,
                        (IMP *)&orig_localStoreAndReturnError);
        RH_LOG("OSLogStore.localStoreAndReturnError hooked");
    }

    // Hook NSFileManager file-existence checks for jailbreak path blocking.
    // Covers BSZInspection Zebra/Zim scan and cekL3Int package metadata reads.
    MSHookMessageEx([NSFileManager class],
                    @selector(fileExistsAtPath:),
                    (IMP)replaced_fileExistsAtPath,
                    (IMP *)&orig_fileExistsAtPath);
    RH_LOG("NSFileManager.fileExistsAtPath: hooked");
    MSHookMessageEx([NSFileManager class],
                    @selector(fileExistsAtPath:isDirectory:),
                    (IMP)replaced_fileExistsAtPathIsDirectory,
                    (IMP *)&orig_fileExistsAtPathIsDirectory);
    RH_LOG("NSFileManager.fileExistsAtPath:isDirectory: hooked");
    RH_LOG("logScanBypassInit complete");
}
