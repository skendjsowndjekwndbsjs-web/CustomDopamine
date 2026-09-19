//
//  DOAppManager.m
//  Dopamine
//

#import "DOAppManager.h"
#import "DOEnvironmentManager.h"
#import <libjailbreak/util.h>
#import <libjailbreak/jbclient_xpc.h>
#import <unistd.h>

static NSString *const DOAppManagerErrorDomain = @"DOAppManagerErrorDomain";

static void recursiveChown(NSString *path, uid_t uid, gid_t gid)
{
    chown(path.fileSystemRepresentation, uid, gid);
    BOOL isDir = NO;
    if ([[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir] && isDir) {
        NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtPath:path];
        for (NSString *subpath in enumerator) {
            chown([path stringByAppendingPathComponent:subpath].fileSystemRepresentation, uid, gid);
        }
    }
}

@implementation DOAppInfo
@end

@implementation DOAppManager

+ (NSArray<DOAppInfo *> *)installedApps
{
    NSMutableArray<DOAppInfo *> *result = [NSMutableArray new];

    NSString *appsDir = JBROOT_PATH(@"/Applications");
    NSArray<NSString *> *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:appsDir error:nil];
    for (NSString *entry in entries) {
        if (![entry.pathExtension isEqualToString:@"app"]) continue;

        NSString *bundlePath = [appsDir stringByAppendingPathComponent:entry];
        NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Info.plist"]];
        if (!infoPlist) continue;

        DOAppInfo *info = [DOAppInfo new];
        info.bundleIdentifier = infoPlist[@"CFBundleIdentifier"] ?: entry;
        info.displayName = infoPlist[@"CFBundleDisplayName"] ?: infoPlist[@"CFBundleName"] ?: entry;
        info.version = infoPlist[@"CFBundleShortVersionString"] ?: infoPlist[@"CFBundleVersion"] ?: @"?";
        info.bundlePath = bundlePath;
        [result addObject:info];
    }

    [result sortUsingComparator:^NSComparisonResult(DOAppInfo *a, DOAppInfo *b) {
        return [a.displayName caseInsensitiveCompare:b.displayName];
    }];

    return result;
}

// Recursively finds every Mach-O binary in a bundle (main executable,
// embedded frameworks, plugins/extensions, anything) by checking each
// file's magic bytes, rather than guessing by extension -- trusting only
// CFBundleExecutable is what left frameworks untrusted and made freshly
// installed apps crash on launch.
static void trustAllMachOsInBundle(NSString *bundlePath)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDirectoryEnumerator<NSString *> *enumerator = [fm enumeratorAtPath:bundlePath];
    for (NSString *relativePath in enumerator) {
        NSString *fullPath = [bundlePath stringByAppendingPathComponent:relativePath];

        NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
        if (![attrs[NSFileType] isEqualToString:NSFileTypeRegular]) continue;

        NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:fullPath];
        if (!fh) continue;
        NSData *header = [fh readDataOfLength:4];
        [fh closeFile];
        if (header.length < 4) continue;

        uint32_t magic;
        memcpy(&magic, header.bytes, 4);
        BOOL isMachO = (magic == 0xfeedface || magic == 0xcefaedfe || // 32-bit
                         magic == 0xfeedfacf || magic == 0xcffaedfe || // 64-bit
                         magic == 0xcafebabe || magic == 0xbebafeca);  // fat/universal
        if (isMachO) {
            jbclient_trust_file_by_path(fullPath.fileSystemRepresentation);
        }
    }
}

+ (nullable NSError *)installIPAAtPath:(NSString *)path
{
    NSFileManager *fm = [NSFileManager defaultManager];

    // Extract into our own sandbox tmp -- this part needs no privilege.
    // An .ipa is just a zip, and libarchive_unarchive already auto-detects
    // format (it's the same call DOBootstrapper uses for bootstrap.tar.zst
    // and basebin.tar), so no bundled unzip binary is needed.
    NSString *extractDir = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
    [fm createDirectoryAtPath:extractDir withIntermediateDirectories:YES attributes:nil error:nil];

    int r = libarchive_unarchive(path.fileSystemRepresentation, extractDir.fileSystemRepresentation);
    if (r != 0) {
        [fm removeItemAtPath:extractDir error:nil];
        return [NSError errorWithDomain:DOAppManagerErrorDomain code:r userInfo:@{
            NSLocalizedDescriptionKey: @"Failed to extract the .ipa (not a valid zip, or corrupt)"
        }];
    }

    NSString *payloadDir = [extractDir stringByAppendingPathComponent:@"Payload"];
    NSString *appName = nil;
    for (NSString *entry in [fm contentsOfDirectoryAtPath:payloadDir error:nil]) {
        if ([entry.pathExtension isEqualToString:@"app"]) {
            appName = entry;
            break;
        }
    }
    if (!appName) {
        [fm removeItemAtPath:extractDir error:nil];
        return [NSError errorWithDomain:DOAppManagerErrorDomain code:-1 userInfo:@{
            NSLocalizedDescriptionKey: @"No Payload/*.app found inside the .ipa"
        }];
    }

    NSString *extractedAppPath = [payloadDir stringByAppendingPathComponent:appName];
    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[extractedAppPath stringByAppendingPathComponent:@"Info.plist"]];
    NSString *bundleIdentifier = infoPlist[@"CFBundleIdentifier"];

    // If an app with the same bundle identifier is already installed
    // (possibly under a differently-named folder, e.g. a resigned build),
    // reuse its folder name so this is an update, not a duplicate icon.
    NSString *targetFolderName = appName;
    if (bundleIdentifier) {
        for (DOAppInfo *existing in [self installedApps]) {
            if ([existing.bundleIdentifier isEqualToString:bundleIdentifier]) {
                targetFolderName = existing.bundlePath.lastPathComponent;
                break;
            }
        }
    }
    NSString *targetPath = [JBROOT_PATH(@"/Applications") stringByAppendingPathComponent:targetFolderName];

    // The move/chown/uicache step needs root. Do it in-process via
    // runAsRoot/runUnsandboxed -- the same mechanism Respring/Reboot
    // Userspace already use -- instead of spawning /basebin/jbctl (which
    // only reaches the device through basebin.tar, extracted by the
    // jailbreak/bootstrap process, so a plain IPA reinstall wouldn't
    // redeploy it).
    //
    // The move and chown are done natively (NSFileManager + chown())
    // rather than by shelling out to /usr/bin/mv & /usr/bin/chown --
    // unlike uicache's path, which is copied from code already known to
    // work elsewhere in this app, I had no verified bootstrap path for
    // mv/chown and guessed wrong. Native calls have no such dependency.
    __block int result = -1;
    __block NSString *stepThatFailed = nil;
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    [envManager runAsRoot:^{
        [envManager runUnsandboxed:^{
            NSFileManager *rootFm = [NSFileManager defaultManager];

            // Trust every Mach-O BEFORE moving -- trusting by path only
            // makes sense while these exact paths still exist.
            trustAllMachOsInBundle(extractedAppPath);

            // Fine if nothing was there yet (reinstall case).
            [rootFm removeItemAtPath:targetPath error:nil];

            NSError *moveErr = nil;
            if (![rootFm moveItemAtPath:extractedAppPath toPath:targetPath error:&moveErr]) {
                stepThatFailed = [NSString stringWithFormat:@"move (%@)", moveErr.localizedDescription];
                return;
            }

            // installd normally owns app bundles as mobile:mobile (501:501
            // on every iOS version -- this has never changed).
            recursiveChown(targetPath, 501, 501);

            int r = exec_cmd_trusted(JBROOT_PATH("/usr/bin/uicache"), "-a", NULL);
            if (r != 0) {
                stepThatFailed = [NSString stringWithFormat:@"uicache (exit %d)", r];
                return;
            }
            result = 0;
        }];
    }];

    [fm removeItemAtPath:extractDir error:nil];

    if (result != 0 || ![fm fileExistsAtPath:targetPath]) {
        return [NSError errorWithDomain:DOAppManagerErrorDomain code:result userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Install didn't complete -- failed at: %@", stepThatFailed ?: @"unknown step"]
        }];
    }
    return nil;
}

+ (nullable NSError *)removeAppAtPath:(NSString *)bundlePath
{
    __block int result = -1;
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    [envManager runAsRoot:^{
        [envManager runUnsandboxed:^{
            exec_cmd_trusted(JBROOT_PATH("/usr/bin/uicache"), "-u", bundlePath.fileSystemRepresentation, NULL);
            result = [[NSFileManager defaultManager] removeItemAtPath:bundlePath error:nil] ? 0 : -1;
        }];
    }];

    if (result != 0 || [[NSFileManager defaultManager] fileExistsAtPath:bundlePath]) {
        return [NSError errorWithDomain:DOAppManagerErrorDomain code:result userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Remove didn't complete (step exited %d)", result]
        }];
    }
    return nil;
}

@end
