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

    // The app's own executable (and any dylibs it embeds) need to be
    // explicitly registered as trusted -- exec_cmd_trusted below only
    // trusts the helper binaries (mv/chown/uicache) it runs, not this
    // freshly-copied-in binary that nothing has ever executed or trusted
    // before. Without this, the move can succeed and uicache can still
    // register the icon, but tapping it on the home screen fails.
    NSString *executableName = infoPlist[@"CFBundleExecutable"];
    NSString *sourceExecutablePath = executableName ? [extractedAppPath stringByAppendingPathComponent:executableName] : nil;

    // The move/chown/uicache step needs root. Do it in-process via
    // runAsRoot/runUnsandboxed -- the same mechanism Respring/Reboot
    // Userspace already use -- instead of spawning /basebin/jbctl.
    // jbctl only reaches the device through basebin.tar, which the
    // jailbreak/bootstrap process extracts; a plain IPA reinstall does
    // NOT redeploy it, so a jbctl-spawn approach would silently run
    // whatever old jbctl is already on disk and never learn about a
    // new "install_app" command. runAsRoot/runUnsandboxed instead ask
    // the currently-running (freshly-installed) app process itself for
    // elevated privileges, so it's always current.
    __block int result = -1;
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    [envManager runAsRoot:^{
        [envManager runUnsandboxed:^{
            // Trust the app's own executable BEFORE moving it -- trusting
            // by path only makes sense while that exact path still exists.
            if (sourceExecutablePath) {
                jbclient_trust_file_by_path(sourceExecutablePath.fileSystemRepresentation);
            }

            // Ignore this one's result -- fine if nothing was there yet.
            exec_cmd_trusted(JBROOT_PATH("/usr/bin/rm"), "-rf", targetPath.fileSystemRepresentation, NULL);

            int r = exec_cmd_trusted(JBROOT_PATH("/usr/bin/mv"), extractedAppPath.fileSystemRepresentation, targetPath.fileSystemRepresentation, NULL);
            if (r == 0) r = exec_cmd_trusted(JBROOT_PATH("/usr/bin/chown"), "-R", "mobile:mobile", targetPath.fileSystemRepresentation, NULL);
            if (r == 0) r = exec_cmd_trusted(JBROOT_PATH("/usr/bin/uicache"), "-a", NULL);
            result = r;
        }];
    }];

    [fm removeItemAtPath:extractDir error:nil];

    if (result != 0 || ![fm fileExistsAtPath:targetPath]) {
        return [NSError errorWithDomain:DOAppManagerErrorDomain code:result userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Install didn't complete (step exited %d). Check that ldid/trust isn't required for this binary.", result]
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
            result = exec_cmd_trusted(JBROOT_PATH("/usr/bin/rm"), "-rf", bundlePath.fileSystemRepresentation, NULL);
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
