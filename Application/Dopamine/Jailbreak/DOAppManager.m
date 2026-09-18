//
//  DOAppManager.m
//  Dopamine
//

#import "DOAppManager.h"
#import <libjailbreak/util.h>
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

    // The move/chown/uicache step needs root -- hand off to jbctl the same
    // way DOPackageManager hands dpkg -i off for non-root installs.
    exec_cmd(JBROOT_PATH("/basebin/jbctl"), "internal", "install_app", extractedAppPath.fileSystemRepresentation, targetPath.fileSystemRepresentation, NULL);

    [fm removeItemAtPath:extractDir error:nil];

    // jbctl's install_app doesn't report status back to us here (same as
    // install_pkg's fire-and-forget non-root path) -- re-check the app
    // actually landed instead of trusting a blind success.
    if (![fm fileExistsAtPath:targetPath]) {
        return [NSError errorWithDomain:DOAppManagerErrorDomain code:-1 userInfo:@{
            NSLocalizedDescriptionKey: @"Install didn't complete -- the app isn't at its expected path. Check that ldid/trust isn't required for this binary."
        }];
    }
    return nil;
}

+ (nullable NSError *)removeAppAtPath:(NSString *)bundlePath
{
    exec_cmd(JBROOT_PATH("/basebin/jbctl"), "internal", "remove_app", bundlePath.fileSystemRepresentation, NULL);

    if ([[NSFileManager defaultManager] fileExistsAtPath:bundlePath]) {
        return [NSError errorWithDomain:DOAppManagerErrorDomain code:-1 userInfo:@{
            NSLocalizedDescriptionKey: @"Remove didn't complete"
        }];
    }
    return nil;
}

@end
