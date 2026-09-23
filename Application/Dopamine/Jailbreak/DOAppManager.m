//
//  DOAppManager.m
//  Dopamine
//

#import "DOAppManager.h"
#import "DOEnvironmentManager.h"
#import <libjailbreak/util.h>
#import <libjailbreak/jbclient_xpc.h>
#import <sys/stat.h>

static NSString *const DOAppManagerErrorDomain = @"DOAppManagerErrorDomain";

@implementation DOAppInfo
@end

@implementation DOAppManager

static NSString *installManifestPath(void)
{
    return JBROOT_PATH(@"/var/mobile/Library/DopamineIPAInstalls.plist");
}

// Copies the bundled helper binary (and libjailbreak.dylib, which it's
// dynamically linked against via @loader_path -- it needs to sit right
// next to the helper for that to resolve, since the helper isn't running
// from inside Dopamine.app's own bundle once copied out) into a fresh
// writable working directory, and marks both trusted.
static NSString *stageHelper(void)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *workDir = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
    [fm createDirectoryAtPath:workDir withIntermediateDirectories:YES attributes:nil error:nil];

    NSString *helperSrc = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"DOAppInstallHelper"];
    NSString *dylibSrc = [[NSBundle mainBundle].privateFrameworksPath stringByAppendingPathComponent:@"libjailbreak.dylib"];

    NSString *helperDst = [workDir stringByAppendingPathComponent:@"DOAppInstallHelper"];
    NSString *dylibDst = [workDir stringByAppendingPathComponent:@"libjailbreak.dylib"];

    if (![fm copyItemAtPath:helperSrc toPath:helperDst error:nil]) return nil;
    [fm copyItemAtPath:dylibSrc toPath:dylibDst error:nil];

    chmod(helperDst.fileSystemRepresentation, 0755);
    jbclient_trust_file_by_path(helperDst.fileSystemRepresentation);
    jbclient_trust_file_by_path(dylibDst.fileSystemRepresentation);

    return helperDst;
}

+ (NSArray<DOAppInfo *> *)installedApps
{
    NSMutableArray<DOAppInfo *> *result = [NSMutableArray new];

    NSDictionary<NSString *, NSString *> *manifest = [NSDictionary dictionaryWithContentsOfFile:installManifestPath()];
    for (NSString *bundleIdentifier in manifest) {
        NSString *bundlePath = manifest[bundleIdentifier];
        NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Info.plist"]];
        if (!infoPlist) continue; // stale entry -- app dir is gone

        DOAppInfo *info = [DOAppInfo new];
        info.bundleIdentifier = bundleIdentifier;
        info.displayName = infoPlist[@"CFBundleDisplayName"] ?: infoPlist[@"CFBundleName"] ?: bundleIdentifier;
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
    NSString *resultPath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];

    __block int result = -1;
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    [envManager runAsRoot:^{
        [envManager runUnsandboxed:^{
            NSString *helperPath = stageHelper();
            if (!helperPath) {
                result = -1;
                return;
            }
            result = exec_cmd(helperPath.fileSystemRepresentation, "install", path.fileSystemRepresentation, resultPath.fileSystemRepresentation, NULL);
        }];
    }];

    NSDictionary *resultDict = [NSDictionary dictionaryWithContentsOfFile:resultPath];
    [[NSFileManager defaultManager] removeItemAtPath:resultPath error:nil];

    if (result != 0 || !resultDict[@"Path"]) {
        return [NSError errorWithDomain:DOAppManagerErrorDomain code:result userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Install helper exited %d -- check its stderr (spawned as root, so it won't show in this app's own logs)", result]
        }];
    }

    NSMutableDictionary *manifest = [NSMutableDictionary dictionaryWithContentsOfFile:installManifestPath()] ?: [NSMutableDictionary new];
    manifest[resultDict[@"BundleIdentifier"]] = resultDict[@"Path"];
    [manifest writeToFile:installManifestPath() atomically:YES];

    return nil;
}

+ (nullable NSError *)removeAppWithBundleIdentifier:(NSString *)bundleIdentifier
{
    __block int result = -1;
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    [envManager runAsRoot:^{
        [envManager runUnsandboxed:^{
            NSString *helperPath = stageHelper();
            if (!helperPath) {
                result = -1;
                return;
            }
            result = exec_cmd(helperPath.fileSystemRepresentation, "remove", bundleIdentifier.fileSystemRepresentation, NULL);
        }];
    }];

    if (result != 0) {
        return [NSError errorWithDomain:DOAppManagerErrorDomain code:result userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Remove helper exited %d", result]
        }];
    }

    NSMutableDictionary *manifest = [NSMutableDictionary dictionaryWithContentsOfFile:installManifestPath()] ?: [NSMutableDictionary new];
    [manifest removeObjectForKey:bundleIdentifier];
    [manifest writeToFile:installManifestPath() atomically:YES];

    return nil;
}

@end
