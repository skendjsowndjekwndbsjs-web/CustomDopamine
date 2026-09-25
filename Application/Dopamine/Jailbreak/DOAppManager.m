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

// Returns the path to the helper inside the app bundle, trusted and chmod'd
// in-place. We do NOT copy it to a temp dir -- the helper links against
// libjailbreak.dylib via @loader_path, and libjailbreak itself links against
// libchoma.dylib, libxpf.dylib etc. the same way. All of those sit in
// Dopamine.app/Frameworks/. The helper's rpath is built as
// @executable_path/Frameworks (set in Application/Makefile), so when it runs
// from inside the app bundle every transitive dylib dependency resolves
// correctly. Copying to a temp dir only brings one dylib along, causing
// dyld to SIGABRT (exit 6) when it can't find the rest.
static NSString *stageHelper(void)
{
    NSString *helperPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"DOAppInstallHelper"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:helperPath]) return nil;
    chmod(helperPath.fileSystemRepresentation, 0755);
    jbclient_trust_file_by_path(helperPath.fileSystemRepresentation);
    return helperPath;
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
