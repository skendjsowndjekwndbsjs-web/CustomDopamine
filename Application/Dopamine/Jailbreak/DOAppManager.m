//
//  DOAppManager.m
//  Dopamine
//

#import "DOAppManager.h"
#import "DOEnvironmentManager.h"
#import <CoreServices/LSApplicationWorkspace.h>
#import <CoreServices/LSApplicationProxy.h>
#import <libjailbreak/util.h>

static NSString *const DOAppManagerErrorDomain = @"DOAppManagerErrorDomain";

@implementation DOAppInfo
@end

@implementation DOAppManager

static NSString *manifestPath(void)
{
    return JBROOT_PATH(@"/var/mobile/Library/DopamineIPAInstalls.plist");
}

+ (BOOL)isAppSyncInstalled
{
    // AppSync Unified installs its dylib here in the Procursus bootstrap
    return [[NSFileManager defaultManager]
        fileExistsAtPath:JBROOT_PATH(@"/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified.dylib")];
}

+ (void)installAppSyncWithCompletion:(void (^)(NSError *_Nullable error))completion
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *debPath = [[NSBundle mainBundle].bundlePath
            stringByAppendingPathComponent:@"AppSync.deb"];

        if (![[NSFileManager defaultManager] fileExistsAtPath:debPath]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion([NSError errorWithDomain:DOAppManagerErrorDomain code:-1 userInfo:@{
                    NSLocalizedDescriptionKey: @"AppSync.deb not found in app bundle"
                }]);
            });
            return;
        }

        __block int result = -1;
        DOEnvironmentManager *env = [DOEnvironmentManager sharedManager];
        [env runAsRoot:^{
            [env runUnsandboxed:^{
                // Same pattern DOPackageManager uses for dpkg -i
                result = exec_cmd_trusted(
                    JBROOT_PATH("/usr/bin/dpkg"),
                    "-i", debPath.fileSystemRepresentation, NULL);
            }];
        }];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (result != 0) {
                completion([NSError errorWithDomain:DOAppManagerErrorDomain code:result userInfo:@{
                    NSLocalizedDescriptionKey: [NSString stringWithFormat:
                        @"dpkg exited %d installing AppSync Unified", result]
                }]);
            } else {
                completion(nil);
            }
        });
    });
}

+ (NSArray<DOAppInfo *> *)installedApps
{
    NSMutableArray<DOAppInfo *> *result = [NSMutableArray new];
    NSDictionary<NSString *, NSString *> *manifest =
        [NSDictionary dictionaryWithContentsOfFile:manifestPath()];

    for (NSString *bundleId in manifest) {
        // Ask LSApplicationWorkspace for live info instead of reading Info.plist
        // ourselves -- covers the case where the OS updated the app name/version.
        LSApplicationProxy *proxy = [LSApplicationProxy
            applicationProxyForIdentifier:bundleId];
        NSString *name = proxy.localizedName ?: bundleId;
        NSString *version = proxy.bundleShortVersionString ?: proxy.bundleVersion ?: @"?";
        NSString *path = proxy.bundleURL.path ?: manifest[bundleId];

        DOAppInfo *info = [DOAppInfo new];
        info.bundleIdentifier = bundleId;
        info.displayName = name;
        info.version = version;
        info.bundlePath = path;
        [result addObject:info];
    }

    [result sortUsingComparator:^NSComparisonResult(DOAppInfo *a, DOAppInfo *b) {
        return [a.displayName caseInsensitiveCompare:b.displayName];
    }];

    return result;
}

+ (nullable NSError *)installIPAAtPath:(NSString *)path
{
    // Copy to a system-accessible tmp path so installd can read the file
    // regardless of sandbox restrictions on our own container.
    NSString *tmpPath = [@"/var/mobile/Media/Inbox/"
        stringByAppendingPathComponent:[[NSUUID UUID].UUIDString
            stringByAppendingPathExtension:@"ipa"]];
    NSError *copyErr = nil;
    if (![[NSFileManager defaultManager] copyItemAtPath:path toPath:tmpPath error:&copyErr]) {
        return copyErr;
    }

    NSError *installError = nil;
    BOOL success = [[LSApplicationWorkspace defaultWorkspace]
        installApplication:[NSURL fileURLWithPath:tmpPath]
        withOptions:@{ @"PackageType": @"Customer" }
        error:&installError];

    [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];

    if (!success) {
        return installError ?: [NSError errorWithDomain:DOAppManagerErrorDomain code:-1 userInfo:@{
            NSLocalizedDescriptionKey: @"installApplication:withOptions:error: returned NO with no error object"
        }];
    }

    // Save to manifest so we can show what WE installed in the UI
    // (LSApplicationWorkspace has all user apps; we only want to show ours)
    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:
        [path stringByAppendingPathComponent:@"Info.plist"]];
    NSString *bundleId = infoPlist[@"CFBundleIdentifier"];
    if (bundleId) {
        NSMutableDictionary *manifest =
            [NSMutableDictionary dictionaryWithContentsOfFile:manifestPath()]
            ?: [NSMutableDictionary new];
        LSApplicationProxy *proxy = [LSApplicationProxy applicationProxyForIdentifier:bundleId];
        manifest[bundleId] = proxy.bundleURL.path ?: @"";
        [manifest writeToFile:manifestPath() atomically:YES];
    }

    return nil;
}

+ (nullable NSError *)removeAppWithBundleIdentifier:(NSString *)bundleIdentifier
{
    BOOL success = [[LSApplicationWorkspace defaultWorkspace]
        uninstallApplication:bundleIdentifier
        withOptions:nil];

    if (!success) {
        return [NSError errorWithDomain:DOAppManagerErrorDomain code:-1 userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:
                @"uninstallApplication: returned NO for %@", bundleIdentifier]
        }];
    }

    // Remove from our manifest
    NSMutableDictionary *manifest =
        [NSMutableDictionary dictionaryWithContentsOfFile:manifestPath()]
        ?: [NSMutableDictionary new];
    [manifest removeObjectForKey:bundleIdentifier];
    [manifest writeToFile:manifestPath() atomically:YES];

    return nil;
}

@end
