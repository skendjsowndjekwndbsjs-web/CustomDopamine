//
//  DOAppManager.m
//  Dopamine
//

#import "DOAppManager.h"
#import "DOEnvironmentManager.h"
#import <libjailbreak/util.h>
#import <libjailbreak/jbclient_xpc.h>
#import <CoreServices/LSApplicationWorkspace.h>
#import <Security/Security.h>
#import <unistd.h>

// MobileContainerManager is a private framework with no vendored header in
// this project (unlike CoreServices/LSApplicationWorkspace.h, which BaseBin
// already ships) -- declared the same minimal way TrollStore's own
// Shared/CoreServices.h does.
@interface MCMContainer : NSObject
+ (id)containerWithIdentifier:(id)identifier createIfNecessary:(BOOL)createIfNecessary existed:(BOOL *)existed error:(NSError **)error;
@property (nonatomic, readonly) NSURL *url;
@end
@interface MCMAppDataContainer : MCMContainer
@end
@interface MCMSharedDataContainer : MCMContainer
@end
@interface MCMSystemDataContainer : MCMContainer
@end
@interface MCMPluginKitPluginDataContainer : MCMContainer
@end

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

// --- The following four helpers are ports of the same-named functions in
// TrollStore's RootHelper/uicache.m (registerPath()). ---

static NSDictionary *dumpEntitlementsFromBinaryAtPath(NSString *binaryPath)
{
    if (!binaryPath) return nil;

    NSURL *binaryURL = [NSURL fileURLWithPath:binaryPath];
    SecStaticCodeRef codeRef = NULL;
    OSStatus result = SecStaticCodeCreateWithPathAndAttributes((__bridge CFURLRef)binaryURL, kSecCSDefaultFlags, NULL, &codeRef);
    if (result != errSecSuccess || codeRef == NULL) {
        if (codeRef) CFRelease(codeRef);
        return nil;
    }

    CFDictionaryRef signingInfo = NULL;
    result = SecCodeCopySigningInformation(codeRef, kSecCSRequirementInformation, &signingInfo);
    CFRelease(codeRef);
    if (result != errSecSuccess) return nil;

    NSDictionary *entitlements = nil;
    CFDictionaryRef entitlementsRef = CFDictionaryGetValue(signingInfo, kSecCodeInfoEntitlementsDict);
    if (entitlementsRef && CFGetTypeID(entitlementsRef) == CFDictionaryGetTypeID()) {
        entitlements = (__bridge NSDictionary *)entitlementsRef;
    }
    CFRelease(signingInfo);
    return entitlements;
}

static BOOL constructContainerizationForEntitlements(NSDictionary *entitlements, NSString **customContainerOut)
{
    NSNumber *noContainer = entitlements[@"com.apple.private.security.no-container"];
    if ([noContainer isKindOfClass:[NSNumber class]] && noContainer.boolValue) {
        return NO;
    }

    id containerRequired = entitlements[@"com.apple.private.security.container-required"];
    if ([containerRequired isKindOfClass:[NSNumber class]]) {
        if (!((NSNumber *)containerRequired).boolValue) return NO;
    } else if ([containerRequired isKindOfClass:[NSString class]]) {
        *customContainerOut = (NSString *)containerRequired;
    }

    return YES;
}

static NSString *constructTeamIdentifierForEntitlements(NSDictionary *entitlements)
{
    NSString *teamIdentifier = entitlements[@"com.apple.developer.team-identifier"];
    return [teamIdentifier isKindOfClass:[NSString class]] ? teamIdentifier : nil;
}

static NSDictionary *constructEnvironmentVariablesForContainerPath(NSString *containerPath, BOOL isContainerized)
{
    NSString *homeDir = isContainerized ? containerPath : @"/var/mobile";
    NSString *tmpDir = isContainerized ? [containerPath stringByAppendingPathComponent:@"tmp"] : @"/var/tmp";
    return @{ @"CFFIXED_USER_HOME": homeDir, @"HOME": homeDir, @"TMPDIR": tmpDir };
}

static NSDictionary *constructGroupContainersForEntitlements(NSDictionary *entitlements, BOOL systemGroups)
{
    if (!entitlements) return nil;

    NSString *entitlementForGroups = systemGroups ? @"com.apple.security.system-groups" : @"com.apple.security.application-groups";
    Class mcmClass = systemGroups ? [MCMSystemDataContainer class] : [MCMSharedDataContainer class];

    NSArray *groupIDs = entitlements[entitlementForGroups];
    if (![groupIDs isKindOfClass:[NSArray class]]) return nil;

    NSMutableDictionary *groupContainers = [NSMutableDictionary new];
    for (NSString *groupID in groupIDs) {
        MCMContainer *container = [mcmClass containerWithIdentifier:groupID createIfNecessary:YES existed:nil error:nil];
        if (container.url) groupContainers[groupID] = container.url.path;
    }
    return groupContainers.count ? groupContainers.copy : nil;
}

// Builds one bundle's entry (main app, or a single PlugIn) for the
// registration dictionary -- shared logic between the two, per TrollStore's
// own registerPath(), which duplicates this inline for app vs. plugin.
static NSMutableDictionary *buildBundleRegistrationDictionary(NSString *bundlePath, NSString *bundleIdentifier, NSString *executablePath, BOOL isPlugin, NSString *ownerBundleID)
{
    NSDictionary *entitlements = dumpEntitlementsFromBinaryAtPath(executablePath);

    NSString *dataContainerID = bundleIdentifier;
    BOOL containerized = constructContainerizationForEntitlements(entitlements, &dataContainerID);

    Class containerClass = isPlugin ? NSClassFromString(@"MCMPluginKitPluginDataContainer") : [MCMAppDataContainer class];
    MCMContainer *dataContainer = [containerClass containerWithIdentifier:dataContainerID createIfNecessary:YES existed:nil error:nil];
    NSString *containerPath = dataContainer.url.path;

    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    if (entitlements) dict[@"Entitlements"] = entitlements;

    dict[@"CFBundleIdentifier"] = bundleIdentifier;
    dict[@"CodeInfoIdentifier"] = bundleIdentifier;
    dict[@"CompatibilityState"] = @0;
    dict[@"IsContainerized"] = @(containerized);
    if (containerPath) {
        dict[@"Container"] = containerPath;
        dict[@"EnvironmentVariables"] = constructEnvironmentVariablesForContainerPath(containerPath, containerized);
    }
    dict[@"Path"] = bundlePath;
    dict[@"SignerOrganization"] = @"Apple Inc.";
    dict[@"SignatureVersion"] = @132352;
    dict[@"SignerIdentity"] = @"Apple iPhone OS Application Signing";

    if (isPlugin) {
        dict[@"ApplicationType"] = @"PluginKitPlugin";
        dict[@"PluginOwnerBundleID"] = ownerBundleID;
    } else {
        dict[@"ApplicationType"] = @"User";
        dict[@"IsAdHocSigned"] = @YES;
        dict[@"LSInstallType"] = @1;
        dict[@"HasMIDBasedSINF"] = @0;
        dict[@"MissingSINF"] = @0;
        dict[@"FamilyID"] = @0;
        dict[@"IsOnDemandInstallCapable"] = @0;
        dict[@"IsDeletable"] = @YES;
    }

    NSString *teamIdentifier = constructTeamIdentifierForEntitlements(entitlements);
    if (teamIdentifier) dict[@"TeamIdentifier"] = teamIdentifier;

    NSDictionary *appGroupContainers = constructGroupContainersForEntitlements(entitlements, NO);
    NSDictionary *systemGroupContainers = constructGroupContainersForEntitlements(entitlements, YES);
    NSMutableDictionary *groupContainers = [NSMutableDictionary new];
    [groupContainers addEntriesFromDictionary:appGroupContainers];
    [groupContainers addEntriesFromDictionary:systemGroupContainers];
    if (groupContainers.count) {
        if (appGroupContainers.count) dict[@"HasAppGroupContainers"] = @YES;
        if (systemGroupContainers.count) dict[@"HasSystemGroupContainers"] = @YES;
        dict[@"GroupContainers"] = groupContainers.copy;
    }

    return dict;
}

// Full port of TrollStore's RootHelper/uicache.m registerPath(): builds the
// main app's registration dict (via the shared helper above), then walks
// PlugIns/*.appex and registers each one the same way, attached under
// _LSBundlePlugins -- this is what makes extensions/widgets actually work,
// not just a plain single-binary app.
static NSDictionary *buildRegistrationDictionary(NSString *bundlePath, NSString *bundleIdentifier)
{
    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Info.plist"]];
    NSString *executablePath = [bundlePath stringByAppendingPathComponent:infoPlist[@"CFBundleExecutable"]];

    NSMutableDictionary *dict = buildBundleRegistrationDictionary(bundlePath, bundleIdentifier, executablePath, NO, nil);

    NSString *pluginsPath = [bundlePath stringByAppendingPathComponent:@"PlugIns"];
    NSMutableDictionary *bundlePlugins = [NSMutableDictionary dictionary];
    for (NSString *pluginName in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:pluginsPath error:nil]) {
        NSString *pluginPath = [pluginsPath stringByAppendingPathComponent:pluginName];
        NSDictionary *pluginInfoPlist = [NSDictionary dictionaryWithContentsOfFile:[pluginPath stringByAppendingPathComponent:@"Info.plist"]];
        NSString *pluginBundleID = pluginInfoPlist[@"CFBundleIdentifier"];
        if (!pluginBundleID) continue;

        NSString *pluginExecutablePath = [pluginPath stringByAppendingPathComponent:pluginInfoPlist[@"CFBundleExecutable"]];
        NSMutableDictionary *pluginDict = buildBundleRegistrationDictionary(pluginPath, pluginBundleID, pluginExecutablePath, YES, bundleIdentifier);
        bundlePlugins[pluginBundleID] = pluginDict;
    }
    dict[@"_LSBundlePlugins"] = bundlePlugins;

    return dict;
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

            // installd owns app bundles as mobile:mobile -- that's uid/gid
            // 33 on iOS, confirmed straight from TrollStore's own working
            // fixPermissionsOfAppBundle(). (Previously used 501:501, which
            // is the macOS convention, not iOS's -- one of the likely
            // causes of the launch crash.)
            recursiveChown(targetPath, 33, 33);

            // This is the actual mechanism TrollStore's own uicache
            // replacement uses (RootHelper/uicache.m, registerPath()) --
            // full port including entitlements-derived containerization,
            // App/System Group containers, and PlugIns/extensions -- not
            // just the main app. Registers directly with LaunchServices,
            // in-process, instead of shelling out to `uicache -a`.
            NSDictionary *registrationDict = buildRegistrationDictionary(targetPath, bundleIdentifier);
            BOOL registered = [[LSApplicationWorkspace defaultWorkspace] registerApplicationDictionary:registrationDict];
            if (!registered) {
                stepThatFailed = @"registerApplicationDictionary";
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
            [[LSApplicationWorkspace defaultWorkspace] unregisterApplication:[NSURL fileURLWithPath:bundlePath]];
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
