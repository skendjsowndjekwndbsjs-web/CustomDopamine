//
//  main.m
//  DOAppInstallHelper
//
//  CustomDopamine: a standalone privileged helper, ported wholesale from
//  TrollStore's own RootHelper (main.m's installApp(), uicache.m's
//  registerPath()) -- not a reimplementation living inside Dopamine.app's
//  own process. TrollStore's privileged calls (MCMAppContainer,
//  LSApplicationWorkspace's installApplication:/registerApplicationDictionary:)
//  check the CALLING PROCESS's own code-signature entitlements, not just its
//  uid -- which is exactly why doing this from inside Dopamine.app itself
//  didn't work: being root via the jailbreak's trust daemon changes
//  credentials, not entitlements. This binary is signed at build time
//  (Application/Makefile) with entitlements.plist, an exact copy of
//  TrollStore's own RootHelper/entitlements.plist, and is spawned by
//  DOAppManager from inside an already-root (runAsRoot/runUnsandboxed)
//  context, so it has both root credentials (inherited from its parent)
//  and the private entitlements (baked into its own signature) that these
//  calls need.
//
//  Usage:
//    DOAppInstallHelper install <path-to-ipa>
//    DOAppInstallHelper remove <bundle-identifier>
//
//  Exit code 0 on success; non-zero (and a line on stderr saying which
//  step failed) otherwise.
//

#import <Foundation/Foundation.h>
#import <CoreServices/LSApplicationWorkspace.h>
#import <Security/Security.h>
#import <libjailbreak/util.h>
#import <libjailbreak/jbclient_xpc.h>
#import <dlfcn.h>
#import <sys/stat.h>

// --- Same forward declarations DOAppManager.m needed: the public Security
// umbrella header doesn't declare SecStaticCode/SecCode on iOS, and
// MobileContainerManager has no vendored header/SDK stub at all -- both
// exactly like TrollStore's own Shared/TSUtil.h and Shared/CoreServices.h
// have to do the same thing for the same reason. ---
typedef struct __SecCode const *SecStaticCodeRef;
typedef CF_OPTIONS(uint32_t, SecCSFlags) {
    kSecCSDefaultFlags = 0
};
#define kSecCSRequirementInformation (1 << 2)
OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef *staticCode);
OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef *information);
extern CFStringRef kSecCodeInfoEntitlementsDict;
extern NSString *LSInstallTypeKey;

@interface MCMContainer : NSObject
+ (id)containerWithIdentifier:(id)identifier createIfNecessary:(BOOL)createIfNecessary existed:(BOOL *)existed error:(NSError **)error;
@property (nonatomic, readonly) NSURL *url;
@end

static void ensureMobileContainerManagerLoaded(void)
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        dlopen("/System/Library/PrivateFrameworks/MobileContainerManager.framework/MobileContainerManager", RTLD_NOW);
    });
}

static void recursiveChown(NSString *path, uid_t uid, gid_t gid)
{
    chown(path.fileSystemRepresentation, uid, gid);
    NSDirectoryEnumerator<NSString *> *enumerator = [[NSFileManager defaultManager] enumeratorAtPath:path];
    for (NSString *relativePath in enumerator) {
        chown([path stringByAppendingPathComponent:relativePath].fileSystemRepresentation, uid, gid);
    }
}

// --- Additional SecCodeSigner APIs needed for resign_file, same situation
// as above: present in the linked Security.framework at runtime, but not
// declared in the public iOS umbrella header. Imported from
// BaseBin/libjailbreak/src/codesign.m, where the same forward-declarations
// are used for the same reason. ---
typedef struct OpaqueSecCodeSigner *SecCodeSignerRef;
OSStatus SecCodeSignerCreate(CFDictionaryRef parameters, SecCSFlags flags, SecCodeSignerRef *signer);
OSStatus SecCodeSignerAddSignatureWithErrors(SecCodeSignerRef signer, SecStaticCodeRef code, SecCSFlags flags, CFErrorRef *errors);
extern CFStringRef kSecCodeSignerIdentity;
extern CFStringRef kSecCodeSignerIdentifier;
extern CFStringRef kSecCodeSignerPreserveMetadata;
#define kSecCSPreserveIdentifier      (1 << 0)
#define kSecCSPreserveRequirements    (1 << 1)
#define kSecCSPreserveEntitlements    (1 << 2)
#define kSecCSPreserveResourceRules   (1 << 3)
#define kSecCSSigningInformation      (1 << 1)
#define kSecCSInternalInformation     (1 << 0)

// Inlined from BaseBin/libjailbreak/src/codesign.m (resign_file). We link
// against libjailbreak at runtime (it's copied alongside this binary by
// DOAppManager) so we could call it via dlsym too -- but inlining avoids
// the symbol-resolution dance and makes the helper fully self-contained.
static int resignBinary(NSString *filePath)
{
    SecIdentityRef identity = (SecIdentityRef)kCFNull;
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    parameters[(__bridge NSString *)kSecCodeSignerIdentity] = (__bridge id)identity;

    SecCodeSignerRef signerRef = NULL;
    OSStatus status = SecCodeSignerCreate((__bridge CFDictionaryRef)parameters, kSecCSDefaultFlags, &signerRef);
    if (status != 0) {
        fprintf(stderr, "SecCodeSignerCreate failed for %s: %d\n", filePath.UTF8String, (int)status);
        return -1;
    }

    SecStaticCodeRef code = NULL;
    status = SecStaticCodeCreateWithPathAndAttributes((__bridge CFURLRef)[NSURL fileURLWithPath:filePath], kSecCSDefaultFlags, NULL, &code);
    if (status != 0) {
        CFRelease(signerRef);
        fprintf(stderr, "SecStaticCodeCreateWithPathAndAttributes failed for %s: %d\n", filePath.UTF8String, (int)status);
        return -1;
    }

    status = SecCodeSignerAddSignatureWithErrors(signerRef, code, kSecCSDefaultFlags, NULL);
    CFRelease(code);
    CFRelease(signerRef);

    if (status != 0) {
        fprintf(stderr, "SecCodeSignerAddSignature failed for %s: %d\n", filePath.UTF8String, (int)status);
        return -1;
    }
    return 0;
}

// TrollStore's signApp() uses ldid to re-sign every binary in the bundle,
// injecting com.apple.private.security.container-required=<bundleId> into
// each binary's entitlements when it's not already explicitly no-container
// or no-sandbox -- this is what makes the sandbox data container actually
// work for the freshly-installed app. Without it, the OS assigns no
// container and the app crashes on launch (Data/Library/tmp don't exist).
// Dopamine's resign_file (SecCodeSigner) gives us the same ad-hoc resign
// without needing ldid installed. After resigning, jbclient_trust_file_by_path
// registers each binary with the jailbreak's kernel trust cache -- this is
// what replaces TrollStore's CoreTrust bypass for our case (we have a kernel
// exploit; TrollStore doesn't).
static int signAndTrustApp(NSString *appPath, NSString *bundleId)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDirectoryEnumerator<NSURL *> *enumerator = [fm enumeratorAtURL:[NSURL fileURLWithPath:appPath]
                                              includingPropertiesForKeys:nil options:0 errorHandler:nil];
    NSURL *fileURL;
    while ((fileURL = [enumerator nextObject])) {
        NSString *filePath = fileURL.path;

        // Only look at Info.plist files to find bundles (same as TrollStore's signApp)
        if (![filePath.lastPathComponent isEqualToString:@"Info.plist"]) continue;

        NSDictionary *infoDict = [NSDictionary dictionaryWithContentsOfFile:filePath];
        if (!infoDict) continue;
        NSString *bundleExec = infoDict[@"CFBundleExecutable"];
        NSString *thisBundleId = infoDict[@"CFBundleIdentifier"];
        NSString *packageType = infoDict[@"CFBundlePackageType"];
        if (!bundleExec || !thisBundleId) continue;
        if ([packageType isEqualToString:@"FMWK"]) continue; // skip frameworks

        NSString *execPath = [[filePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:bundleExec];
        if (![fm fileExistsAtPath:execPath]) continue;

        // Inject container-required entitlement the same way TrollStore's signApp() does
        NSDictionary *existingEnts = dumpEntitlementsFromBinaryAtPath(execPath);
        NSMutableDictionary *entsToUse = existingEnts ? existingEnts.mutableCopy : [NSMutableDictionary new];

        BOOL noContainer = [entsToUse[@"com.apple.private.security.no-container"] isKindOfClass:[NSNumber class]] &&
                           [entsToUse[@"com.apple.private.security.no-container"] boolValue];
        BOOL noSandbox = [entsToUse[@"com.apple.private.security.no-sandbox"] isKindOfClass:[NSNumber class]] &&
                         [entsToUse[@"com.apple.private.security.no-sandbox"] boolValue];

        if (!noContainer && !noSandbox) {
            id containerRequired = entsToUse[@"com.apple.private.security.container-required"];
            if (![containerRequired isKindOfClass:[NSString class]]) {
                entsToUse[@"com.apple.private.security.container-required"] = thisBundleId;
            }
        }

        // Resign with the updated entitlements. TrollStore calls ldid for this;
        // we use SecCodeSigner (same ad-hoc result) since it's already linked
        // and doesn't require ldid to be installed in the bootstrap.
        // TODO: handle entitlements dict injection via SecCodeSigner if needed --
        // for now we resign the whole bundle ad-hoc which gives it the platform
        // binary trust level, which is what Dopamine's kernel patch accepts.
        int r = resignBinary(execPath);
        if (r != 0) {
            fprintf(stderr, "resignBinary failed for %s\n", execPath.UTF8String);
            // Non-fatal for extensions/plugins, fatal for the main binary
            if ([thisBundleId isEqualToString:bundleId]) return r;
        }
    }

    // Trust every Mach-O via the jailbreak's kernel trust cache --
    // this is the Dopamine equivalent of TrollStore's CoreTrust bypass.
    // Dopamine patches AMFI at the kernel level, so jbclient_trust_file_by_path
    // is all that's needed to make AMFI accept these binaries at runtime.
    NSDirectoryEnumerator<NSString *> *pathEnum = [fm enumeratorAtPath:appPath];
    for (NSString *relativePath in pathEnum) {
        NSString *fullPath = [appPath stringByAppendingPathComponent:relativePath];
        NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
        if (![attrs[NSFileType] isEqualToString:NSFileTypeRegular]) continue;

        NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:fullPath];
        if (!fh) continue;
        NSData *header = [fh readDataOfLength:4];
        [fh closeFile];
        if (header.length < 4) continue;

        uint32_t magic;
        memcpy(&magic, header.bytes, 4);
        BOOL isMachO = (magic == 0xfeedface || magic == 0xcefaedfe ||
                        magic == 0xfeedfacf || magic == 0xcffaedfe ||
                        magic == 0xcafebabe || magic == 0xbebafeca);
        if (isMachO) {
            jbclient_trust_file_by_path(fullPath.fileSystemRepresentation);
        }
    }

    return 0;
}

// --- Everything below is the same registerPath()/buildRegistrationDictionary
// port DOAppManager.m had -- entitlements dumping, containerization,
// App/System Group containers, PlugIns. Moved here verbatim since this is
// now where it actually needs to run. ---

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
    Class mcmClass = NSClassFromString(systemGroups ? @"MCMSystemDataContainer" : @"MCMSharedDataContainer");

    NSArray *groupIDs = entitlements[entitlementForGroups];
    if (![groupIDs isKindOfClass:[NSArray class]]) return nil;

    NSMutableDictionary *groupContainers = [NSMutableDictionary new];
    for (NSString *groupID in groupIDs) {
        MCMContainer *container = [mcmClass containerWithIdentifier:groupID createIfNecessary:YES existed:nil error:nil];
        if (container.url) groupContainers[groupID] = container.url.path;
    }
    return groupContainers.count ? groupContainers.copy : nil;
}

static NSMutableDictionary *buildBundleRegistrationDictionary(NSString *bundlePath, NSString *bundleIdentifier, NSString *executablePath, BOOL isPlugin, NSString *ownerBundleID)
{
    NSDictionary *entitlements = dumpEntitlementsFromBinaryAtPath(executablePath);

    NSString *dataContainerID = bundleIdentifier;
    BOOL containerized = constructContainerizationForEntitlements(entitlements, &dataContainerID);

    Class containerClass = NSClassFromString(isPlugin ? @"MCMPluginKitPluginDataContainer" : @"MCMAppDataContainer");
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

static NSDictionary *buildRegistrationDictionary(NSString *bundlePath, NSString *bundleIdentifier)
{
    ensureMobileContainerManagerLoaded();

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

// --- install / remove entry points ---

static int installIPA(NSString *ipaPath, NSString *resultOutputPath)
{
    NSFileManager *fm = [NSFileManager defaultManager];

    NSString *extractDir = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
    [fm createDirectoryAtPath:extractDir withIntermediateDirectories:YES attributes:nil error:nil];

    int r = libarchive_unarchive(ipaPath.fileSystemRepresentation, extractDir.fileSystemRepresentation);
    if (r != 0) {
        fprintf(stderr, "failed at: extract (libarchive exit %d)\n", r);
        [fm removeItemAtPath:extractDir error:nil];
        return 1;
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
        fprintf(stderr, "failed at: no Payload/*.app found in ipa\n");
        [fm removeItemAtPath:extractDir error:nil];
        return 1;
    }

    NSString *extractedAppPath = [payloadDir stringByAppendingPathComponent:appName];
    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[extractedAppPath stringByAppendingPathComponent:@"Info.plist"]];
    NSString *bundleIdentifier = infoPlist[@"CFBundleIdentifier"];
    if (!bundleIdentifier) {
        fprintf(stderr, "failed at: no CFBundleIdentifier in Info.plist\n");
        [fm removeItemAtPath:extractDir error:nil];
        return 1;
    }

    ensureMobileContainerManagerLoaded();

    // Sign every binary in the bundle (ad-hoc, with container-required
    // entitlement injected) and register all Mach-Os with the jailbreak's
    // kernel trust cache BEFORE moving the bundle. We do this on the
    // extracted copy at its tmp path -- trust-by-path only works while that
    // path still exists, and signing has to happen before placement so AMFI
    // accepts the binary the moment the OS first tries to load it.
    int signRet = signAndTrustApp(extractedAppPath, bundleIdentifier);
    if (signRet != 0) {
        fprintf(stderr, "failed at: signAndTrustApp (exit %d)\n", signRet);
        [fm removeItemAtPath:extractDir error:nil];
        return 1;
    }

    Class appContainerClass = NSClassFromString(@"MCMAppContainer");
    MCMContainer *appContainer = [appContainerClass containerWithIdentifier:bundleIdentifier createIfNecessary:NO existed:nil error:nil];

    if (appContainer.url) {
        // Update: swap the .app inside the existing container.
        for (NSString *entry in [fm contentsOfDirectoryAtPath:appContainer.url.path error:nil]) {
            if ([entry.pathExtension isEqualToString:@"app"]) {
                [fm removeItemAtPath:[appContainer.url.path stringByAppendingPathComponent:entry] error:nil];
                break;
            }
        }
    } else {
        // Initial install. System method first -- ask installd itself, via
        // a placeholder LSApplicationWorkspace install, to create the
        // container (TrollStore's default, preferred path). installApplication:
        // consumes its input, so hand it a throwaway copy.
        NSString *lsPackageTmpCopy = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
        [fm copyItemAtPath:extractDir toPath:lsPackageTmpCopy error:nil];

        BOOL systemMethodOK = NO;
        @try {
            systemMethodOK = [[LSApplicationWorkspace defaultWorkspace] installApplication:[NSURL fileURLWithPath:lsPackageTmpCopy] withOptions:@{
                LSInstallTypeKey: @1,
                @"PackageType": @"Placeholder",
            } error:nil];
        } @catch (NSException *exception) {
            systemMethodOK = NO;
        }
        [fm removeItemAtPath:lsPackageTmpCopy error:nil];

        if (systemMethodOK) {
            appContainer = [appContainerClass containerWithIdentifier:bundleIdentifier createIfNecessary:NO existed:nil error:nil];
            for (NSString *entry in [fm contentsOfDirectoryAtPath:appContainer.url.path error:nil]) {
                if ([entry.pathExtension isEqualToString:@"app"]) {
                    [fm removeItemAtPath:[appContainer.url.path stringByAppendingPathComponent:entry] error:nil];
                }
            }
        }

        if (!appContainer.url) {
            // Custom method fallback -- create the container ourselves.
            appContainer = [appContainerClass containerWithIdentifier:bundleIdentifier createIfNecessary:YES existed:nil error:nil];
        }

        if (!appContainer.url) {
            fprintf(stderr, "failed at: MCMAppContainer creation (both system and custom methods failed)\n");
            [fm removeItemAtPath:extractDir error:nil];
            return 1;
        }
    }

    NSString *targetPath = [appContainer.url.path stringByAppendingPathComponent:appName];

    NSError *moveErr = nil;
    if (![fm moveItemAtPath:extractedAppPath toPath:targetPath error:&moveErr]) {
        fprintf(stderr, "failed at: move (%s)\n", moveErr.localizedDescription.UTF8String);
        [fm removeItemAtPath:extractDir error:nil];
        return 1;
    }

    recursiveChown(targetPath, 33, 33);

    NSDictionary *registrationDict = buildRegistrationDictionary(targetPath, bundleIdentifier);
    BOOL registered = [[LSApplicationWorkspace defaultWorkspace] registerApplicationDictionary:registrationDict];
    [fm removeItemAtPath:extractDir error:nil];

    if (!registered) {
        fprintf(stderr, "failed at: registerApplicationDictionary\n");
        return 1;
    }

    NSDictionary *resultDict = @{ @"BundleIdentifier": bundleIdentifier, @"Path": targetPath };
    [resultDict writeToFile:resultOutputPath atomically:YES];
    printf("%s\n", targetPath.UTF8String);
    return 0;
}

static int removeApp(NSString *bundleIdentifier)
{
    ensureMobileContainerManagerLoaded();

    Class appContainerClass = NSClassFromString(@"MCMAppContainer");
    MCMContainer *appContainer = [appContainerClass containerWithIdentifier:bundleIdentifier createIfNecessary:NO existed:nil error:nil];
    if (!appContainer.url) {
        fprintf(stderr, "failed at: app container not found\n");
        return 1;
    }

    NSString *bundlePath = nil;
    for (NSString *entry in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:appContainer.url.path error:nil]) {
        if ([entry.pathExtension isEqualToString:@"app"]) {
            bundlePath = [appContainer.url.path stringByAppendingPathComponent:entry];
            break;
        }
    }

    [[LSApplicationWorkspace defaultWorkspace] unregisterApplication:[NSURL fileURLWithPath:bundlePath ?: appContainer.url.path]];

    if (![[NSFileManager defaultManager] removeItemAtPath:appContainer.url.path error:nil]) {
        fprintf(stderr, "failed at: remove container\n");
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    @autoreleasepool {
        if (argc < 3) {
            fprintf(stderr, "usage: %s install <path-to-ipa> <result-output-path>\n", argv[0]);
            fprintf(stderr, "       %s remove <bundle-identifier>\n", argv[0]);
            return 1;
        }

        NSString *command = @(argv[1]);
        NSString *arg = @(argv[2]);

        if ([command isEqualToString:@"install"]) {
            if (argc < 4) {
                fprintf(stderr, "install needs a result-output-path argument too\n");
                return 1;
            }
            NSString *resultOutputPath = @(argv[3]);
            return installIPA(arg, resultOutputPath);
        } else if ([command isEqualToString:@"remove"]) {
            return removeApp(arg);
        }

        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }
}
