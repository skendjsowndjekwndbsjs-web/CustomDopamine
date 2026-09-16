//
//  DOPackageManager.m
//  Dopamine
//

#import "DOPackageManager.h"
#import <libjailbreak/util.h>
#import <unistd.h>

@implementation DOPackageInfo
@end

@implementation DOPackageManager

+ (NSArray<DOPackageInfo *> *)installedPackages
{
    NSMutableArray<DOPackageInfo *> *result = [NSMutableArray new];

    NSString *dpkgStatus = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/var/lib/dpkg/status") encoding:NSUTF8StringEncoding error:nil];
    if (!dpkgStatus) {
        return result;
    }

    // Same per-package block splitting DOBootstrapper already uses in
    // -installedVersionForPackageWithIdentifier:, generalised to walk
    // every block instead of searching for one specific package.
    NSArray<NSString *> *packageBlocks = [dpkgStatus componentsSeparatedByString:@"\n\n"];
    for (NSString *block in packageBlocks) {
        if (block.length == 0) continue;

        __block NSString *identifier = nil;
        __block NSString *version = nil;
        __block NSString *description = nil;
        __block NSString *status = nil;

        [block enumerateLinesUsingBlock:^(NSString * _Nonnull line, BOOL * _Nonnull stop) {
            if ([line hasPrefix:@"Package: "]) {
                identifier = [line substringFromIndex:9];
            } else if ([line hasPrefix:@"Version: "]) {
                version = [line substringFromIndex:9];
            } else if ([line hasPrefix:@"Description: "]) {
                description = [line substringFromIndex:14];
            } else if ([line hasPrefix:@"Status: "]) {
                status = [line substringFromIndex:8];
            }
        }];

        // dpkg keeps entries for removed-but-not-purged packages too;
        // only surface packages that are actually installed.
        if (!identifier || !version) continue;
        if (status && ![status containsString:@"installed"]) continue;

        DOPackageInfo *info = [DOPackageInfo new];
        info.identifier = identifier;
        info.version = version;
        info.packageDescription = description;
        [result addObject:info];
    }

    [result sortUsingComparator:^NSComparisonResult(DOPackageInfo *a, DOPackageInfo *b) {
        return [a.identifier caseInsensitiveCompare:b.identifier];
    }];

    return result;
}

+ (nullable NSError *)installPackageAtPath:(NSString *)path
{
    int r;
    if (getuid() == 0) {
        r = exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"), "-i", path.fileSystemRepresentation, NULL);
    } else {
        // Same non-root fallback DOBootstrapper uses: route through the
        // privileged jbctl helper rather than calling dpkg directly.
        exec_cmd(JBROOT_PATH("/basebin/jbctl"), "internal", "install_pkg", path.fileSystemRepresentation, NULL);
        r = 0;
    }

    if (r != 0) {
        return [NSError errorWithDomain:@"DOPackageManagerErrorDomain" code:r userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:@"dpkg -i exited with status %d", r]
        }];
    }
    return nil;
}

+ (nullable NSError *)removePackageWithIdentifier:(NSString *)identifier
{
    int r = exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"), "-r", identifier.UTF8String, NULL);
    if (r != 0) {
        return [NSError errorWithDomain:@"DOPackageManagerErrorDomain" code:r userInfo:@{
            NSLocalizedDescriptionKey: [NSString stringWithFormat:@"dpkg -r exited with status %d", r]
        }];
    }
    return nil;
}

@end
