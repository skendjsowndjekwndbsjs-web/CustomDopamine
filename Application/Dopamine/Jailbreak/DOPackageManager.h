//
//  DOPackageManager.h
//  Dopamine
//
//  CustomDopamine: package manager backend, replacing the Sileo/Zebra
//  bridge. Talks directly to the dpkg binary that ships inside the
//  bootstrap (see Packages/bootstrap-manifest/CLASSIFICATION.md) using
//  the same shell-out pattern DOBootstrapper already uses for its own
//  seed packages (libroot/libkrw/basebin-link).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DOPackageInfo : NSObject
@property (nonatomic, copy) NSString *identifier; // dpkg "Package:" field
@property (nonatomic, copy) NSString *version;     // dpkg "Version:" field
@property (nonatomic, copy, nullable) NSString *packageDescription; // dpkg "Description:" first line only
@end

@interface DOPackageManager : NSObject

// Parses JBROOT_PATH(/var/lib/dpkg/status) into a list of installed
// packages. Returns an empty array (not nil) if the file can't be read.
+ (NSArray<DOPackageInfo *> *)installedPackages;

// Shells out to dpkg -i <path>. Returns an NSError on failure (dpkg's
// stderr output is included in the error's localizedDescription), or
// nil on success. Mirrors -[DOBootstrapper installPackage:]'s exec
// pattern exactly, but exposed here as a small standalone utility so
// the package-manager screen doesn't need to reach into DOBootstrapper.
+ (nullable NSError *)installPackageAtPath:(NSString *)path;

// Shells out to dpkg -r <identifier>.
+ (nullable NSError *)removePackageWithIdentifier:(NSString *)identifier;

@end

NS_ASSUME_NONNULL_END
