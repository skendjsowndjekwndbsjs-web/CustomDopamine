//
//  DOAppManager.h
//  Dopamine
//
//  CustomDopamine: installs .ipa files as jailbroken apps under
//  JBROOT_PATH(/Applications/), the same directory refreshJailbreakApps/
//  unregisterJailbreakApps already manage with uicache. Extraction reuses
//  libarchive_unarchive() -- already linked in for bootstrap.tar.zst/
//  basebin.tar -- since an .ipa is just a zip; no bundled unzip binary
//  needed. Mirrors DOPackageManager's shape (installedX / installX /
//  removeX) so DOPackageManagerController can drive apps the same way
//  it drives dpkg packages.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DOAppInfo : NSObject
@property (nonatomic, copy) NSString *bundleIdentifier;
@property (nonatomic, copy) NSString *displayName;
@property (nonatomic, copy) NSString *version;
@property (nonatomic, copy) NSString *bundlePath; // full path under JBROOT_PATH(/Applications/...)
@end

@interface DOAppManager : NSObject

+ (NSArray<DOAppInfo *> *)installedApps;

// Extracts the ipa, moves Payload/*.app into JBROOT_PATH(/Applications/),
// replacing any existing app with the same CFBundleIdentifier, chowns it
// to mobile:mobile, and re-runs uicache so the icon shows up.
+ (nullable NSError *)installIPAAtPath:(NSString *)path;

+ (nullable NSError *)removeAppAtPath:(NSString *)bundlePath;

@end

NS_ASSUME_NONNULL_END
