//
//  DOAppManager.h
//  Dopamine
//
//  CustomDopamine: installs .ipa files the same way TrollStore's own
//  "custom" installation method does -- a real MCMAppContainer under
//  /private/var/containers/Bundle/Application/, registered directly with
//  LaunchServices via registerApplicationDictionary:, not a jbroot-local
//  folder. Extraction reuses libarchive_unarchive() -- already linked in
//  for bootstrap.tar.zst/basebin.tar -- since an .ipa is just a zip; no
//  bundled unzip binary needed. Mirrors DOPackageManager's shape
//  (installedX / installX / removeX) so DOPackageManagerController-style
//  screens can drive apps the same way they drive dpkg packages.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DOAppInfo : NSObject
@property (nonatomic, copy) NSString *bundleIdentifier;
@property (nonatomic, copy) NSString *displayName;
@property (nonatomic, copy) NSString *version;
@property (nonatomic, copy) NSString *bundlePath; // full path, under the real MCMAppContainer location
@end

@interface DOAppManager : NSObject

// Only lists apps this installer itself put on the device (tracked via its
// own manifest) -- not every app on the device, which is what actually
// lives at the same real container path now.
+ (NSArray<DOAppInfo *> *)installedApps;

// Extracts the ipa, creates/reuses a real MCMAppContainer for the app's
// CFBundleIdentifier (the same class TrollStore's own custom-install
// method uses -- NOT MCMAppDataContainer, which is only the data
// container), moves Payload/*.app there, chowns it to mobile:mobile, and
// registers it directly with LaunchServices.
+ (nullable NSError *)installIPAAtPath:(NSString *)path;

+ (nullable NSError *)removeAppWithBundleIdentifier:(NSString *)bundleIdentifier;

@end

NS_ASSUME_NONNULL_END
