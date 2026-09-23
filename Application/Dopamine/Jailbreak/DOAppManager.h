//
//  DOAppManager.h
//  Dopamine
//
//  CustomDopamine: installs .ipa files fully inside this app -- no
//  dependency on a separate installer app. The actual privileged work
//  (MCMAppContainer, LSApplicationWorkspace) is TrollStore's own
//  installApp()/registerPath() logic, ported wholesale into a standalone
//  helper binary (Application/AppInstallHelper), signed at build time with
//  an exact copy of TrollStore's own RootHelper entitlements -- because
//  those private APIs check the CALLING PROCESS's own code-signature
//  entitlements, not just its uid, which is why running the same calls
//  from inside Dopamine.app's own (differently-entitled) process didn't
//  work. This class just copies that helper out, trusts it, and spawns it
//  from an already-root context.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DOAppInfo : NSObject
@property (nonatomic, copy) NSString *bundleIdentifier;
@property (nonatomic, copy) NSString *displayName;
@property (nonatomic, copy) NSString *version;
@property (nonatomic, copy) NSString *bundlePath;
@end

@interface DOAppManager : NSObject

// Only lists apps this installer itself put on the device (tracked via its
// own manifest) -- not every app on the device, which is what actually
// lives at the same real container path now.
+ (NSArray<DOAppInfo *> *)installedApps;

+ (nullable NSError *)installIPAAtPath:(NSString *)path;
+ (nullable NSError *)removeAppWithBundleIdentifier:(NSString *)bundleIdentifier;

@end

NS_ASSUME_NONNULL_END
