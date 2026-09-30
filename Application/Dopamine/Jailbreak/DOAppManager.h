//
//  DOAppManager.h
//  Dopamine
//
//  CustomDopamine: installs .ipa files via the standard installd path,
//  patched by AppSync Unified to accept any signature. No custom helper,
//  no MCMAppContainer calls, no ldid signing -- just
//  LSApplicationWorkspace installApplication:withOptions:error:, the same
//  call every jailbreak package manager uses once AppSync is installed.
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

// Returns YES if AppSync Unified's dylib is present in the bootstrap.
+ (BOOL)isAppSyncInstalled;

// Installs the bundled AppSync Unified .deb via dpkg (needs jailbreak active).
// Calls back on the main queue with an error or nil.
+ (void)installAppSyncWithCompletion:(void (^)(NSError *_Nullable error))completion;

// Only apps this installer put on the device (tracked in our manifest).
+ (NSArray<DOAppInfo *> *)installedApps;

// Installs .ipa via LSApplicationWorkspace (AppSync must be installed).
// Blocking -- call off the main thread.
+ (nullable NSError *)installIPAAtPath:(NSString *)path;

// Uninstalls via LSApplicationWorkspace.
+ (nullable NSError *)removeAppWithBundleIdentifier:(NSString *)bundleIdentifier;

@end

NS_ASSUME_NONNULL_END
