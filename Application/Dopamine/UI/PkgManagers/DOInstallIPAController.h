//
//  DOInstallIPAController.h
//  Dopamine
//
//  CustomDopamine: standalone home-menu screen for installing .ipa files,
//  separate from the Packages (.deb) screen -- same DOPSListController base
//  as DOPackageManagerController.
//
//  Does NOT install anything itself. TrollStore registers as the default
//  handler for the com.apple.itunes.ipa document type (see TrollStore's
//  own Info.plist, CFBundleDocumentTypes), so the picked .ipa is handed to
//  it through the system "Open In" sheet -- the exact same hand-off Files/
//  Safari/AirDrop already use to open a downloaded .ipa in TrollStore. This
//  runs TrollStore's own real, proven install pipeline (RootHelper, its
//  CoreTrust-bypass signing, its MCMAppContainer/LSApplicationWorkspace
//  calls) instead of trying to reproduce it from inside this app's own,
//  differently-entitled process, which is what didn't work.
//

#import <UIKit/UIKit.h>
#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>
#import "DOPSListController.h"

NS_ASSUME_NONNULL_BEGIN

@interface DOInstallIPAController : DOPSListController <UIDocumentPickerDelegate, UIDocumentInteractionControllerDelegate>

@end

NS_ASSUME_NONNULL_END
