//
//  DOInstallIPAController.h
//  Dopamine
//
//  CustomDopamine: standalone home-menu screen for installing .ipa files,
//  separate from the Packages (.deb) screen -- same DOPSListController base
//  and DOButtonCell row pattern as DOPackageManagerController.
//

#import <UIKit/UIKit.h>
#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>
#import "DOPSListController.h"

NS_ASSUME_NONNULL_BEGIN

@interface DOInstallIPAController : DOPSListController <UIDocumentPickerDelegate>

@end

NS_ASSUME_NONNULL_END
