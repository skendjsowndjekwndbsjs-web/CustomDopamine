//
//  DOInstallIPAController.h
//  Dopamine
//
//  CustomDopamine: standalone home-menu screen for installing .ipa files,
//  separate from the Packages (.deb) screen -- same DOPSListController base
//  as DOPackageManagerController. Installs entirely inside this app via
//  DOAppManager/the embedded DOAppInstallHelper -- no separate installer
//  app needed.
//

#import <UIKit/UIKit.h>
#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>
#import "DOPSListController.h"

NS_ASSUME_NONNULL_BEGIN

@interface DOInstallIPAController : DOPSListController <UIDocumentPickerDelegate>

@end

NS_ASSUME_NONNULL_END
