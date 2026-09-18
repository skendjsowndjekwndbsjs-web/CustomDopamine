//
//  DOPackageManagerController.h
//  Dopamine
//
//  CustomDopamine: the package-manager screen that replaces the
//  Sileo/Zebra bridge. Built on DOPSListController -- the same base
//  class DOSettingsController uses -- so it presents exactly the way
//  every other screen in this app does, instead of the plain
//  UITableViewController this started as.
//

#import <UIKit/UIKit.h>
#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>
#import "DOPSListController.h"

NS_ASSUME_NONNULL_BEGIN

@interface DOPackageManagerController : DOPSListController <UIDocumentPickerDelegate>

@end

NS_ASSUME_NONNULL_END
