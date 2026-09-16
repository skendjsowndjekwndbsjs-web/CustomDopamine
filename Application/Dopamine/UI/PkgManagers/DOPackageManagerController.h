//
//  DOPackageManagerController.h
//  Dopamine
//
//  CustomDopamine: the package-manager screen that replaces the
//  Sileo/Zebra bridge. Lists installed packages (via DOPackageManager,
//  which reads dpkg's own status file) and lets you install a local
//  .deb or remove an installed one.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface DOPackageManagerController : UITableViewController <UIDocumentPickerDelegate>

@end

NS_ASSUME_NONNULL_END
