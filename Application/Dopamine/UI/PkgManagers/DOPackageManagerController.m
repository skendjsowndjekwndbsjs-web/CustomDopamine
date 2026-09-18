//
//  DOPackageManagerController.m
//  Dopamine
//

#import "DOPackageManagerController.h"
#import "DOPackageManager.h"
#import "DOAppManager.h"
#import "DOButtonCell.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@interface DOPackageManagerController ()
// documentPicker:didPickDocumentsAtURLs: is shared by both the "Install
// Local Package…" (.deb) and "Install App…" (.ipa) buttons -- this says
// which one is currently open so the one delegate callback knows which
// install path to run.
@property (nonatomic) BOOL pendingPickerIsApp;
@end

@implementation DOPackageManagerController

- (id)specifiers
{
    NSMutableArray *specifiers = [NSMutableArray new];

    SEL defGetter = @selector(readPreferenceValue:);
    SEL defSetter = @selector(setPreferenceValue:specifier:);
    NSNumber *buttonHeight = @(44);

    PSSpecifier *headerSpecifier = [PSSpecifier emptyGroupSpecifier];
    headerSpecifier.name = @"Packages";
    [specifiers addObject:headerSpecifier];

    PSSpecifier *installSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
    [installSpecifier setProperty:@"Install Local Package…" forKey:@"title"];
    [installSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
    [installSpecifier setProperty:buttonHeight forKey:@"height"];
    [installSpecifier setProperty:@"plus.circle" forKey:@"image"];
    [installSpecifier setProperty:@"installButtonTapped" forKey:@"action"];
    [specifiers addObject:installSpecifier];

    PSSpecifier *installedGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
    installedGroupSpecifier.name = @"Installed Packages";
    [specifiers addObject:installedGroupSpecifier];

    NSArray<DOPackageInfo *> *packages = [DOPackageManager installedPackages];
    for (DOPackageInfo *package in packages) {
        PSSpecifier *packageSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
        [packageSpecifier setProperty:[NSString stringWithFormat:@"%@ (%@)", package.identifier, package.version] forKey:@"title"];
        [packageSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [packageSpecifier setProperty:buttonHeight forKey:@"height"];
        [packageSpecifier setProperty:@"shippingbox" forKey:@"image"];
        [packageSpecifier setProperty:@"packageRowTapped:" forKey:@"action"];
        // DOButtonCell always calls performSelector:withObject:<the specifier itself> --
        // stash which package this row represents as a custom property so the single
        // shared handler below knows which one was tapped.
        [packageSpecifier setProperty:package.identifier forKey:@"customPackageIdentifier"];
        [specifiers addObject:packageSpecifier];
    }

    if (packages.count == 0) {
        PSSpecifier *emptySpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
        [emptySpecifier setProperty:@"No packages installed" forKey:@"title"];
        [specifiers addObject:emptySpecifier];
    }

    PSSpecifier *appsHeaderSpecifier = [PSSpecifier emptyGroupSpecifier];
    appsHeaderSpecifier.name = @"Install IPA";
    [specifiers addObject:appsHeaderSpecifier];

    PSSpecifier *installAppSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
    [installAppSpecifier setProperty:@"Install App (.ipa)…" forKey:@"title"];
    [installAppSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
    [installAppSpecifier setProperty:buttonHeight forKey:@"height"];
    [installAppSpecifier setProperty:@"square.and.arrow.down" forKey:@"image"];
    [installAppSpecifier setProperty:@"installAppButtonTapped" forKey:@"action"];
    [specifiers addObject:installAppSpecifier];

    PSSpecifier *installedAppsGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
    installedAppsGroupSpecifier.name = @"Installed Apps";
    [specifiers addObject:installedAppsGroupSpecifier];

    NSArray<DOAppInfo *> *apps = [DOAppManager installedApps];
    for (DOAppInfo *app in apps) {
        PSSpecifier *appSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
        [appSpecifier setProperty:[NSString stringWithFormat:@"%@ (%@)", app.displayName, app.version] forKey:@"title"];
        [appSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [appSpecifier setProperty:buttonHeight forKey:@"height"];
        [appSpecifier setProperty:@"app.badge" forKey:@"image"];
        [appSpecifier setProperty:@"appRowTapped:" forKey:@"action"];
        [appSpecifier setProperty:app.bundlePath forKey:@"customAppBundlePath"];
        [specifiers addObject:appSpecifier];
    }

    if (apps.count == 0) {
        PSSpecifier *emptyAppsSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
        [emptyAppsSpecifier setProperty:@"No apps installed" forKey:@"title"];
        [specifiers addObject:emptyAppsSpecifier];
    }

    _specifiers = specifiers;
    return _specifiers;
}

#pragma mark - Preference value stubs

// defGetter/defSetter below point at these. Our rows are action buttons,
// not persisted key/value preferences, so these are trivial no-ops --
// existing only so nothing ever hits an unrecognized-selector crash if
// some PSListController-internal code path calls get/set on a specifier
// regardless of cell class (DOButtonCell itself never does, per its own
// source, but this costs nothing and removes the risk entirely).

- (id)readPreferenceValue:(PSSpecifier *)specifier
{
    return nil;
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier
{
}

#pragma mark - Install

- (void)installButtonTapped
{
    _pendingPickerIsApp = NO;
    UTType *debType = [UTType typeWithFilenameExtension:@"deb"] ?: UTTypeData;
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc]
        initForOpeningContentTypes:@[debType]];
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)installAppButtonTapped
{
    _pendingPickerIsApp = YES;
    UTType *ipaType = [UTType typeWithFilenameExtension:@"ipa"] ?: UTTypeData;
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc]
        initForOpeningContentTypes:@[ipaType]];
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls
{
    if (urls.count == 0) return;
    NSURL *url = urls.firstObject;
    BOOL isApp = _pendingPickerIsApp;

    BOOL accessing = [url startAccessingSecurityScopedResource];
    NSError *installError = isApp ? [DOAppManager installIPAAtPath:url.path] : [DOPackageManager installPackageAtPath:url.path];
    if (accessing) [url stopAccessingSecurityScopedResource];

    if (installError) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Install Failed"
            message:installError.localizedDescription
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    } else {
        _specifiers = nil;
        [self reloadSpecifiers];
    }
}

#pragma mark - Remove

- (void)packageRowTapped:(PSSpecifier *)specifier
{
    NSString *identifier = [specifier propertyForKey:@"customPackageIdentifier"];
    if (!identifier) return;

    UIAlertController *confirm = [UIAlertController alertControllerWithTitle:@"Remove Package"
        message:[NSString stringWithFormat:@"Remove %@?", identifier]
        preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Remove" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        NSError *removeError = [DOPackageManager removePackageWithIdentifier:identifier];
        if (removeError) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Remove Failed"
                message:removeError.localizedDescription
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        } else {
            self->_specifiers = nil;
            [self reloadSpecifiers];
        }
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

#pragma mark - Remove App

- (void)appRowTapped:(PSSpecifier *)specifier
{
    NSString *bundlePath = [specifier propertyForKey:@"customAppBundlePath"];
    if (!bundlePath) return;

    UIAlertController *confirm = [UIAlertController alertControllerWithTitle:@"Remove App"
        message:[NSString stringWithFormat:@"Remove %@?", bundlePath.lastPathComponent]
        preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Remove" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        NSError *removeError = [DOAppManager removeAppAtPath:bundlePath];
        if (removeError) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Remove Failed"
                message:removeError.localizedDescription
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        } else {
            self->_specifiers = nil;
            [self reloadSpecifiers];
        }
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

@end
