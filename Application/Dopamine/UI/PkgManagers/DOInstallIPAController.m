//
//  DOInstallIPAController.m
//  Dopamine
//

#import "DOInstallIPAController.h"
#import "DOAppManager.h"
#import "DOButtonCell.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@implementation DOInstallIPAController

- (id)specifiers
{
    NSMutableArray *specifiers = [NSMutableArray new];

    SEL defGetter = @selector(readPreferenceValue:);
    SEL defSetter = @selector(setPreferenceValue:specifier:);
    NSNumber *buttonHeight = @(44);

    BOOL appSyncInstalled = [DOAppManager isAppSyncInstalled];

    PSSpecifier *headerSpecifier = [PSSpecifier emptyGroupSpecifier];
    headerSpecifier.name = @"Install IPA";
    [specifiers addObject:headerSpecifier];

    if (!appSyncInstalled) {
        // AppSync not installed -- show one-tap install button
        PSSpecifier *installASSpecifier = [PSSpecifier preferenceSpecifierNamed:@""
            target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
        [installASSpecifier setProperty:@"Install AppSync Unified" forKey:@"title"];
        [installASSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [installASSpecifier setProperty:buttonHeight forKey:@"height"];
        [installASSpecifier setProperty:@"square.and.arrow.down.on.square" forKey:@"image"];
        [installASSpecifier setProperty:@"installAppSyncTapped" forKey:@"action"];
        [specifiers addObject:installASSpecifier];

        PSSpecifier *footerSpecifier = [PSSpecifier emptyGroupSpecifier];
        footerSpecifier.name = @"";
        [footerSpecifier setProperty:
            @"AppSync Unified is required for installing .ipa files. "
             "It patches installd to accept any code signature. "
             "Tap above to install it now."
            forKey:@"footerText"];
        [specifiers addObject:footerSpecifier];

        _specifiers = specifiers;
        return _specifiers;
    }

    // AppSync installed -- show the real install button
    PSSpecifier *installAppSpecifier = [PSSpecifier preferenceSpecifierNamed:@""
        target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
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
        PSSpecifier *appSpecifier = [PSSpecifier preferenceSpecifierNamed:@""
            target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
        [appSpecifier setProperty:[NSString stringWithFormat:@"%@ (%@)",
            app.displayName, app.version] forKey:@"title"];
        [appSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [appSpecifier setProperty:buttonHeight forKey:@"height"];
        [appSpecifier setProperty:@"app.badge" forKey:@"image"];
        [appSpecifier setProperty:@"appRowTapped:" forKey:@"action"];
        [appSpecifier setProperty:app.bundleIdentifier forKey:@"customAppBundleIdentifier"];
        [specifiers addObject:appSpecifier];
    }

    if (apps.count == 0) {
        PSSpecifier *emptySpec = [PSSpecifier preferenceSpecifierNamed:@""
            target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
        [emptySpec setProperty:@"No apps installed" forKey:@"title"];
        [specifiers addObject:emptySpec];
    }

    _specifiers = specifiers;
    return _specifiers;
}

#pragma mark - Preference value stubs

- (id)readPreferenceValue:(PSSpecifier *)specifier { return nil; }
- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {}

#pragma mark - AppSync Install

- (void)installAppSyncTapped
{
    UIAlertController *progress = [UIAlertController
        alertControllerWithTitle:@"Installing AppSync Unified…"
        message:@"Please wait."
        preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:progress animated:YES completion:nil];

    [DOAppManager installAppSyncWithCompletion:^(NSError *error) {
        [progress dismissViewControllerAnimated:YES completion:^{
            if (error) {
                UIAlertController *alert = [UIAlertController
                    alertControllerWithTitle:@"Install Failed"
                    message:error.localizedDescription
                    preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                    style:UIAlertActionStyleDefault handler:nil]];
                [self presentViewController:alert animated:YES completion:nil];
            } else {
                // Reload to show the real install UI now
                self->_specifiers = nil;
                [self reloadSpecifiers];
            }
        }];
    }];
}

#pragma mark - Install IPA

- (void)installAppButtonTapped
{
    UTType *ipaType = [UTType typeWithFilenameExtension:@"ipa"] ?: UTTypeData;
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc]
        initForOpeningContentTypes:@[ipaType]];
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller
    didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls
{
    if (urls.count == 0) return;
    NSURL *url = urls.firstObject;

    BOOL accessing = [url startAccessingSecurityScopedResource];

    NSString *localCopyPath = [NSTemporaryDirectory()
        stringByAppendingPathComponent:url.lastPathComponent];
    [[NSFileManager defaultManager] removeItemAtPath:localCopyPath error:nil];
    NSError *copyErr = nil;
    BOOL copied = [[NSFileManager defaultManager]
        copyItemAtURL:url toURL:[NSURL fileURLWithPath:localCopyPath] error:&copyErr];

    if (accessing) [url stopAccessingSecurityScopedResource];

    if (!copied) {
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"Couldn't Read File"
            message:copyErr.localizedDescription
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK"
            style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }

    UIAlertController *progress = [UIAlertController
        alertControllerWithTitle:@"Installing…"
        message:url.lastPathComponent
        preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:progress animated:YES completion:nil];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *installError = [DOAppManager installIPAAtPath:localCopyPath];
        [[NSFileManager defaultManager] removeItemAtPath:localCopyPath error:nil];

        dispatch_async(dispatch_get_main_queue(), ^{
            [progress dismissViewControllerAnimated:YES completion:^{
                if (installError) {
                    UIAlertController *alert = [UIAlertController
                        alertControllerWithTitle:@"Install Failed"
                        message:installError.localizedDescription
                        preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                        style:UIAlertActionStyleDefault handler:nil]];
                    [self presentViewController:alert animated:YES completion:nil];
                } else {
                    self->_specifiers = nil;
                    [self reloadSpecifiers];
                }
            }];
        });
    });
}

#pragma mark - Remove

- (void)appRowTapped:(PSSpecifier *)specifier
{
    NSString *bundleId = [specifier propertyForKey:@"customAppBundleIdentifier"];
    if (!bundleId) return;

    UIAlertController *confirm = [UIAlertController
        alertControllerWithTitle:@"Remove App"
        message:[NSString stringWithFormat:@"Remove %@?", bundleId]
        preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Cancel"
        style:UIAlertActionStyleCancel handler:nil]];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Remove"
        style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            NSError *err = [DOAppManager removeAppWithBundleIdentifier:bundleId];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (err) {
                    UIAlertController *alert = [UIAlertController
                        alertControllerWithTitle:@"Remove Failed"
                        message:err.localizedDescription
                        preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                        style:UIAlertActionStyleDefault handler:nil]];
                    [self presentViewController:alert animated:YES completion:nil];
                } else {
                    self->_specifiers = nil;
                    [self reloadSpecifiers];
                }
            });
        });
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

@end
