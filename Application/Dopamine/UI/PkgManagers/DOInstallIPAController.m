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

    PSSpecifier *headerSpecifier = [PSSpecifier emptyGroupSpecifier];
    headerSpecifier.name = @"Install IPA";
    [specifiers addObject:headerSpecifier];

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
        [appSpecifier setProperty:app.bundleIdentifier forKey:@"customAppBundleIdentifier"];
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

- (id)readPreferenceValue:(PSSpecifier *)specifier
{
    return nil;
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier
{
}

#pragma mark - Install

- (void)installAppButtonTapped
{
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

    BOOL accessing = [url startAccessingSecurityScopedResource];
    NSError *installError = [DOAppManager installIPAAtPath:url.path];
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

- (void)appRowTapped:(PSSpecifier *)specifier
{
    NSString *bundleIdentifier = [specifier propertyForKey:@"customAppBundleIdentifier"];
    if (!bundleIdentifier) return;

    UIAlertController *confirm = [UIAlertController alertControllerWithTitle:@"Remove App"
        message:[NSString stringWithFormat:@"Remove %@?", bundleIdentifier]
        preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Remove" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        NSError *removeError = [DOAppManager removeAppWithBundleIdentifier:bundleIdentifier];
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
