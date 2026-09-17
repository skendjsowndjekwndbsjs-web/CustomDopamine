//
//  DOPackageManagerController.m
//  Dopamine
//

#import "DOPackageManagerController.h"
#import "DOPackageManager.h"
#import "DOButtonCell.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

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
    UTType *debType = [UTType typeWithFilenameExtension:@"deb"] ?: UTTypeData;
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc]
        initForOpeningContentTypes:@[debType]];
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls
{
    if (urls.count == 0) return;
    NSURL *url = urls.firstObject;

    BOOL accessing = [url startAccessingSecurityScopedResource];
    NSError *installError = [DOPackageManager installPackageAtPath:url.path];
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

@end
