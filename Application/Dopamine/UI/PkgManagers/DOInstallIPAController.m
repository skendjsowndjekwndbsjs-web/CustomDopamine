//
//  DOInstallIPAController.m
//  Dopamine
//

#import "DOInstallIPAController.h"
#import "DOButtonCell.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@interface DOInstallIPAController ()
@property (nonatomic, strong) UIDocumentInteractionController *pendingInteractionController;
@end

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

    PSSpecifier *footerSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
    [footerSpecifier setProperty:@"Hands the file to TrollStore to install -- TrollStore must be installed." forKey:@"footerText"];
    footerSpecifier.name = @"";
    [specifiers addObject:footerSpecifier];

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

#pragma mark - Install (hand off to TrollStore)

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
    NSURL *pickedURL = urls.firstObject;

    BOOL accessing = [pickedURL startAccessingSecurityScopedResource];

    // Copy out of the document picker's security-scoped location into our
    // own tmp -- UIDocumentInteractionController needs to hand this off to
    // a different process (TrollStore), which can't reach into another
    // app's security-scoped picker access.
    NSString *localCopyPath = [NSTemporaryDirectory() stringByAppendingPathComponent:pickedURL.lastPathComponent];
    [[NSFileManager defaultManager] removeItemAtPath:localCopyPath error:nil];
    NSError *copyError = nil;
    BOOL copied = [[NSFileManager defaultManager] copyItemAtURL:pickedURL toURL:[NSURL fileURLWithPath:localCopyPath] error:&copyError];

    if (accessing) [pickedURL stopAccessingSecurityScopedResource];

    if (!copied) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Couldn't Read File"
            message:copyError.localizedDescription
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }

    // Keep a strong reference -- UIDocumentInteractionController doesn't
    // retain itself, and this method returns before the user picks
    // anything from the sheet.
    self.pendingInteractionController = [UIDocumentInteractionController interactionControllerWithURL:[NSURL fileURLWithPath:localCopyPath]];
    self.pendingInteractionController.delegate = self;

    BOOL presented = [self.pendingInteractionController presentOpenInMenuFromRect:CGRectZero inView:self.view animated:YES];
    if (!presented) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"TrollStore Not Found"
            message:@"No app on this device is registered to open .ipa files. Install TrollStore first."
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
}

- (UIViewController *)documentInteractionControllerViewControllerForPreview:(UIDocumentInteractionController *)controller
{
    return self;
}

@end
