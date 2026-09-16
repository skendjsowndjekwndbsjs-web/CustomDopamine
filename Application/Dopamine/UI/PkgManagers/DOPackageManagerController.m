//
//  DOPackageManagerController.m
//  Dopamine
//

#import "DOPackageManagerController.h"
#import "DOPackageManager.h"
#import "DOGlobalAppearance.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@interface DOPackageManagerController ()
@property (nonatomic, strong) NSArray<DOPackageInfo *> *packages;
@end

@implementation DOPackageManagerController

- (instancetype)init
{
    return [super initWithStyle:UITableViewStyleInsetGrouped];
}

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.title = @"Packages";
    self.view.backgroundColor = [DOGlobalAppearance windowColorWithAlpha:1.0];

    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemAdd
        target:self
        action:@selector(installButtonTapped)];

    UIRefreshControl *refresh = [UIRefreshControl new];
    [refresh addTarget:self action:@selector(reloadPackages) forControlEvents:UIControlEventValueChanged];
    self.refreshControl = refresh;

    [self.tableView registerClass:[UITableViewCell class] forCellReuseIdentifier:@"PackageCell"];

    [self reloadPackages];
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    // Packages can change from outside this screen (a fresh bootstrap,
    // or a future repo-install feature), so refresh every time this
    // screen becomes visible, not just on first load.
    [self reloadPackages];
}

- (void)reloadPackages
{
    self.packages = [DOPackageManager installedPackages];
    [self.tableView reloadData];
    [self.refreshControl endRefreshing];
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
        [self reloadPackages];
    }
}

#pragma mark - UITableViewDataSource

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return self.packages.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"PackageCell" forIndexPath:indexPath];
    DOPackageInfo *package = self.packages[indexPath.row];

    UIListContentConfiguration *config = [cell defaultContentConfiguration];
    config.text = package.identifier;
    config.secondaryText = package.packageDescription.length > 0
        ? [NSString stringWithFormat:@"%@ — %@", package.version, package.packageDescription]
        : package.version;
    config.secondaryTextProperties.numberOfLines = 1;
    cell.contentConfiguration = config;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;

    return cell;
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath
{
    return YES;
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath
{
    if (editingStyle != UITableViewCellEditingStyleDelete) return;
    DOPackageInfo *package = self.packages[indexPath.row];

    UIAlertController *confirm = [UIAlertController alertControllerWithTitle:@"Remove Package"
        message:[NSString stringWithFormat:@"Remove %@?", package.identifier]
        preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
        [self.tableView setEditing:NO animated:YES];
    }]];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Remove" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        NSError *removeError = [DOPackageManager removePackageWithIdentifier:package.identifier];
        if (removeError) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Remove Failed"
                message:removeError.localizedDescription
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        } else {
            [self reloadPackages];
        }
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

@end
