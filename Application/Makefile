.PHONY: all clean build_clean

all: Dopamine.ipa

AppInstallHelper/DOAppInstallHelper: AppInstallHelper/main.m
	@echo Building DOAppInstallHelper
	clang -framework Foundation -framework CoreServices -framework Security \
		-I../BaseBin/.include \
		-L../BaseBin/.build -ljailbreak \
		-Wl,-rpath,@executable_path/Frameworks \
		-isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -target arm64-apple-ios15.0 \
		-Wno-availability -miphoneos-version-min=15.0 -fobjc-arc \
		-o AppInstallHelper/DOAppInstallHelper AppInstallHelper/main.m
	ldid -SAppInstallHelper/entitlements.plist AppInstallHelper/DOAppInstallHelper

Dopamine.ipa: build/Build/Products/Debug-iphoneos/Dopamine.app AppInstallHelper/DOAppInstallHelper
	@echo Ad-Hoc signing Dopamine
	xattr -rc build/Build/Products/Debug-iphoneos/Dopamine.app
	ldid -SDopamine/Dopamine.entitlements build/Build/Products/Debug-iphoneos/Dopamine.app/Dopamine
	ldid -s build/Build/Products/Debug-iphoneos/Dopamine.app
	cp AppInstallHelper/DOAppInstallHelper build/Build/Products/Debug-iphoneos/Dopamine.app/DOAppInstallHelper
	rm -rf Payload Dopamine.ipa
	mkdir Payload
	cp -r build/Build/Products/Debug-iphoneos/Dopamine.app Payload/Dopamine.app
	zip -Ar Dopamine.ipa Payload
	rm -rf Payload
	rm -rf Dopamine.tipa
	cp Dopamine.ipa Dopamine.tipa

ifeq ($(NIGHTLY), 1)
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO GCC_PREPROCESSOR_DEFINITIONS='NIGHTLY=1 COMMIT_HASH=\"$(COMMIT_HASH)\"'
else
build/Build/Products/Debug-iphoneos/Dopamine.app: FORCE
	xcodebuild -scheme Dopamine -derivedDataPath build -destination 'generic/platform=iOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO
endif

clean:
	rm -rf build Payload Dopamine.ipa Dopamine.tipa AppInstallHelper/DOAppInstallHelper

build_clean:
	rm -rf Payload build

FORCE: ;