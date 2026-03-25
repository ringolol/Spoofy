PROJECT = Spoofy.xcodeproj
SCHEME = Spoofy
ARCHIVE_DIR = altstore
ARCHIVE_PATH = $(ARCHIVE_DIR)/Spoofy.xcarchive
IPA_NAME = Spoofy.ipa
IPA_PATH = $(ARCHIVE_DIR)/$(IPA_NAME)
EXPORT_DIR = $(ARCHIVE_DIR)/export
MACOS_ARCHIVE_PATH = $(ARCHIVE_DIR)/Spoofy-macOS.xcarchive
MACOS_APP_NAME = Spoofy.app
MACOS_ZIP_NAME = Spoofy-macOS.zip
MACOS_ZIP_PATH = $(ARCHIVE_DIR)/$(MACOS_ZIP_NAME)

ALTSOURCE = $(ARCHIVE_DIR)/altsource.json
ALTSOURCE_ALPHA = $(ARCHIVE_DIR)/altsource-alpha.json
TODAY = $(shell date +%Y-%m-%d)

TEAM_ID := $(shell grep "DEVELOPMENT_TEAM" $(PROJECT)/project.pbxproj | grep -v '""' | head -n 1 | awk -F' = ' '{print $$2}' | tr -d ' ;"')

.PHONY: build build-macos install-macos release release-alpha _do-release clean

build:
	@echo "Archiving $(SCHEME)..."
	xcodebuild archive \
		-project "$(PROJECT)" \
		-scheme "$(SCHEME)" \
		-archivePath "$(ARCHIVE_PATH)" \
		-destination "generic/platform=iOS" \
		CODE_SIGN_IDENTITY="" \
		CODE_SIGNING_REQUIRED=NO \
		CODE_SIGNING_ALLOWED=NO \
		| tail -1
	@echo "Creating IPA..."
	@rm -rf Payload && mkdir -p Payload
	@cp -r "$(ARCHIVE_PATH)/Products/Applications/Spoofy.app" Payload/
	@rm -f "$(IPA_PATH)"
	@zip -qr "$(IPA_PATH)" Payload
	@rm -rf Payload
	@echo "Created $(IPA_PATH)"

build-macos:
	@echo "Archiving $(SCHEME) for macOS Catalyst..."
	xcodebuild archive \
		-project "$(PROJECT)" \
		-scheme "$(SCHEME)" \
		-archivePath "$(MACOS_ARCHIVE_PATH)" \
		-destination "platform=macOS,variant=Mac Catalyst" \
		CODE_SIGN_IDENTITY="" \
		CODE_SIGNING_REQUIRED=NO \
		CODE_SIGNING_ALLOWED=NO \
		| tail -1
	@echo "Creating macOS zip..."
	@rm -f "$(MACOS_ZIP_PATH)"
	@cd "$(MACOS_ARCHIVE_PATH)/Products/Applications" && zip -qr "../../../$(MACOS_ZIP_NAME)" "$(MACOS_APP_NAME)"
	@echo "Created $(MACOS_ZIP_PATH)"

release:
	@$(MAKE) _do-release TAG_PREFIX=v RELEASE_ALTSOURCE="$(ALTSOURCE)"

release-alpha:
	@$(MAKE) _do-release TAG_PREFIX=a RELEASE_ALTSOURCE="$(ALTSOURCE_ALPHA)"

_do-release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=1.2 DESCRIPTION="Bug fixes")
endif
ifndef DESCRIPTION
	$(error DESCRIPTION is required. Usage: make release VERSION=1.2 DESCRIPTION="Bug fixes")
endif
	@echo "Bumping version to $(VERSION)..."
	@sed -i '' 's/MARKETING_VERSION = [^;]*/MARKETING_VERSION = $(VERSION)/' "$(PROJECT)/project.pbxproj"
	@$(MAKE) build
	@$(MAKE) build-macos
	@SIZE=$$(stat -f%z "$(IPA_PATH)"); \
	jq --arg ver "$(VERSION)" \
	   --arg date "$(TODAY)" \
	   --arg desc "$(DESCRIPTION)" \
	   --arg prefix "$(TAG_PREFIX)" \
	   --argjson size $$SIZE \
	   '.apps[0].version = $$ver | .apps[0].versionDate = $$date | .apps[0].versionDescription = $$desc | .apps[0].size = $$size | .apps[0].downloadURL = "https://github.com/ringolol/Spoofy/releases/download/\($$prefix)\($$ver)/Spoofy.ipa"' \
	   "$(RELEASE_ALTSOURCE)" > "$(RELEASE_ALTSOURCE).tmp" && mv "$(RELEASE_ALTSOURCE).tmp" "$(RELEASE_ALTSOURCE)"; \
	echo "Updated $(RELEASE_ALTSOURCE): version=$(VERSION), date=$(TODAY), downloadURL=$(TAG_PREFIX)$(VERSION)"
	@git add "$(RELEASE_ALTSOURCE)" "$(PROJECT)/project.pbxproj" && \
	git commit --allow-empty -m "Release $(TAG_PREFIX)$(VERSION)" && git push
	@gh release create "$(TAG_PREFIX)$(VERSION)" "$(IPA_PATH)" "$(MACOS_ZIP_PATH)" --title "$(TAG_PREFIX)$(VERSION)" --generate-notes
	@echo "Released $(TAG_PREFIX)$(VERSION) on GitHub"

CATALYST_BUILD_DIR = build/maccatalyst

install-macos:
	@echo "Building $(SCHEME) for macOS Catalyst..."
	xcodebuild build \
		-project "$(PROJECT)" \
		-scheme "$(SCHEME)" \
		-configuration Release \
		-destination "platform=macOS,variant=Mac Catalyst" \
		-derivedDataPath "$(CATALYST_BUILD_DIR)" \
		CODE_SIGN_STYLE=Automatic \
		DEVELOPMENT_TEAM="$(TEAM_ID)" \
		| tail -1
	@rm -rf /Applications/Spoofy.app
	@cp -R "$(CATALYST_BUILD_DIR)/Build/Products/Release-maccatalyst/Spoofy.app" /Applications/
	@echo "Installed /Applications/Spoofy.app"

clean:
	@rm -rf "$(ARCHIVE_PATH)" "$(MACOS_ARCHIVE_PATH)" "$(EXPORT_DIR)" Payload
	@echo "Cleaned build artifacts"
