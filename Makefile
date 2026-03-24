PROJECT = Spoofy.xcodeproj
SCHEME = Spoofy
ARCHIVE_DIR = altstore
ARCHIVE_PATH = $(ARCHIVE_DIR)/Spoofy.xcarchive
IPA_NAME = Spoofy.ipa
IPA_PATH = $(ARCHIVE_DIR)/$(IPA_NAME)
EXPORT_DIR = $(ARCHIVE_DIR)/export

ALTSOURCE = $(ARCHIVE_DIR)/altsource.json
ALTSOURCE_ALPHA = $(ARCHIVE_DIR)/altsource-alpha.json
TODAY = $(shell date +%Y-%m-%d)

.PHONY: build release release-alpha _do-release clean

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
	@gh release create "$(TAG_PREFIX)$(VERSION)" "$(IPA_PATH)" --title "$(TAG_PREFIX)$(VERSION)" --generate-notes
	@echo "Released $(TAG_PREFIX)$(VERSION) on GitHub"

clean:
	@rm -rf "$(ARCHIVE_PATH)" "$(EXPORT_DIR)" Payload
	@echo "Cleaned build artifacts"
