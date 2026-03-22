PROJECT = Spoofy.xcodeproj
SCHEME = Spoofy
ARCHIVE_DIR = altstore
ARCHIVE_PATH = $(ARCHIVE_DIR)/Spoofy.xcarchive
IPA_NAME = Spoofy.ipa
IPA_PATH = $(ARCHIVE_DIR)/$(IPA_NAME)
EXPORT_DIR = $(ARCHIVE_DIR)/export

ALTSOURCE = $(ARCHIVE_DIR)/altsource.json
TODAY = $(shell date +%Y-%m-%d)

.PHONY: build release clean

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
	sed -i '' "s/\"size\": [0-9]*/\"size\": $$SIZE/" "$(ALTSOURCE)"; \
	sed -i '' 's/"version": "[^"]*"/"version": "$(VERSION)"/' "$(ALTSOURCE)"; \
	sed -i '' 's/"versionDate": "[^"]*"/"versionDate": "$(TODAY)"/' "$(ALTSOURCE)"; \
	sed -i '' 's/"versionDescription": "[^"]*"/"versionDescription": "$(DESCRIPTION)"/' "$(ALTSOURCE)"; \
	sed -i '' 's|releases/download/v[^/]*/|releases/download/v$(VERSION)/|' "$(ALTSOURCE)"; \
	echo "Updated altsource.json: version=$(VERSION), date=$(TODAY), downloadURL=v$(VERSION)"
	@git add "$(ALTSOURCE)" "$(PROJECT)/project.pbxproj" && \
	git commit -m "Release v$(VERSION)" && git push
	@gh release create "v$(VERSION)" "$(IPA_PATH)" --title "v$(VERSION)" --generate-notes
	@echo "Released v$(VERSION) on GitHub"

clean:
	@rm -rf "$(ARCHIVE_PATH)" "$(EXPORT_DIR)" Payload
	@echo "Cleaned build artifacts"
