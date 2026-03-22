ARCHIVE_DIR = altstore
IPA_NAME = Spoofy.ipa
IPA_PATH = $(ARCHIVE_DIR)/$(IPA_NAME)

ALTSOURCE = $(ARCHIVE_DIR)/altsource.json
TODAY = $(shell date +%Y-%m-%d)

.PHONY: ipa release

ipa:
	@ARCHIVE=$$(ls -dt "$(ARCHIVE_DIR)"/*.xcarchive 2>/dev/null | head -1); \
	if [ -z "$$ARCHIVE" ]; then \
		echo "Error: No .xcarchive found in $(ARCHIVE_DIR)/"; \
		exit 1; \
	fi; \
	echo "Using archive: $$ARCHIVE"; \
	rm -rf Payload && mkdir -p Payload; \
	cp -r "$$ARCHIVE/Products/Applications/Spoofy.app" Payload/; \
	rm -f "$(IPA_PATH)"; \
	zip -r "$(IPA_PATH)" Payload; \
	rm -rf Payload; \
	SIZE=$$(stat -f%z "$(IPA_PATH)"); \
	sed -i '' "s/\"size\": [0-9]*/\"size\": $$SIZE/" "$(ARCHIVE_DIR)/altsource.json"; \
	echo "Created $(IPA_PATH) ($$SIZE bytes) and updated altsource.json"

release: ipa
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=1.1 DESCRIPTION="Bug fixes")
endif
ifndef DESCRIPTION
	$(error DESCRIPTION is required. Usage: make release VERSION=1.1 DESCRIPTION="Bug fixes")
endif
	@sed -i '' 's/"version": "[^"]*"/"version": "$(VERSION)"/' "$(ALTSOURCE)"; \
	sed -i '' 's/"versionDate": "[^"]*"/"versionDate": "$(TODAY)"/' "$(ALTSOURCE)"; \
	sed -i '' 's/"versionDescription": "[^"]*"/"versionDescription": "$(DESCRIPTION)"/' "$(ALTSOURCE)"; \
	sed -i '' 's|releases/download/v[^/]*/|releases/download/v$(VERSION)/|' "$(ALTSOURCE)"; \
	echo "Updated altsource.json: version=$(VERSION), date=$(TODAY), downloadURL=v$(VERSION)"; \
	git add "$(ALTSOURCE)" && git commit -m "Release v$(VERSION)" && git push; \
	gh release create "v$(VERSION)" "$(IPA_PATH)" --title "v$(VERSION)" --generate-notes; \
	echo "Released v$(VERSION) on GitHub"
