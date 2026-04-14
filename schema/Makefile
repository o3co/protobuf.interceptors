SCHEMA_DIR := .
SCHEMA_RELS := $(wildcard $(SCHEMA_DIR)/*.proto)

generate:
	protoc -I $(SCHEMA_DIR) \
		--go_out=paths=source_relative:$(SCHEMA_DIR) \
		$(SCHEMA_RELS)
