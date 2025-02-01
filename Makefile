.PHONY : build install

default: install

build:
ifeq ($(OS),Windows_NT)
	set CGO_ENABLED=0
	go build -trimpath -o dist/essd .
	set CGO_ENABLED=
else
	CGO_ENABLED=0 go build -trimpath -o dist/essd .
endif

install:
ifeq ($(OS),Windows_NT)
	set CGO_ENABLED=0
	go install -trimpath github.com/adityasaky/essd
	set CGO_ENABLED=
else
	CGO_ENABLED=0 go install -trimpath github.com/adityasaky/essd
endif

generate:
	go generate ./...
