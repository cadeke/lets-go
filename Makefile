BINARY_NAME=bin/lets-go
SOURCE_FILE=main.go

build: build-win build-lin build-mac

build-win:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ${BINARY_NAME}-windows.exe ${SOURCE_FILE}

build-lin:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ${BINARY_NAME}-linux ${SOURCE_FILE}

build-mac:
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o ${BINARY_NAME}-macos ${SOURCE_FILE}

test:
	go test -v ./lib -cover

clean:
	go clean
	rm bin/*
	rm tmp/*.enc
