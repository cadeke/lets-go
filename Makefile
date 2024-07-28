BINARY_NAME=bin/lets-go
SOURCE_FILE=cmd/main.go

build: build-win build-linux build-macos

build-win:
	GOOS=windows GOARCH=amd64 go build -o ${BINARY_NAME}-win.exe ${SOURCE_FILE}

build-linux:
	GOOS=linux GOARCH=amd64 go build -o ${BINARY_NAME}-linux ${SOURCE_FILE}

build-macos:
	GOOS=darwin GOARCH=amd64 go build -o ${BINARY_NAME}-macos ${SOURCE_FILE}

clean:
	go clean
	rm bin/*