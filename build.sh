version=1.0.0

ldflags=''
ldflags+="$ldflags -s -w"  # -s  删除符号表 -w  删除调试信息
ldflags+="$ldflags -X main.Version=$version"  # 注入版本信息

GOOS=linux GOARCH=amd64 go build -ldflags="$ldflags" -o bin/oauth2acf-linux-arm64
GOOS=darwin GOARCH=arm64 go build -ldflags="$ldflags" -o bin/oauth2acf-macos-arm64
GOOS=windows GOARCH=amd64 go build -ldflags="$ldflags" -o bin/oauth2acf-windows-amd64.exe
