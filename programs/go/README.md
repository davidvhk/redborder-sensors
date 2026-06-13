CGO_ENABLED=0 GOOS=linux go build -ldflags "-extldflags '-static'" -o webserver webserver.go
