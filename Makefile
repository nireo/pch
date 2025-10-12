.PHONY: proto test tidy clean

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pb/chat.proto

test:
	go test -v ./...

tidy:
	go mod tidy

clean:
	rm -f pb/*.pb.go
