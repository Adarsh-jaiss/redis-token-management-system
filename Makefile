.phony: build run push
build:
	@go build -o bin/app .
run:build
	@./bin/app

push:
	@git init
	@git add .
	@git commit -s -m "$(msg)"
	@git push -u origin main