#!/usr/bin/env bash
protoc -I=../proto  --dart_out=../proto_dart ../proto/*.proto