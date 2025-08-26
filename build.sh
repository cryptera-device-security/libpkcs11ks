#!/bin/sh
CGO_ENABLED=1 go build -buildmode c-shared -o libpkcs11ks.so
