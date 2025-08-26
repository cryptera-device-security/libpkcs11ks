FROM golang AS builder

WORKDIR /app

# Clone pkcs11mod dependency
RUN git clone https://github.com/cryptera-device-security/pkcs11mod.git

# Copy your pksc11ks source code into the build context
COPY . ./libpkcs11ks

# Prepare pkcs11mod module
RUN cd pkcs11mod && \
    go mod init github.com/cryptera-device-security/pkcs11mod && \
    go mod tidy && \
    go generate ./...

# Build the pkcs11ks library, build path within the comtainer app/libpkcs11ks/libpkcs11ks.so
RUN cd libpkcs11ks && \
    go mod edit -replace github.com/cryptera-device-security/pkcs11mod=../pkcs11mod && \
    go mod tidy && \
    chmod +x build.sh && \
    ./build.sh

    
FROM alpine
COPY --from=builder /app/libpkcs11ks/libpkcs11ks.so /libpkcs11ks/
CMD ["cp", "/libpkcs11ks/libpkcs11ks.so", "/output/"]