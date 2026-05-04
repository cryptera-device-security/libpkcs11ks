module github.com/cryptera-device-security/libpkcs11ks

go 1.25.0

require (
	github.com/miekg/pkcs11 v1.1.1
	golang.org/x/crypto v0.50.0
)

require github.com/cryptera-device-security/pkcs11mod v1.0.1

replace github.com/cryptera-device-security/pkcs11mod => ../pkcs11mod
