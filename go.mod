module github.com/cryptera-device-security/libpkcs11ks

go 1.20

require (
	github.com/miekg/pkcs11 v1.1.1
	golang.org/x/crypto v0.28.0
)

require github.com/cryptera-device-security/pkcs11mod v0.0.0-3f5cd08c0eb38bb4c98fc65d5edd0a084c33194c

replace github.com/namecoin/pkcs11mod => github.com/cryptera-device-security/pkcs11mod v0.0.0-3f5cd08c0eb38bb4c98fc65d5edd0a084c33194c

replace github.com/cryptera-device-security/pkcs11mod => ../pkcs11mod
