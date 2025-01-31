package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/miekg/pkcs11"
)

type pkcsObject []*pkcs11.Attribute

func toBytes(value int, size int) []byte {
	b := make([]byte, size)

	for i := range size {
		b[size-i-1] = byte(value)
		value >>= 8
	}
	return b
}

func createX509Cert(id int, label, subject string, data []byte) pkcsObject {
	return pkcsObject{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, subject),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, data),
	}
}

func createECPrivateKey(id int, label string, ecPoint, ecParams []byte) pkcsObject {
	return pkcsObject{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPoint),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_AUTHENTICATE, false),
	}
}

func createRSAPrivateKey(id int, label string, modulus, exponent []byte) pkcsObject {
	return pkcsObject{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, modulus),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, exponent),
		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_AUTHENTICATE, false),
	}
}

func createPrivateKey(block *pem.Block, cert *x509.Certificate, id int, label string) (pkcsObject, error) {
	if cert.PublicKeyAlgorithm == x509.ECDSA {
		ecPoint, err := getECPoint(cert)
		if err != nil {
			return pkcsObject{}, err
		}

		ecParams, err := getECParams(block.Bytes)
		if err != nil {
			return pkcsObject{}, err
		}
		return createECPrivateKey(id, label, ecPoint, ecParams), nil
	} else if cert.PublicKeyAlgorithm == x509.RSA {
		pk := cert.PublicKey.(*rsa.PublicKey)
		return createRSAPrivateKey(id, label, pk.N.Bytes(), toBytes(pk.E, 8)), nil
	}
	return pkcsObject{}, fmt.Errorf("unknown certificate type")
}

func parseCerts(certs []KeyServerCert) []pkcsObject {
	objs := make([]pkcsObject, 0, len(certs)*3)

	id := 0x1000

	for _, crt := range certs {
		block, _ := pem.Decode([]byte(crt.Certificate))
		if block == nil || block.Type != "CERTIFICATE" {
			fmt.Println("Incorrect certificate for key:", crt.Keyid)
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		pk, err := createPrivateKey(block, cert, id, crt.Keyid)
		if err != nil {
			continue
		}
		id++

		x509crt := createX509Cert(id, crt.Keyid, crt.Keyinfo, block.Bytes)
		id++

		objs = append(objs, pk)
		objs = append(objs, x509crt)
	}

	return objs
}
