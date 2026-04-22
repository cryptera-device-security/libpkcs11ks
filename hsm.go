package main

import (
	"encoding/asn1"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/miekg/pkcs11"
)

type pkcsObject []*pkcs11.Attribute

func toBytes(value int, size int) []byte {
	b := make([]byte, size)

	for i := 0; i < size; i++ {
		b[size-i-1] = byte(value)
		value >>= 8
	}
	return b
}

func makeObjectID(id int) []byte {
	return toBytes(id, 2)
}

func createX509Cert(id int, label, subject string, data []byte) pkcsObject {
	return pkcsObject{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, subject),
		pkcs11.NewAttribute(pkcs11.CKA_ID, makeObjectID(id)),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, data),
		pkcs11.NewAttribute(pkcs11.CKA_TRUSTED, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
	}
}

func createECPublicKey(id int, label string, ecPoint, ecParams []byte) (pkcsObject, error) {
	encodedPoint, err := asn1.Marshal(ecPoint)
	if err != nil {
		return nil, err
	}

	return pkcsObject{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, makeObjectID(id)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY_RECOVER, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LOCAL, false),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, encodedPoint),
	}, nil
}

func createRSAPublicKey(id int, label string, modulus, exponent []byte) pkcsObject {
	return pkcsObject{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, makeObjectID(id)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY_RECOVER, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LOCAL, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, len(modulus)*8),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, modulus),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, exponent),
	}
}

func createECPrivateKey(id int, label string, ecPoint, ecParams []byte) pkcsObject {
	_ = ecPoint
	return pkcsObject{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN_RECOVER, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_ID, makeObjectID(id)),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_AUTHENTICATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_NEVER_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LOCAL, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_TRUSTED, false),
	}
}

func createRSAPrivateKey(id int, label string, modulus, exponent []byte) pkcsObject {
	return pkcsObject{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN_RECOVER, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_ID, makeObjectID(id)),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, modulus),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, exponent),
		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_AUTHENTICATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_NEVER_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LOCAL, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_TRUSTED, false),
	}
}

func createKeyPair(block *pem.Block, cert *x509.Certificate, id int, label string) (pkcsObject, pkcsObject, error) {
	if cert.PublicKeyAlgorithm == x509.ECDSA {
		ecPoint, err := getECPoint(cert)
		if err != nil {
			return nil, nil, err
		}

		ecParams, err := getECParams(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		pub, err := createECPublicKey(id, label, ecPoint, ecParams)
		if err != nil {
			return nil, nil, err
		}
		return pub, createECPrivateKey(id, label, ecPoint, ecParams), nil
	} else if cert.PublicKeyAlgorithm == x509.RSA {
		pk := cert.PublicKey.(*rsa.PublicKey)
		pub := createRSAPublicKey(id, label, pk.N.Bytes(), toBytes(pk.E, 8))
		priv := createRSAPrivateKey(id, label, pk.N.Bytes(), toBytes(pk.E, 8))
		return pub, priv, nil
	}
	return nil, nil, fmt.Errorf("unknown certificate type")
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

		pub, pk, err := createKeyPair(block, cert, id, crt.Keyid)
		if err != nil {
			continue
		}

		x509crt := createX509Cert(id, crt.Keyid, crt.Keyinfo, block.Bytes)
		objs = append(objs, pub)
		objs = append(objs, pk)
		objs = append(objs, x509crt)
		id++
	}

	return objs
}
