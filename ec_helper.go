package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func getECParams(der []byte) ([]byte, error) {
	input := cryptobyte.String(der)

	if !input.ReadASN1(&input, asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed certificate")
	}

	var tbs cryptobyte.String
	// do the same trick again as above to extract the raw
	// bytes for Certificate.RawTBSCertificate
	if !input.ReadASN1Element(&tbs, asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed tbs certificate")
	}
	if !tbs.ReadASN1(&tbs, asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed tbs certificate")
	}

	// version
	tbs.SkipOptionalASN1(asn1.Tag(0).Constructed().ContextSpecific())
	// serial
	tbs.SkipASN1(asn1.INTEGER)

	// sig ai seq
	tbs.SkipASN1(asn1.SEQUENCE)

	// inner seq
	tbs.SkipASN1(asn1.SEQUENCE)

	// validity
	tbs.SkipASN1(asn1.SEQUENCE)

	// subject
	tbs.SkipASN1(asn1.SEQUENCE)

	var spki cryptobyte.String
	if !tbs.ReadASN1Element(&spki, asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed spki")
	}

	if !spki.ReadASN1(&spki, asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed spki")
	}

	var pkAISeq cryptobyte.String
	if !spki.ReadASN1(&pkAISeq, asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed public key algorithm identifier")
	}

	pkAISeq.SkipASN1(asn1.OBJECT_IDENTIFIER)

	var params cryptobyte.String
	var tag asn1.Tag
	if !pkAISeq.ReadAnyASN1Element(&params, &tag) {
		return nil, errors.New("x509: malformed parameters")
	}

	return params, nil
}

func getECPoint(cert *x509.Certificate) ([]byte, error) {
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return nil, errors.New("incorrect key type")
	}

	pk, err := cert.PublicKey.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		return nil, err
	}

	return pk.Bytes(), nil
}
