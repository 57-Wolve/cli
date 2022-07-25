package x509util

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"

	"github.com/pkg/errors"
)

// Leaf implements the Profile for a leaf certificate.
type Leaf struct {
	base
}

// NewLeafProfileWithTemplate returns a new leaf x509 Certificate Profile with
// Subject Certificate set to the value of the template argument.
// A public/private keypair **WILL NOT** be generated for this profile because
// the public key will be populated from the Subject Certificate parameter.
func NewLeafProfileWithTemplate(sub *x509.Certificate, iss *x509.Certificate, issPriv crypto.PrivateKey, withOps ...WithOption) (Profile, error) {
	withOps = append(withOps, WithPublicKey(sub.PublicKey))
	return newProfile(&Leaf{}, sub, iss, issPriv, withOps...)
}

// NewLeafProfile returns a new leaf x509 Certificate profile.
// A new public/private key pair will be generated for the Profile if
// not set in the `withOps` profile modifiers.
func NewLeafProfile(cn string, iss *x509.Certificate, issPriv crypto.PrivateKey, withOps ...WithOption) (Profile, error) {
	sub := defaultLeafTemplate(pkix.Name{CommonName: cn}, iss.Subject)
	return newProfile(&Leaf{}, sub, iss, issPriv, withOps...)
}

// NewSelfSignedLeafProfile returns a new leaf x509 Certificate profile.
// A new public/private key pair will be generated for the Profile if
// not set in the `withOps` profile modifiers.
func NewSelfSignedLeafProfile(cn string, withOps ...WithOption) (Profile, error) {
	sub := defaultLeafTemplate(pkix.Name{CommonName: cn}, pkix.Name{CommonName: cn})
	p, err := newProfile(&Leaf{}, sub, sub, nil, withOps...)
	if err != nil {
		return nil, err
	}
	// self-signed certificate
	p.SetIssuerPrivateKey(p.SubjectPrivateKey())
	return p, nil
}

// NewLeafProfileWithCSR returns a new leaf x509 Certificate Profile with
// Subject Certificate fields populated directly from the CSR.
// A public/private keypair **WILL NOT** be generated for this profile because
// the public key will be populated from the CSR.
func NewLeafProfileWithCSR(csr *x509.CertificateRequest, iss *x509.Certificate, issPriv crypto.PrivateKey, withOps ...WithOption) (Profile, error) {
	if csr.PublicKey == nil {
		return nil, errors.Errorf("CSR must have PublicKey")
	}

	sub := defaultLeafTemplate(csr.Subject, iss.Subject)
	sub.ExtraExtensions = csr.Extensions
	sub.DNSNames = csr.DNSNames
	sub.EmailAddresses = csr.EmailAddresses
	sub.IPAddresses = csr.IPAddresses
	sub.URIs = csr.URIs

	withOps = append(withOps, WithPublicKey(csr.PublicKey))
	return newProfile(&Leaf{}, sub, iss, issPriv, withOps...)
}

func defaultLeafTemplate(sub, iss pkix.Name) *x509.Certificate {
	notBefore := time.Now()
	return &x509.Certificate{
		IsCA:      false,
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(DefaultCertValidity),
		// KeyEncipherment MUST only be used for RSA keys. At signing time we
		// will check the type of the key and remove the KeyEncipherment if
		// necessary.
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			[]int{2, 5, 29, 32, 0},			// All Issuance Policies
			[]int{2, 23, 140, 1, 1},		// Certificate issued in compliance with the Extended Validation Guidelines (2.23.140.1.1)
			[]int{2, 23, 140, 1, 3},		// EV Code Signing Certificate issued in compliance with the Code Signing Baseline Requirements (2.23.140.1.3)
			//[]int{2, 23, 140, 1, 2, 1},	// Certificate issued in compliance with the TLS Baseline Requirements – No entity identity asserted (2.23.140.1.2.1)
			//[]int{2, 23, 140, 1, 2, 2},	// Certificate issued in compliance with the TLS Baseline Requirements – Organization identity asserted (2.23.140.1.2.2)
			//[]int{2, 23, 140, 1, 2, 3},	// Certificate issued in compliance with the TLS Baseline Requirements – Individual identity asserted (2.23.140.1.2.3)
		},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageTimeStamping,
		},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			[]int{1, 3, 6, 1, 4, 1, 311, 20, 2, 2},		// Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
			[]int{1, 3, 6, 1, 4, 1, 311, 10, 3, 12},	// Document Signing (1.3.6.1.4.1.311.10.3.12)
			[]int{1, 3, 6, 1, 4, 1, 311, 80, 1},		// Document Encryption (1.3.6.1.4.1.311.80.1)
		},
		BasicConstraintsValid: false,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
		Issuer:                iss,
		Subject:               sub,
	}
}
