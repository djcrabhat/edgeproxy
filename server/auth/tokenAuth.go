package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"edgeproxy/client/clientauth"
	b64 "encoding/base64"
	"encoding/pem"
	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"regexp"
	"strings"
)

const (
	HeaderAuthorization = "Authorization"
	HeaderCertificate   = "X-Client-Certificate"
)

var (
	pubkey *rsa.PublicKey
)

func SetValidationKey(pemPath string) {
	buf, err := ioutil.ReadFile(pemPath)
	if err != nil {
		log.Fatalf("error loading public key: %v", err)
		return
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		log.Fatalln("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("error loading private key: %v", err)
		return
	}

	pubkey = priv.(*rsa.PublicKey)

}

func IsValidToken(token string, encodedCertificate string) bool {
	var extractToken = regexp.MustCompile(`^Bearer (.*)$`)

	validationErr := validateClientCertificate(encodedCertificate)
	if validationErr != nil {
		log.Debugf("error validting client cert: %v", validationErr)
		return false
	}
	bearerMatch := extractToken.FindStringSubmatch(token)
	if len(bearerMatch) != 2 {
		//not in bearer token format
		log.Debugf("bad auth header %s", token)
		return false
	}

	// TODO: check if we trust the presented encodedCertificate
	// TODO: check the jwt was _signed_ by the same public key the certificate presents

	bearerToken := strings.TrimSpace(bearerMatch[1])

	// TODO: allow more than one signing key
	parsedToken, err := jwt.ParseWithClaims(bearerToken, &clientauth.ClientAuthorizationClaims{}, func(token *jwt.Token) (interface{}, error) {
		return pubkey, nil
	})
	if err != nil {
		log.Debugf("error validting authentication client: %v", err)
		return false
	}
	claims := parsedToken.Claims.(*clientauth.ClientAuthorizationClaims)
	// didn't blow up, meaning it's signed by the right key and not expired
	if claims.StandardClaims.VerifyAudience("edgeproxy", true) {
		return true
	} else {
		log.Debugf("bad audience: %s", claims.StandardClaims.Audience)
		return false
	}
}

func validateClientCertificate(certificate string) error {
	sDec, _ := b64.StdEncoding.DecodeString(certificate)
	block, _ := pem.Decode([]byte(sDec))
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("error loading private key: %v", err)
		return err
	}

	// TODO: build roots
	//roots := x509.NewCertPool()
	//ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	opts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		//Roots:     roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}
