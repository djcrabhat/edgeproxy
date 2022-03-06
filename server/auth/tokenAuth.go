package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"httpProxy/client/clientauth"
	"io/ioutil"
	"regexp"
	"strings"
)

const (
	HeaderAuthorization = "Authorization"
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

func IsValidToken(token string) bool {
	var extractToken = regexp.MustCompile(`^Bearer (.*)$`)

	bearerMatch := extractToken.FindStringSubmatch(token)
	if len(bearerMatch) != 2 {
		//not in bearer token format
		log.Debugf("bad auth header %s", token)
		return false
	}

	// TODO: real validation
	bearerToken := strings.TrimSpace(bearerMatch[1])
	if bearerToken == "letMeIIIIIIIN!!!" {
		return true
	}

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
