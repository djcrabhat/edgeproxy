package clientauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"math/rand"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

type ClientAuthorizationClaims struct {
	*jwt.StandardClaims
	Nonce string `json:"nonce"`
}

var (
	signKey *rsa.PrivateKey
	pubkey  *rsa.PublicKey
)

func SetSigningKey(pemPath string) {
	buf, err := ioutil.ReadFile(pemPath)
	if err != nil {
		log.Fatalf("error loading private key: %v", err)
		return
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		log.Fatalln("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("error loading private key: %v", err)
		return
	}

	signKey = priv
}

func CreateClientToken() (string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	t.Claims = &ClientAuthorizationClaims{
		&jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 10).Unix(),
			Audience:  "edgeproxy",
		},
		strconv.Itoa(rand.Int()),
	}
	return t.SignedString(signKey)
}
