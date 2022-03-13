package clientauth

import (
	"crypto/rsa"
	"crypto/x509"
	"edgeproxy/config"
	b64 "encoding/base64"
	"encoding/pem"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

type ClientAuthorizationClaims struct {
	*jwt.StandardClaims
	Nonce string `json:"nonce"`
}

var (
	signKey        *rsa.PrivateKey
	pubkey         *rsa.PublicKey
	certificate    *x509.Certificate
	certificatePem string
)

const (
	HeaderAuthorization = "Authorization"
	HeaderCertificate   = "X-Client-Certificate"
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

func SetCertificate(pemPath string) {
	buf, err := ioutil.ReadFile(pemPath)
	if err != nil {
		log.Fatalf("error loading private key: %v", err)
		return
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		log.Fatalln("failed to parse PEM block containing the key")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("error loading private key: %v", err)
		return
	}

	certificate = cert
	certificatePem = b64.StdEncoding.EncodeToString(buf)
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

func GetClientCertificate() (string, error) {

	return certificatePem, nil
}

type JwtAuthenticator struct {

}

func (receiver JwtAuthenticator) AddAuthenticationHeaders(headers *http.Header)  {
	// TODO: add header
	token, _ := CreateClientToken()
	//cert, _ := GetClientCertificate()
	headers.Add(HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
}


func (receiver JwtAuthenticator) Load(config config.ClientAuthCaConfig)  {
	SetCertificate(config.Certificate)
	SetSigningKey(config.Key)
}