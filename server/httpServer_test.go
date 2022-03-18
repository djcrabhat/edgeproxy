package server

import (
	"context"
	"crypto/rand"
	auth2 "edgeproxy/server/auth"
	"edgeproxy/transport"
	"encoding/base64"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/http/httptest"
	url2 "net/url"
	"testing"
)

func generateChallengeKey() (string, error) {
	p := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, p); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}

func TestAPIServer_CanConnectWSS(t *testing.T) {
	ctx := context.Background()
	auth := auth2.NoopAuthorizer()
	server := NewHttpServer(ctx, auth, auth, 8080)
	//rec := httptest.NewRecorder()

	//req, _ := http.NewRequest("GET", "/", nil)
	headers := http.Header{}

	headers.Add(transport.HeaderNetworkType, transport.TcpNetType.String())
	headers.Add(transport.HeaderDstAddress, "8.8.8.8:443")
	headers.Add(transport.HeaderMuxerType, string(transport.HttpNoMuxer))
	headers.Add(transport.HeaderRouterAction, transport.ConnectionForwardRouterAction.String())

	s := httptest.NewServer(server.srv.Handler)
	defer s.Close()

	url, _ := url2.Parse(s.URL)
	switch url.Scheme {
	case "https":
		url.Scheme = "wss"
		break
	case "http":
		url.Scheme = "ws"
	}

	ws, _, err := websocket.DefaultDialer.Dial(url.String(), headers)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	if err := ws.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("%v", err)
	}
}
