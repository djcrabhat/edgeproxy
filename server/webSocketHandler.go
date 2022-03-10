package server

import (
	"context"
	"fmt"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"httpProxy/server/auth"
	"httpProxy/transport"
	"net"
	"net/http"
)

type wsHandler struct {
	upgrader websocket.Upgrader
	ctx      context.Context
}

func NewWebSocketHandler(ctx context.Context, path string) WebSocketHandler {
	return &wsHandler{
		ctx:      ctx,
		upgrader: websocket.Upgrader{},
	}
}

func (ws *wsHandler) socketHandler(w http.ResponseWriter, r *http.Request) {
	netType := r.Header.Get(transport.HeaderNetworkType)
	dstAddr := r.Header.Get(transport.HeaderDstAddress)
	if netType == "" {
		ws.InvalidRequest(w, fmt.Errorf("invalid Net Type"))
		return
	}
	if dstAddr == "" {
		ws.InvalidRequest(w, fmt.Errorf("invalid dst Addr"))
		return
	}

	authToken := r.Header.Get(auth.HeaderAuthorization)
	certEncoded := r.Header.Get(auth.HeaderCertificate)
	if certEncoded == "" {
		ws.InvalidRequest(w, fmt.Errorf("must present a %s header", auth.HeaderCertificate))
		return
	}
	if !auth.IsValidToken(authToken, certEncoded) {
		ws.InvalidRequest(w, fmt.Errorf("invalid authentication"))
		return
	}

	wsConn, err := ws.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("Error during connection upgrade: %v", err)
	}
	edgeReadWriter := transport.NewEdgeProxyReadWriter(wsConn)
	backendConn, err := net.Dial(netType, dstAddr)
	transport.ProxyConnection(edgeReadWriter, backendConn)
	if err != nil {
		log.Errorf("Can not connect to %s: %v", dstAddr, err)
		return
	}

}

func (ws *wsHandler) InvalidRequest(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte(err.Error()))
}
