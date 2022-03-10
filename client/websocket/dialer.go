package websocket

import (
	"context"
	"fmt"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"httpProxy/client/clientauth"
	"httpProxy/client/proxy"
	"httpProxy/server/auth"
	"httpProxy/transport"
	"net"
	"net/http"
	"net/url"
)

type dialer struct {
	Endpoint *url.URL
}

func NewWebSocketDialer(endpoint string) (proxy.Dialer, error) {
	endpointUrl, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	return &dialer{
		Endpoint: endpointUrl,
	}, nil
}

func (d *dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.Dial(network, addr)
}

func (d *dialer) Dial(network string, addr string) (net.Conn, error) {
	if network == "udp" {
		return nil, fmt.Errorf("not Support %s network", network)
	}
	switch d.Endpoint.Scheme {
	case "https":
		d.Endpoint.Scheme = "wss"
		break
	case "http":
		d.Endpoint.Scheme = "ws"
	}
	log.Debugf("Connecting to Websocket tunnel endpoint %s, Forwarding %s %s", d.Endpoint.String(), network, addr)
	headers := http.Header{}
	headers.Add(transport.HeaderNetworkType, transport.TCPNetwork)
	headers.Add(transport.HeaderDstAddress, addr)

	authToken, tokenError := clientauth.CreateClientToken()
	if tokenError != nil {
		log.Errorf("Cannote generate authentication token: %v", tokenError)
		return nil, tokenError
	}
	clientCertificate, certificateError := clientauth.GetClientCertificate()
	if certificateError != nil {
		log.Errorf("Cannote read certificate: %v", certificateError)
		return nil, certificateError
	}
	headers.Add(auth.HeaderAuthorization, fmt.Sprintf("Bearer %s", authToken))
	headers.Add(auth.HeaderCertificate, clientCertificate)
	wssCon, _, err := websocket.DefaultDialer.Dial(d.Endpoint.String(), headers)
	if err != nil {
		log.Errorf("error when dialing Websocket tunnel %s: %v", d.Endpoint.String(), err)
	}
	edgeReadWriter := transport.NewEdgeProxyReadWriter(wssCon)
	return edgeReadWriter, nil
}
