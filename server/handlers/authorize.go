package handlers

import (
	"edgeproxy/server/authorization"
	"edgeproxy/transport"
	"net/http"
)

type httpHandlerFunc func(http.ResponseWriter, *http.Request)

func Authorize(authorizer authorization.Authorizer, acl *authorization.PolicyEnforcer, next httpHandlerFunc) httpHandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		authorized, subject := authorizer.Authorize(res, req)
		if !authorized {
			res.WriteHeader(http.StatusUnauthorized)
			return
		}

		// TODO enforce subject is allowed to do this
		netType := req.Header.Get(transport.HeaderNetworkType)
		dstAddr := req.Header.Get(transport.HeaderDstAddress)
		subj := subject.GetSubject()
		if policyRes, _ := acl.Enforcer.Enforce(subj, dstAddr, netType); policyRes {
			next(res, req)
		} else {
			// deny the request, show an error
			res.WriteHeader(http.StatusForbidden)
			return
		}

	}
}
