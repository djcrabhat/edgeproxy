package auth

import (
	"edgeproxy/config"
	"testing"
)

func TestPolicyEnforcer_AuthorizeForward_GoodUser(t *testing.T) {
	aclPolicyPath := config.AclCollection{
		IpPath:     "../../test/resources/example_ip_policy.csv",
		DomainPath: "../../test/resources/example_domain_policy.csv",
	}
	enforcer := NewPolicyEnforcer(aclPolicyPath)
	fa := ForwardAction{
		Subject:         "spiffe://example.com/users/good-user-123",
		DestinationAddr: "192.168.0.10:443",
		NetType:         "tcp",
	}
	authorized := enforcer.AuthorizeForward(fa)
	if !authorized {
		t.Fatalf("%s should have been authorized", fa.DestinationAddr)
	}

	faBadPort := ForwardAction{
		Subject:         "spiffe://example.com/users/good-user-123",
		DestinationAddr: "192.168.0.10:8080",
		NetType:         "tcp",
	}
	authorizedBadPort := enforcer.AuthorizeForward(faBadPort)
	if authorizedBadPort {
		t.Fatalf("%s should not have been authorized", fa.DestinationAddr)
	}
}

func TestPolicyEnforcer_AuthorizeForwardBadUser(t *testing.T) {
	aclPolicyPath := config.AclCollection{
		IpPath:     "../../test/resources/example_ip_policy.csv",
		DomainPath: "../../test/resources/example_domain_policy.csv",
	}
	enforcer := NewPolicyEnforcer(aclPolicyPath)
	fa := ForwardAction{
		Subject:         "spiffe://example.com/users/bad-user",
		DestinationAddr: "10.11.12.13:443",
		NetType:         "tcp",
	}
	authorized := enforcer.AuthorizeForward(fa)
	if authorized {
		t.Fatalf("%s should not have been authorized", fa.DestinationAddr)
	}
}

func TestPolicyEnforcer_AuthorizeForwardUnkownUser(t *testing.T) {
	aclPolicyPath := config.AclCollection{
		IpPath:     "../../test/resources/example_ip_policy.csv",
		DomainPath: "../../test/resources/example_domain_policy.csv",
	}
	enforcer := NewPolicyEnforcer(aclPolicyPath)
	fa := ForwardAction{
		Subject:         "spiffe://some-other-site.com/users/unknown-user",
		DestinationAddr: "10.11.12.13:443",
		NetType:         "tcp",
	}
	authorized := enforcer.AuthorizeForward(fa)
	if authorized {
		t.Fatalf("%s should not have been authorized", fa.DestinationAddr)
	}
}
