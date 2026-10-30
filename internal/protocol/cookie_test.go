package protocol

import (
	"net/http"
	"strings"
	"testing"
)

func TestSetRawSessionCookieStripsQuotedJarValue(t *testing.T) {
	req, err := http.NewRequest("GET", "https://gateway/vpn/user/portal/intergration.xml", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Cookie", `VSG_SESSIONID="abc,def"`)
	req.Header.Add("Cookie", "other=1")

	setRawSessionCookie(req, "abc,def")

	got := strings.Join(req.Header["Cookie"], "; ")
	if strings.Contains(got, `"`) {
		t.Fatalf("cookie still quoted: %s", got)
	}
	if !strings.Contains(got, "VSG_SESSIONID=abc,def") {
		t.Fatalf("raw session missing: %s", got)
	}
	if !strings.Contains(got, "other=1") {
		t.Fatalf("unrelated cookie dropped: %s", got)
	}
}
