package clientip

import (
	"net"
	"net/http"
	"testing"
)

func trustedSet(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	parsed, err := ParseTrustedCIDRs(cidrs)
	if err != nil {
		t.Fatalf("parse trusted cidrs: %v", err)
	}
	return parsed
}

func extractFrom(t *testing.T, remoteAddr string, xff []string, trusted []*net.IPNet) (net.IP, error) {
	t.Helper()
	req := &http.Request{RemoteAddr: remoteAddr, Header: make(http.Header)}
	for _, v := range xff {
		req.Header.Add("X-Forwarded-For", v)
	}
	return Extract(req, trusted)
}

func wantIP(t *testing.T, got net.IP, err error, want string) {
	t.Helper()
	if err != nil {
		t.Fatalf("extract err = %v, want nil", err)
	}
	if got == nil || got.String() != want {
		t.Fatalf("extract = %v, want %s", got, want)
	}
}

// TestExtractUntrustedRemoteIgnoresXFF 验证未受信对端永远忽略 X-Forwarded-For，
// 无论其中携带什么值。
func TestExtractUntrustedRemoteIgnoresXFF(t *testing.T) {
	t.Parallel()
	trusted := trustedSet(t, "10.0.0.0/8")
	cases := []struct {
		name   string
		remote string
		xff    []string
	}{
		{name: "spoofed left value", remote: "198.51.100.7:8080", xff: []string{"192.168.1.1"}},
		{name: "forged private", remote: "198.51.100.7:8080", xff: []string{"10.0.0.1, 127.0.0.1"}},
		{name: "malformed xff ignored", remote: "198.51.100.7:8080", xff: []string{"not-an-ip"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractFrom(t, tt.remote, tt.xff, trusted)
			wantIP(t, got, err, "198.51.100.7")
		})
	}
}

// TestExtractSingleTrustedHop 验证单级可信代理链：跳过可信代理，返回其前一跳。
func TestExtractSingleTrustedHop(t *testing.T) {
	t.Parallel()
	trusted := trustedSet(t, "10.0.0.0/8")
	got, err := extractFrom(t, "10.0.0.2:8080", []string{"203.0.113.9"}, trusted)
	wantIP(t, got, err, "203.0.113.9")
}

// TestExtractMultiLevelTrustedChain 验证多级可信代理：从右向左跳过可信跳，
// 返回第一个非可信地址。
func TestExtractMultiLevelTrustedChain(t *testing.T) {
	t.Parallel()
	trusted := trustedSet(t, "10.0.0.0/8", "172.16.0.0/12")
	got, err := extractFrom(t, "10.0.0.2:8080", []string{"203.0.113.9, 10.0.0.3, 172.16.0.5"}, trusted)
	wantIP(t, got, err, "203.0.113.9")
}

// TestExtractSpoofedLeftValueRejected 验证伪造左端值不会胜出：从右向左跳过可信跳，
// 返回第一个非可信地址而不是最左值。
func TestExtractSpoofedLeftValueRejected(t *testing.T) {
	t.Parallel()
	trusted := trustedSet(t, "10.0.0.0/8")
	// 边缘代理追加而非覆盖时，攻击者预填左端伪造地址。
	got, err := extractFrom(t, "10.0.0.2:8080", []string{"6.6.6.6, 203.0.113.9"}, trusted)
	wantIP(t, got, err, "203.0.113.9")
}

// TestExtractAllHopsTrustedReturnsLeftmost 验证全部跳都可信时返回最左一跳。
func TestExtractAllHopsTrustedReturnsLeftmost(t *testing.T) {
	t.Parallel()
	trusted := trustedSet(t, "10.0.0.0/8")
	got, err := extractFrom(t, "10.0.0.2:8080", []string{"10.0.0.3, 10.0.0.4"}, trusted)
	wantIP(t, got, err, "10.0.0.3")
}

// TestExtractNoTrustedProxiesFailClosed 验证未配置可信代理时只信任直接连接地址。
func TestExtractNoTrustedProxiesFailClosed(t *testing.T) {
	t.Parallel()
	got, err := extractFrom(t, "198.51.100.7:8080", []string{"6.6.6.6"}, nil)
	wantIP(t, got, err, "198.51.100.7")
}

// TestExtractMultipleXFFHeaders 验证多个 X-Forwarded-For header 按出现顺序展开，
// 逗号拆分后从右向左解析。
func TestExtractMultipleXFFHeaders(t *testing.T) {
	t.Parallel()
	trusted := trustedSet(t, "10.0.0.0/8")
	got, err := extractFrom(t, "10.0.0.2:8080", []string{"203.0.113.9", "198.51.100.4"}, trusted)
	wantIP(t, got, err, "198.51.100.4")
}

// TestExtractMalformedHopRejected 验证来自可信对端的畸形跳返回错误，不静默回退。
func TestExtractMalformedHopRejected(t *testing.T) {
	t.Parallel()
	trusted := trustedSet(t, "10.0.0.0/8")
	_, err := extractFrom(t, "10.0.0.2:8080", []string{"203.0.113.9, not-an-ip"}, trusted)
	if err == nil {
		t.Fatal("malformed hop must return an error")
	}
}

// TestExtractIPv6AndIPv4 验证 IPv6 与 IPv4 跳都能正确规范化并返回。
func TestExtractIPv6AndIPv4(t *testing.T) {
	t.Parallel()
	trusted := trustedSet(t, "2001:db8::/32")
	got, err := extractFrom(t, "[2001:db8::1]:8080", []string{"203.0.113.9"}, trusted)
	wantIP(t, got, err, "203.0.113.9")

	got, err = extractFrom(t, "[2001:db8::1]:8080", []string{"2001:db8::ffff"}, trusted)
	wantIP(t, got, err, "2001:db8::ffff")
}

// TestExtractEmptyXFFFallsBackToRemote 验证可信对端但无有效 XFF 跳时回退 RemoteAddr。
func TestExtractEmptyXFFFallsBackToRemote(t *testing.T) {
	t.Parallel()
	trusted := trustedSet(t, "10.0.0.0/8")
	got, err := extractFrom(t, "10.0.0.2:8080", []string{""}, trusted)
	wantIP(t, got, err, "10.0.0.2")
}
