// Package clientip 从请求提取客户端 IP，并做格式化与隐私变换。
package clientip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/mileusna/useragent"
)

// 隐私模式：none 关闭记录、coarse 简单、full 完整。
const (
	// ModeNone 关闭记录。
	ModeNone = "none"
	// ModeCoarse 记录处理后的值：IPv4 /24、IPv6 /48，以及 UA 的设备/OS/浏览器族。
	ModeCoarse = "coarse"
	// ModeFull 记录原始的值。
	ModeFull = "full"
)

// ParseTrustedCIDRs 将已验证的 CIDR 字符串转换为网段。
func ParseTrustedCIDRs(cidrs []string) ([]*net.IPNet, error) {
	parsed := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("clientip: parse trusted proxy %q: %w", cidr, err)
		}
		parsed = append(parsed, ipnet)
	}
	return parsed, nil
}

// Extract 返回请求的有效客户端 IP。
// 仅当位于某个可信代理 CIDR 内时，才解析 X-Forwarded-For 可信代理链；否则直接使用 RemoteAddr。
// 链解析从最右一跳向左遍历，跳过位于可信代理 CIDR 的地址，选择第一个非可信地址；
// 全部跳都可信时返回最左一跳。任一非空跳格式错误都返回错误。
func Extract(r *http.Request, trusted []*net.IPNet) (net.IP, error) {
	remote, err := peerIP(r.RemoteAddr)
	if err != nil {
		return nil, err
	}
	if !isTrusted(remote, trusted) {
		return Normalize(remote), nil
	}
	hops, err := xffHops(r.Header.Values("X-Forwarded-For"))
	if err != nil {
		return nil, fmt.Errorf("clientip: malformed X-Forwarded-For: %w", err)
	}
	if len(hops) == 0 {
		return Normalize(remote), nil
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !isTrusted(hops[i], trusted) {
			return Normalize(hops[i]), nil
		}
	}
	return Normalize(hops[0]), nil
}

// xffHops 按 HTTP 字段出现顺序展开全部 X-Forwarded-For header
func xffHops(values []string) ([]net.IP, error) {
	var hops []net.IP
	for _, value := range values {
		for _, raw := range strings.Split(value, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			ip, err := parseIP(raw)
			if err != nil {
				return nil, err
			}
			hops = append(hops, Normalize(ip))
		}
	}
	return hops, nil
}

func isTrusted(ip net.IP, trusted []*net.IPNet) bool {
	for _, cidr := range trusted {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// peerIP 解析可能包含或不包含端口的 RemoteAddr，包括裸 IPv6 字面量与带 zone 的 IPv6 字面量。
func peerIP(remoteAddr string) (net.IP, error) {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return parseIP(host)
	}
	return parseIP(remoteAddr)
}

func parseIP(host string) (net.IP, error) {
	host = strings.TrimSpace(host)
	if idx := strings.IndexByte(host, '%'); idx >= 0 {
		host = host[:idx]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("clientip: not an IP address")
	}
	return ip, nil
}

// Normalize 返回单一形式的IP
// IPv4 为 4 字节形式，IPv6 为 16 字节形式，并去除 zone。
func Normalize(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

// CoarsenIP 对 IP 应用隐私模式：
// none 返回 nil（使用方不得持久化该值）；
// coarse IPv4 返回 /24 前缀，IPv6 返回 /48 前缀；
// full 返回格式化后的原始值。
func CoarsenIP(ip net.IP, mode string) (net.IP, error) {
	ip = Normalize(ip)
	if ip == nil {
		return nil, errors.New("clientip: nil IP")
	}
	switch mode {
	case ModeNone:
		return nil, nil
	case ModeCoarse:
		if ip4 := ip.To4(); ip4 != nil {
			return masked(ip4, net.CIDRMask(24, 32)), nil
		}
		return masked(ip.To16(), net.CIDRMask(48, 128)), nil
	case ModeFull:
		return ip, nil
	default:
		return nil, fmt.Errorf("clientip: unknown IP mode %q", mode)
	}
}

func masked(ip net.IP, mask net.IPMask) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out.Mask(mask)
}

// UARecord 保存按隐私模式处理后的 User-Agent 记录。
type UARecord struct {
	Raw     *string
	Browser *string
	OS      *string
	Device  *string
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ParseUA 按给定隐私模式处理原始 User-Agent 字符串。
func ParseUA(raw, mode string) (*UARecord, error) {
	switch mode {
	case ModeNone:
		return &UARecord{}, nil
	case ModeFull:
		return &UARecord{Raw: strPtr(raw)}, nil
	case ModeCoarse:
		ua := useragent.Parse(raw)
		device := ua.Device
		if device == "" {
			switch {
			case ua.Mobile:
				device = "mobile"
			case ua.Tablet:
				device = "tablet"
			case ua.Bot:
				device = "bot"
			default:
				device = "desktop"
			}
		}
		return &UARecord{
			Browser: strPtr(ua.Name),
			OS:      strPtr(ua.OS),
			Device:  strPtr(device),
		}, nil
	default:
		return nil, fmt.Errorf("clientip: unknown UA mode %q", mode)
	}
}
