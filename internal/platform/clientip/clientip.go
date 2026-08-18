// Package clientip 从请求提取客户端 IP，并做规范化与隐私变换（none/coarse/full）。
// 仅当直接对端位于可信代理 CIDR 内时才信任 X-Forwarded-For；
// 否则使用 RemoteAddr。
package clientip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/mileusna/useragent"
)

// 隐私模式：none 丢弃值、coarse 降级、full 保留。
const (
	// ModeNone 完全丢弃该值（不持久化任何内容）。
	ModeNone = "none"
	// ModeCoarse 保留隐私降低后的值：IPv4 /24、IPv6 /48，以及 UA 的设备/OS/浏览器族。
	ModeCoarse = "coarse"
	// ModeFull 保留规范化后的或原始的值。
	ModeFull = "full"
)

// ParseTrustedCIDRs 将已验证的 CIDR 字符串转换为网段。
// 使用方通常传入静态配置的 TrustedProxies（加载时已校验）；此函数主要供测试与组合使用。
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

// Extract 返回请求的有效客户端 IP。仅当直接对端位于某个可信代理 CIDR 内时，
// 才解析 X-Forwarded-For 可信代理链；否则直接使用 RemoteAddr。
// 链解析从最右一跳向左遍历，跳过位于可信代理 CIDR 的地址，选择第一个非可信
// 地址；全部跳都可信时返回最左一跳。任一非空跳格式错误都返回错误，不静默信任。
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

// xffHops 按 HTTP 字段出现顺序展开全部 X-Forwarded-For header，再按逗号拆分成
// 跳，并对每个非空跳做严格 IP 解析与规范化。任一非空值不是合法 IP 都返回错误。
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

// Normalize 返回 IP 的规范单一形式：IPv4 为 4 字节形式，IPv6 为 16 字节形式，并去除 zone。
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
//   - none 返回 nil（使用方不得持久化该值）；
//   - coarse 将 IPv4 掩码为其 /24 前缀，将 IPv6 掩码为其 /48 前缀；
//   - full 返回规范化后的原始值。
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
// Raw 与 coarse 组件中恰好设置一个：
//   - none：不设置任何字段（不持久化任何内容）；
//   - coarse：设置 Browser、OS 和 Device；Raw 为 nil；
//   - full：设置 Raw；coarse 组件为 nil。
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

// ParseUA 按给定隐私模式处理原始 User-Agent 字符串。none/coarse 模式
// 不记录或持久化原始值。
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
