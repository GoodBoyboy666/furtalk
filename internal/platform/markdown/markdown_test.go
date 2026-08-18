package markdown

import (
	"errors"
	"testing"
)

func TestValidateDestinations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want error
	}{
		{name: "http link", body: `[link](https://example.com/path)`, want: nil},
		{name: "mailto link", body: `[link](mailto:user@example.com)`, want: nil},
		{name: "relative link", body: `[link](/docs/start)`, want: nil},
		{name: "anchor link", body: `[link](#section)`, want: nil},
		{name: "http image", body: `![image](https://example.com/image.png)`, want: nil},
		{name: "javascript link", body: `[link](javascript:alert(1))`, want: ErrUnsafeDestination},
		{name: "mixed case javascript link", body: `[link](JaVaScRiPt:alert(1))`, want: ErrUnsafeDestination},
		{name: "data image", body: `![image](data:text/html;base64,abc)`, want: ErrUnsafeDestination},
		{name: "vbscript link", body: `[link](vbscript:msgbox(1))`, want: ErrUnsafeDestination},
		{name: "control character obfuscation", body: `[link](java&#x09;script:alert(1))`, want: ErrUnsafeDestination},
		{name: "encoded colon obfuscation", body: `[link](javascript&colon;alert(1))`, want: ErrUnsafeDestination},
		{name: "network path", body: `[link](//example.com/path)`, want: ErrUnsafeDestination},
		{name: "backslash path", body: `[link](/\\\\example.com)`, want: ErrUnsafeDestination},
		{name: "raw html", body: `<a href="javascript:alert(1)">link</a>`, want: ErrRawHTML},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.body)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Validate(%q) error = %v, want %v", tt.body, err, tt.want)
			}
		})
	}
}
