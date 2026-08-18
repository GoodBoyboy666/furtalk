package httpx

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type sliceError []string

func (e sliceError) Error() string { return "slice error" }

func TestNewTranslatorValidation(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("sentinel")
	tests := []struct {
		name   string
		groups [][]Mapping
	}{
		{name: "nil target", groups: [][]Mapping{{{Status: http.StatusBadRequest, Code: "bad", Message: "bad"}}}},
		{name: "non-comparable target", groups: [][]Mapping{{{Target: sliceError{"bad"}, Status: http.StatusBadRequest, Code: "bad", Message: "bad"}}}},
		{name: "invalid status", groups: [][]Mapping{{{Target: sentinel, Status: http.StatusOK, Code: "bad", Message: "bad"}}}},
		{name: "missing code", groups: [][]Mapping{{{Target: sentinel, Status: http.StatusBadRequest, Message: "bad"}}}},
		{name: "duplicate", groups: [][]Mapping{{{Target: sentinel, Status: http.StatusBadRequest, Code: "bad", Message: "bad"}}, {{Target: sentinel, Status: http.StatusConflict, Code: "conflict", Message: "conflict"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewTranslator(tt.groups...); err == nil {
				t.Fatal("NewTranslator() error = nil, want validation error")
			}
		})
	}
}

func TestTranslatorCopiesMappingsAndMatchesWrappedErrors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("sentinel")
	group := []Mapping{{Target: sentinel, Status: http.StatusConflict, Code: "conflict", Message: "original"}}
	translator, err := NewTranslator(group)
	if err != nil {
		t.Fatal(err)
	}
	group[0].Code = "mutated"
	group[0].Message = "mutated"

	mapping, ok := translator.Translate(fmt.Errorf("operation failed: %w", sentinel))
	if !ok {
		t.Fatal("Translate() did not match wrapped sentinel")
	}
	if mapping.Code != "conflict" || mapping.Message != "original" {
		t.Fatalf("Translate() = %#v, mappings were not copied", mapping)
	}
}

func TestWriteErrorKnownAndUnknown(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sentinel := errors.New("sentinel")
	translator, err := NewTranslator([]Mapping{{
		Target: sentinel, Status: http.StatusConflict, Code: "conflict", Message: "冲突",
	}})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("known wrapped error", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Set(RequestIDKey, "request-1")
		ctx.Set(translatorContextKey, translator)
		WriteError(ctx, fmt.Errorf("wrapped: %w", sentinel))
		if recorder.Code != http.StatusConflict {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusConflict)
		}
		want := `{"error":{"code":"conflict","message":"冲突","request_id":"request-1","details":{}}}`
		if got := recorder.Body.String(); got != want {
			t.Fatalf("body = %s, want %s", got, want)
		}
	})

	for _, tt := range []struct {
		name       string
		translator *Translator
	}{
		{name: "unknown", translator: translator},
		{name: "missing translator"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			if tt.translator != nil {
				ctx.Set(translatorContextKey, tt.translator)
			}
			WriteError(ctx, errors.New("unknown"))
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
			}
			if len(ctx.Errors) != 1 {
				t.Fatalf("gin errors = %d, want 1", len(ctx.Errors))
			}
		})
	}
}

func TestProtocolParsing(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "0", "-1", "1.5", "9223372036854775808"} {
		if _, err := ParseDecimalID(raw); !errors.Is(err, ErrInvalidID) {
			t.Errorf("ParseDecimalID(%q) error = %v, want ErrInvalidID", raw, err)
		}
	}
	if got, err := ParseDecimalID(" 42 "); err != nil || got != 42 {
		t.Fatalf("ParseDecimalID(valid) = %d, %v", got, err)
	}
}
