package app

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"furtalk/internal/platform/config"
	"furtalk/internal/service/comment"
	"furtalk/internal/service/identity"
	"go.uber.org/fx"
)

// testConfig 返回一个能通过生产 Options 图校验的静态配置。
// fx.ValidateApp 不执行构造器，因此数据库连接字段只需要存在。
func testConfig() config.Config {
	return config.Config{
		HTTP: config.HTTPConfig{
			Address:           "127.0.0.1:8080",
			PublicBaseURL:     "http://localhost:8080",
			ShutdownTimeout:   time.Second,
			ReadHeaderTimeout: time.Second,
			ReadTimeout:       time.Second,
			WriteTimeout:      time.Second,
			IdleTimeout:       time.Second,
			MaxHeaderBytes:    1024,
			BodyLimit:         1 << 20,
			RateLimitRate:     10,
			RateLimitBurst:    100,
		},
		Database: config.DatabaseConfig{Dialect: "sqlite", Path: "file:graph_test?mode=memory"},
		Tokens: config.TokensConfig{
			JWTIssuer:         "http://localhost:8080",
			JWTAlgorithm:      "HS256",
			JWTKey:            strings.Repeat("k", 32),
			SecretKey:         strings.Repeat("s", 32),
			JWTLifetime:       time.Hour,
			WidgetJWTLifetime: time.Hour,
		},
		WebAuthn: config.WebAuthnConfig{
			RPID:      "localhost",
			RPOrigins: []string{"http://localhost:8080"},
			RPName:    "Furtalk",
		},
		OAuth: config.OAuthConfig{ClientTimeout: time.Second},
		SMTP:  config.SMTPConfig{Host: "", Port: 587, TLS: "starttls", Timeout: time.Second},
	}
}

// TestProductionGraphValidates 校验与生产完全一致的根 option 依赖图。
// 任一 provider 缺失/重复/循环都会在此暴露，而不是在部署后。
func TestProductionGraphValidates(t *testing.T) {
	if err := fx.ValidateApp(Options(testConfig())); err != nil {
		t.Fatalf("production graph must validate: %v", err)
	}
}

// TestProductionGraphAcceptsWebOption 确保 CLI 运行时 Web 选项不会破坏生产图。
func TestProductionGraphAcceptsWebOption(t *testing.T) {
	if err := fx.ValidateApp(Options(testConfig(), WithWeb(true))); err != nil {
		t.Fatalf("production graph with Web option must validate: %v", err)
	}
}

// TestFeatureProviderOutputsReachServices 确保 featureModule 注册的构造器
// 全部被生产聚合消费，不产生死 provider。配合 TestProductionGraphValidates，
// 它约束 newServices 的精确输入类型，并由 Fx 校验这些类型确实由生产 Options 提供。
func TestFeatureProviderOutputsReachServices(t *testing.T) {
	want := map[reflect.Type]bool{
		reflect.TypeOf((*identity.Signer)(nil)):              false,
		reflect.TypeOf((identity.OAuthProviderFactory)(nil)): false,
		reflect.TypeOf((*comment.WidgetSigner)(nil)):         false,
		reflect.TypeOf((*comment.WidgetJWTVerifier)(nil)):    false,
		reflect.TypeOf((*fatalCoordinator)(nil)):             false,
	}

	constructor := reflect.TypeOf(newServices)
	for i := 0; i < constructor.NumIn(); i++ {
		input := constructor.In(i)
		if _, required := want[input]; required {
			want[input] = true
		}
	}
	for output, reached := range want {
		if !reached {
			t.Errorf("feature provider output %v is not consumed by newServices", output)
		}
	}
}

// 诊断 fixture 使用的小类型；展示 Fx 对缺失、重复与循环依赖的报错。
type (
	dependencyMissing struct{}
	dependencyFoo     struct{}
	dependencyBar     struct{}
	cycleA            struct{}
	cycleB            struct{}
)

func TestGraphDiagnostics(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		err := fx.ValidateApp(
			fx.Provide(func(foo *dependencyFoo) *dependencyBar { return &dependencyBar{} }),
			fx.Invoke(func(*dependencyBar) {}),
		)
		if err == nil {
			t.Fatal("expected missing dependency error")
		}
		if !strings.Contains(err.Error(), "missing type") {
			t.Fatalf("expected a missing-type diagnostic, got: %v", err)
		}
	})

	t.Run("duplicate", func(t *testing.T) {
		err := fx.ValidateApp(
			fx.Provide(func() *dependencyFoo { return &dependencyFoo{} }),
			fx.Provide(func() *dependencyFoo { return &dependencyFoo{} }),
			fx.Invoke(func(*dependencyFoo) {}),
		)
		if err == nil {
			t.Fatal("expected duplicate provider error")
		}
		if !strings.Contains(err.Error(), "already provided") {
			t.Fatalf("expected a duplicate-provider diagnostic, got: %v", err)
		}
	})

	t.Run("cycle", func(t *testing.T) {
		err := fx.ValidateApp(
			fx.Provide(func(b *cycleB) *cycleA { return &cycleA{} }),
			fx.Provide(func(a *cycleA) *cycleB { return &cycleB{} }),
			fx.Invoke(func(*cycleA) {}),
		)
		if err == nil {
			t.Fatal("expected cycle error")
		}
		if !strings.Contains(err.Error(), "cycle") {
			t.Fatalf("expected a cycle diagnostic, got: %v", err)
		}
	})
}
