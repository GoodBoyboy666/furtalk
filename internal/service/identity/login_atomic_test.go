package identity

import (
	"context"
	"errors"
	"sync"
	"testing"

	"furtalk/internal/domain"
)

// TestLoginWithEmailCodeConcurrentWrongAttemptsDoNotLoseCount 证明在并发错误验证码
// 提交下，失败次数在原子边界内累计且不丢失：耗尽最大尝试次数后记录被消费，
// 后续正确验证码也无法登录。
func TestLoginWithEmailCodeConcurrentWrongAttemptsDoNotLoseCount(t *testing.T) {
	db := newCaptchaLoginDB(t)
	svc := captchaLoginService(t, db, map[string]bool{}, &recordingCaptchaVerifier{})
	insertVerifiedUser(t, db, "user@example.com")
	seedEmailCode(t, svc, "user@example.com", "123456")

	const workers = 20
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := svc.LoginWithEmailCode(context.Background(), EmailCodeLoginInput{Email: "user@example.com", Code: "wrong"})
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatalf("wrong attempt %d err = %v, want ErrInvalidCredentials", i, err)
		}
	}

	// 耗尽最大尝试次数后，正确验证码必须同样失败（记录已被原子消费）。
	if _, err := svc.LoginWithEmailCode(context.Background(), EmailCodeLoginInput{Email: "user@example.com", Code: "123456"}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("correct code after exhaustion err = %v, want ErrInvalidCredentials", err)
	}
}

// TestLoginWithEmailCodeConcurrentCorrectSingleSuccess 证明并发正确验证码提交下
// 只有一个请求成功登录，其余请求因验证码已被消费而失败。
func TestLoginWithEmailCodeConcurrentCorrectSingleSuccess(t *testing.T) {
	db := newCaptchaLoginDB(t)
	svc := captchaLoginService(t, db, map[string]bool{}, &recordingCaptchaVerifier{})
	insertVerifiedUser(t, db, "user@example.com")
	seedEmailCode(t, svc, "user@example.com", "123456")

	const workers = 20
	var wg sync.WaitGroup
	successes := 0
	var mu sync.Mutex
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := svc.LoginWithEmailCode(context.Background(), EmailCodeLoginInput{Email: "user@example.com", Code: "123456"})
			mu.Lock()
			defer mu.Unlock()
			errs[i] = err
			if err == nil {
				successes++
			}
		}(i)
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successful logins = %d, want exactly 1", successes)
	}
	if emailCodeStillValid(t, svc, "user@example.com") {
		t.Fatal("email code must be consumed after a successful concurrent login")
	}
}
