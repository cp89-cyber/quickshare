package server

import (
	"os"
	"testing"
	"time"

	"github.com/ihexxa/quickshare/src/client"
	"github.com/pquerna/otp/totp"
)

func TestTOTPHandlers(t *testing.T) {
	addr := "http://127.0.0.1:8687" // Use a different port to avoid conflict
	rootPath := "tmpTestDataTOTP"
	config := `{
		"users": {
			"enableAuth": true,
			"minUserNameLen": 2,
			"minPwdLen": 4,
			"captchaEnabled": false,
			"predefinedUsers": [
				{
					"name": "totpuser",
					"pwd": "password",
					"role": "user"
				}
			]
		},
		"server": {
			"debug": true,
			"host": "127.0.0.1",
			"port": 8687
		},
		"fs": {
			"root": "tmpTestDataTOTP"
		},
		"db": {
			"dbPath": "tmpTestDataTOTP/quickshare"
		}
	}`
	adminName := "qs"
	adminPwd := "quicksh@re"
	setUpEnv(t, rootPath, adminName, adminPwd)
	defer os.RemoveAll(rootPath)

	srv := startTestServer(config)
	defer srv.Shutdown()

	if !isServerReady(addr) {
		t.Fatal("fail to start server")
	}

	t.Run("test TOTP flow", func(t *testing.T) {
		usersCli := client.NewUsersClient(addr)
		
		// 1. Login
		resp, _, errs := usersCli.Login("totpuser", "password")
		if len(errs) > 0 {
			t.Fatal(errs)
		} else if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}

		// 2. Generate TOTP
		resp, totpResp, errs := usersCli.GenerateTOTP()
		if len(errs) > 0 {
			t.Fatal(errs)
		} else if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}
		if totpResp.Secret == "" {
			t.Fatal("TOTP secret is empty")
		}

		// 3. Enable TOTP
		code, err := totp.GenerateCode(totpResp.Secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		resp, _, errs = usersCli.EnableTOTP(totpResp.Secret, code)
		if len(errs) > 0 {
			t.Fatal(errs)
		} else if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}

		// 4. Logout
		resp, _, errs = usersCli.Logout()
		if len(errs) > 0 {
			t.Fatal(errs)
		} else if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}

		// 5. Login without TOTP (should fail)
		resp, _, errs = usersCli.Login("totpuser", "password")
		if len(errs) > 0 {
			t.Fatal(errs)
		}
		if resp.StatusCode != 403 {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}

		// 6. Login with invalid TOTP (should fail)
		resp, _, errs = usersCli.Login("totpuser", "password", "000000")
		if len(errs) > 0 {
			t.Fatal(errs)
		}
		if resp.StatusCode != 403 {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}

		// 7. Login with valid TOTP (should succeed)
		code, err = totp.GenerateCode(totpResp.Secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		resp, _, errs = usersCli.Login("totpuser", "password", code)
		if len(errs) > 0 {
			t.Fatal(errs)
		} else if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}

		// 8. Disable TOTP
		resp, _, errs = usersCli.DisableTOTP()
		if len(errs) > 0 {
			t.Fatal(errs)
		} else if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}

		// 9. Logout
		resp, _, errs = usersCli.Logout()
		if len(errs) > 0 {
			t.Fatal(errs)
		} else if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}

		// 10. Login without TOTP (should succeed)
		resp, _, errs = usersCli.Login("totpuser", "password")
		if len(errs) > 0 {
			t.Fatal(errs)
		} else if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}
	})
}
