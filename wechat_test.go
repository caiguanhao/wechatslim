package wechatslim

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var emptyClient, badClient, goodClient *Client

func init() {
	emptyClient = New("", "")
	badClient = New(os.Getenv("WECHAT_APPID"), "00000000000000000000000000000000")
	goodClient = New(os.Getenv("WECHAT_APPID"), os.Getenv("WECHAT_APPSECRET"))
}

func TestRaceConditions(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			goodClient.GetWXACodeUnlimit(context.Background(), "", "")
		}()
	}
	wg.Wait()
}

func TestCreateWXAQrcode(t *testing.T) {
	if os.Getenv("ALLOW_ALL") != "1" {
		t.Log("TestCreateWXAQrcode disabled by default as it will use your quota. Use ALLOW_ALL=1 env to enable.")
		return
	}
	ctx := context.Background()
	b, err := goodClient.CreateWXAQrcode(ctx, "/pages/index/index?id=1")
	if err != nil {
		t.Error(err)
	} else if http.DetectContentType(b) != "image/jpeg" {
		t.Error("expected image to be jpeg")
	} else {
		t.Log("image test passed")
	}
}

func TestGetWXACodeUnlimit(t *testing.T) {
	errMustContain := func(actual error, expected string) {
		t.Helper()
		if actual == nil {
			t.Errorf("error should not be nil, should contain %s", expected)
		} else if !strings.Contains(actual.Error(), expected) {
			t.Errorf("expected %s to contain %s", actual.Error(), expected)
		} else {
			t.Log("error test passed")
		}
	}

	var err error
	ctx := context.Background()

	_, err = emptyClient.GetWXACodeUnlimit(ctx, "", "")
	errMustContain(err, "appid missing")

	_, err = badClient.GetWXACodeUnlimit(ctx, "", "")
	errMustContain(err, "invalid appsecret")

	_, err = goodClient.GetWXACodeUnlimit(ctx, "", "")
	errMustContain(err, "invalid length for scene")

	_, err = goodClient.GetWXACodeUnlimit(ctx, "invalid-page", "id=1")
	errMustContain(err, "invalid page")

	b, err := goodClient.GetWXACodeUnlimit(ctx, "", "id=1")
	if err != nil {
		t.Error(err)
	} else if http.DetectContentType(b) != "image/png" {
		t.Error("expected image to be png")
	} else {
		t.Log("image test passed")
	}
}

const key = "qJMcNH17/cfQOf7HKlScvw=="
const iv = "bH0eOEspJ+FrJ2eWXmmarQ=="
const encryped = "S+5IGXxdaFfZxvhaIFuqKVtbQJiNJxod+CYIOkR1PSENfK7rJTLJuSilBRrG" +
	"WihNBZJr7AYHJn824sjkzMdvRv6kDiu8QB7PHntGHZayzgQy9/tGqcPtZ67k" +
	"xxL/QO92HTmaKkqFNZk0nUIMwqJ+eeLXtJKKpvBUi83a++Hgbz4fDuZSH6vp" +
	"vXq6YE7iM6ZDgVrSO6MwO/CClcrFgVXDGw=="

func TestDecrypt(t *testing.T) {
	stringMustEqual := func(actual, expected string) {
		t.Helper()
		if actual == expected {
			t.Log("string test passed")
		} else {
			t.Errorf("expected %s to be %s", actual, expected)
		}
	}

	userInfo, err := Decrypt(key, encryped, iv)
	if err != nil {
		t.Error(err)
	} else {
		stringMustEqual(userInfo.PhoneNumber, "12345678901")
		stringMustEqual(userInfo.PurePhoneNumber, "12345678901")
		stringMustEqual(userInfo.CountryCode, "86")
	}
}

func TestAnalysisGetDailyVisitTrend(t *testing.T) {
	date := os.Getenv("TEST_DATE")
	if date == "" {
		date = time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	}
	ctx := context.Background()
	var b struct {
		Date                         string  `json:"ref_date"`
		SessionsCount                int     `json:"session_cnt"`
		PageViews                    int     `json:"visit_pv"`
		UniqueVisitors               int     `json:"visit_uv"`
		NewUniqueVisitors            int     `json:"visit_uv_new"`
		SecondsOnAppPerSession       float64 `json:"stay_time_session"`
		SecondsOnAppPerUniqueVisitor float64 `json:"stay_time_uv"`
		AveragePageDepth             float64 `json:"visit_depth"`
	}
	goodClient.MustNewRequest(ctx, "POST", UrlAnalysisGetDailyVisitTrend, ReqBodyAnalysisGetDailyVisitTrend{
		BeginDate: date,
		EndDate:   date,
	}).MustDo(&b, "list.*")
	t.Logf("%+v\n", b)
}

// func encrypt(sessionKey, plainText, iv string) (string, error) {
// 	ivBytes, err := base64.StdEncoding.DecodeString(iv)
// 	if err != nil {
// 		return "", err
// 	}
// 	key, err := base64.StdEncoding.DecodeString(sessionKey)
// 	if err != nil {
// 		return "", err
// 	}
// 	cipherText := []byte(plainText)
// 	cipherText, err = pkcs7Pad(cipherText, aes.BlockSize)
// 	if err != nil {
// 		return "", err
// 	}
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return "", err
// 	}
// 	mode := cipher.NewCBCEncrypter(block, ivBytes)
// 	mode.CryptBlocks(cipherText, cipherText)
// 	return base64.StdEncoding.EncodeToString(cipherText), nil
// }
//
// func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
// 	if blocksize <= 0 {
// 		return nil, errors.New("invalid block size")
// 	}
// 	if b == nil || len(b) == 0 {
// 		return nil, errors.New("invalid PKCS7 data")
// 	}
// 	n := blocksize - (len(b) % blocksize)
// 	pb := make([]byte, len(b)+n)
// 	copy(pb, b)
// 	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
// 	return pb, nil
// }
