package wechatslim

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
)

var emptyClient, badClient, goodClient *Client

func init() {
	emptyClient = New("", "")
	badClient = New(os.Getenv("WECHAT_APPID"), "00000000000000000000000000000000")
	goodClient = New(os.Getenv("WECHAT_APPID"), os.Getenv("WECHAT_APPSECRET"))
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
