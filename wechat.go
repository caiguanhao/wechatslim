package wechatslim

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
)

type (
	Client struct {
		AppId     string
		AppSecret string
	}

	WechatError struct {
		Code     int    `json:"errcode"`
		Messsage string `json:"errmsg"`
	}

	wechatAccessToken struct {
		AccessToken string `json:"access_token"`
	}

	wechatSession struct {
		OpenId     string `json:"openid"`
		SessionKey string `json:"session_key"`
		UnionId    string `json:"unionid"`
	}

	wechatCreateWXAQrcodeRequest struct {
		Path  string `json:"path"`
		Width int    `json:"width"`
	}

	wechatGetWXACodeUnlimitRequest struct {
		Page        string `json:"page"`
		Scene       string `json:"scene"`
		Width       int    `json:"width"`
		Transparent bool   `json:"is_hyaline"`
	}

	wechatUserInfo struct {
		PhoneNumber     string `json:"phoneNumber"`
		PurePhoneNumber string `json:"purePhoneNumber"`
		CountryCode     string `json:"countryCode"`
	}
)

// New creates new client.
func New(appId, appSecret string) *Client {
	return &Client{
		AppId:     appId,
		AppSecret: appSecret,
	}
}

func (e WechatError) Error() string {
	return "Error Code #" + strconv.Itoa(e.Code) + ": " + e.Messsage
}

// GetAccessToken gets access token.
func (c Client) GetAccessToken(ctx context.Context) (*wechatAccessToken, error) {
	url := "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=" +
		c.AppId + "&secret=" + c.AppSecret
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var respError WechatError
	json.Unmarshal(b, &respError)
	if respError.Code != 0 {
		return nil, respError
	}
	var data wechatAccessToken
	err = json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

// CreateWXAQrcode generates new Wechat mini program QR code (given path) and
// returns the JPEG image. Please note that Wechat allows total of only 100,000
// QR codes created by this API for every account.
// https://developers.weixin.qq.com/miniprogram/dev/api-backend/open-api/qr-code/wxacode.createQRCode.html
func (c Client) CreateWXAQrcode(ctx context.Context, path string) ([]byte, error) {
	access, err := c.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	url := "https://api.weixin.qq.com/cgi-bin/wxaapp/createwxaqrcode?access_token=" + access.AccessToken
	b, err := json.Marshal(wechatCreateWXAQrcodeRequest{
		Path:  path,
		Width: 1280,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var respError WechatError
	json.Unmarshal(b, &respError)
	if respError.Code != 0 {
		return nil, respError
	}
	return b, nil
}

// GetWXACodeUnlimit generates new Wechat mini program QR code (given page and
// scene) and returns the PNG image. If page is empty, index page will be used.
// https://developers.weixin.qq.com/miniprogram/dev/api-backend/open-api/qr-code/wxacode.getUnlimited.html
func (c Client) GetWXACodeUnlimit(ctx context.Context, page, scene string) ([]byte, error) {
	access, err := c.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	url := "https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token=" + access.AccessToken
	b, err := json.Marshal(wechatGetWXACodeUnlimitRequest{
		Page:        page,
		Scene:       scene,
		Width:       1280,
		Transparent: true,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var respError WechatError
	json.Unmarshal(b, &respError)
	if respError.Code != 0 {
		return nil, respError
	}
	return b, nil
}

// JsCodeToSession gets user's OpenId, UnionId and session key by the code from
// wx.login().
func (c Client) JsCodeToSession(ctx context.Context, code string) (*wechatSession, error) {
	url := "https://api.weixin.qq.com/sns/jscode2session?grant_type=authorization_code&js_code=" + code +
		"&appid=" + c.AppId + "&secret=" + c.AppSecret
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var respError WechatError
	json.Unmarshal(b, &respError)
	if respError.Code != 0 {
		return nil, respError
	}
	var data wechatSession
	err = json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

// Decrypt decrypts encrypted data given session key and IV.
func Decrypt(sessionKey, encryptedData, iv string) (*wechatUserInfo, error) {
	// from github.com/silenceper/wechat
	aesKey, err := base64.StdEncoding.DecodeString(sessionKey)
	if err != nil {
		return nil, err
	}
	cipherText, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	ivBytes, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}
	if len(ivBytes) != aes.BlockSize {
		return nil, fmt.Errorf("bad iv length %d", len(ivBytes))
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, ivBytes)
	mode.CryptBlocks(cipherText, cipherText)
	cipherText, err = pkcs7Unpad(cipherText, block.BlockSize())
	if err != nil {
		return nil, err
	}
	var userInfo wechatUserInfo
	err = json.Unmarshal(cipherText, &userInfo)
	if err != nil {
		return nil, err
	}
	return &userInfo, nil
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	// from github.com/silenceper/wechat
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}
	if len(data)%blockSize != 0 || len(data) == 0 {
		return nil, errors.New("invalid PKCS7 data")
	}
	c := data[len(data)-1]
	n := int(c)
	if n == 0 || n > len(data) {
		return nil, errors.New("invalid padding on input")
	}
	for i := 0; i < n; i++ {
		if data[len(data)-n+i] != c {
			return nil, errors.New("invalid padding on input")
		}
	}
	return data[:len(data)-n], nil
}
