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
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

type (
	Client struct {
		AppId     string
		AppSecret string
		Debug     bool

		accessToken *wechatAccessToken
		mutex       sync.RWMutex
	}

	Request struct {
		*http.Request
		client *Client
	}

	WechatError struct {
		Code     int    `json:"errcode"`
		Messsage string `json:"errmsg"`
	}

	wechatAccessToken struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`

		createdAt time.Time
	}

	WechatSession struct {
		OpenId     string `json:"openid"`
		SessionKey string `json:"session_key"`
		UnionId    string `json:"unionid"`
	}

	WechatUserInfo struct {
		PhoneNumber     string `json:"phoneNumber"`
		PurePhoneNumber string `json:"purePhoneNumber"`
		CountryCode     string `json:"countryCode"`
	}

	ReqBodyAnalysisGetDailyVisitTrend struct {
		BeginDate string `json:"begin_date"`
		EndDate   string `json:"end_date"`
	}
	ReqBodyAnalysisGetWeeklyVisitTrend  = ReqBodyAnalysisGetDailyVisitTrend
	ReqBodyAnalysisGetMonthlyVisitTrend = ReqBodyAnalysisGetDailyVisitTrend

	ReqBodyCreateWXAQrcode struct {
		Path  string `json:"path"`
		Width int    `json:"width"`
	}

	ReqBodyGetWXACodeUnlimit struct {
		Page        string `json:"page"`
		Scene       string `json:"scene"`
		Width       int    `json:"width"`
		Transparent bool   `json:"is_hyaline"`
	}
)

const (
	UrlApi                          = "https://api.weixin.qq.com"
	UrlAnalysisGetDailyVisitTrend   = UrlApi + "/datacube/getweanalysisappiddailyvisittrend?access_token={ACCESS_TOKEN}"
	UrlAnalysisGetWeeklyVisitTrend  = UrlApi + "/datacube/getweanalysisappidweeklyvisittrend?access_token={ACCESS_TOKEN}"
	UrlAnalysisGetMonthlyVisitTrend = UrlApi + "/datacube/getweanalysisappidmonthlyvisittrend?access_token={ACCESS_TOKEN}"
	UrlCreateWXAQrcode              = UrlApi + "/cgi-bin/wxaapp/createwxaqrcode?access_token={ACCESS_TOKEN}"
	UrlGetWXACodeUnlimit            = UrlApi + "/wxa/getwxacodeunlimit?access_token={ACCESS_TOKEN}"
)

// New creates new client.
func New(appId, appSecret string) *Client {
	return &Client{
		AppId:     appId,
		AppSecret: appSecret,
	}
}

// AccessToken returns current access token.
func (c *Client) AccessToken() *wechatAccessToken {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.accessToken
}

// MustNewRequest is like NewRequest but panics if operation fails.
func (c *Client) MustNewRequest(ctx context.Context, method, url string, reqBody interface{}) *Request {
	req, err := c.NewRequest(ctx, "POST", url, reqBody)
	if err != nil {
		panic(err)
	}
	return req
}

// NewRequest create a new request given context, method, url and request body.
// {ACCESS_TOKEN} in the URL will be replaced with the current access token.
// Request body can be io.Reader or data structures that can be JSON-marshaled.
func (c *Client) NewRequest(ctx context.Context, method, url string, reqBody interface{}) (*Request, error) {
	if strings.Contains(url, "{ACCESS_TOKEN}") {
		access, err := c.GetAccessToken(ctx)
		if err != nil {
			return nil, err
		}
		url = strings.Replace(url, "{ACCESS_TOKEN}", access.AccessToken, -1)
	}
	r, err := reqBodyToReader(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return &Request{req, c}, nil
}

// MustDo is like Do but panics if operation fails.
func (req *Request) MustDo(dest ...interface{}) {
	if err := req.Do(dest...); err != nil {
		panic(err)
	}
}

// Do sends the HTTP request and receives the response, unmarshals JSON
// response into the optional dest. Specify JSON path after each dest to
// efficiently get required info from deep nested structs. Original body is
// returned if dest is *[]byte.
func (req *Request) Do(dest ...interface{}) error {
	if req.client.Debug {
		dump, err := httputil.DumpRequestOut(req.Request, true)
		if err != nil {
			return err
		}
		log.Println(string(dump))
	}
	res, err := http.DefaultClient.Do(req.Request)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if req.client.Debug {
		dumpBody := strings.Contains(res.Header.Get("Content-Type"), "json")
		dump, err := httputil.DumpResponse(res, dumpBody)
		if err != nil {
			return err
		}
		log.Println(string(dump))
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	var respError WechatError
	json.Unmarshal(b, &respError)
	if respError.Code != 0 {
		return respError
	}
	if len(dest) == 0 {
		return nil
	}
	if len(dest) > 1 {
		for n := 0; n < len(dest)/2; n++ {
			arrange(b, dest[2*n], dest[2*n+1].(string))
		}
		return nil
	}
	if x, ok := dest[0].(*[]byte); ok {
		*x = b
		return nil
	}
	return json.Unmarshal(b, dest[0])
}

// GetAccessToken gets access token and caches it to client.AccessToken.
func (c *Client) GetAccessToken(ctx context.Context) (*wechatAccessToken, error) {
	t := c.AccessToken()
	if t != nil && !t.Expired() {
		return t, nil
	}
	url := UrlApi + "/cgi-bin/token?grant_type=client_credential&appid=" +
		c.AppId + "&secret=" + c.AppSecret
	req, err := c.NewRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	data := wechatAccessToken{
		createdAt: time.Now(),
	}
	err = req.Do(&data)
	if err != nil {
		return nil, err
	}
	c.mutex.Lock()
	c.accessToken = &data
	c.mutex.Unlock()
	return &data, nil
}

// CreateWXAQrcode generates new Wechat mini program QR code (given path) and
// returns the JPEG image. Please note that Wechat allows total of only 100,000
// QR codes created by this API for every account.
// https://developers.weixin.qq.com/miniprogram/dev/api-backend/open-api/qr-code/wxacode.createQRCode.html
func (c *Client) CreateWXAQrcode(ctx context.Context, path string) ([]byte, error) {
	req, err := c.NewRequest(ctx, "POST", UrlCreateWXAQrcode, ReqBodyCreateWXAQrcode{
		Path:  path,
		Width: 1280,
	})
	if err != nil {
		return nil, err
	}
	var b []byte
	err = req.Do(&b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GetWXACodeUnlimit generates new Wechat mini program QR code (given page and
// scene) and returns the PNG image. If page is empty, index page will be used.
// https://developers.weixin.qq.com/miniprogram/dev/api-backend/open-api/qr-code/wxacode.getUnlimited.html
func (c *Client) GetWXACodeUnlimit(ctx context.Context, page, scene string) ([]byte, error) {
	req, err := c.NewRequest(ctx, "POST", UrlGetWXACodeUnlimit, ReqBodyGetWXACodeUnlimit{
		Page:        page,
		Scene:       scene,
		Width:       1280,
		Transparent: true,
	})
	if err != nil {
		return nil, err
	}
	var b []byte
	err = req.Do(&b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// JsCodeToSession gets user's OpenId, UnionId and session key by the code from
// wx.login().
func (c *Client) JsCodeToSession(ctx context.Context, code string) (*WechatSession, error) {
	url := UrlApi + "/sns/jscode2session?grant_type=authorization_code&js_code=" + code +
		"&appid=" + c.AppId + "&secret=" + c.AppSecret
	req, err := c.NewRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	var data WechatSession
	err = req.Do(&data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func (e WechatError) Error() string {
	return "Error Code #" + strconv.Itoa(e.Code) + ": " + e.Messsage
}

func (t wechatAccessToken) Expired() bool {
	return t.createdAt.Add(time.Duration(t.ExpiresIn-30) * time.Second).Before(time.Now())
}

// Decrypt decrypts encrypted data given session key and IV.
func Decrypt(sessionKey, encryptedData, iv string) (*WechatUserInfo, error) {
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
	var userInfo WechatUserInfo
	err = json.Unmarshal(cipherText, &userInfo)
	if err != nil {
		return nil, err
	}
	return &userInfo, nil
}

func reqBodyToReader(reqBody interface{}) (io.Reader, error) {
	if reqBody == nil {
		return nil, nil
	}
	if r, ok := reqBody.(io.Reader); ok {
		return r, nil
	}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

func arrange(data []byte, target interface{}, key string) {
	keys := strings.Split(key, ".")
	baseType := reflect.TypeOf(target).Elem()
	if baseType.Kind() == reflect.Slice {
		baseType = baseType.Elem()
	}
	typ := baseType
	for i := len(keys) - 1; i > -1; i-- {
		key := keys[i]
		if key == "*" {
			typ = reflect.SliceOf(typ)
		} else if key != "" {
			typ = reflect.MapOf(reflect.TypeOf(key), typ)
		}
	}
	d := reflect.New(typ)
	json.Unmarshal(data, d.Interface())
	items := collect(d.Elem(), keys)
	v := reflect.Indirect(reflect.ValueOf(target))
	for n := range items {
		item := items[n]
		if !item.IsValid() {
			item = reflect.New(baseType).Elem()
		}
		if v.Kind() == reflect.Slice {
			v.Set(reflect.Append(v, item))
		} else {
			v.Set(item)
		}
	}
}

func collect(x reflect.Value, keys []string) (out []reflect.Value) {
	for i, key := range keys {
		if key == "*" {
			k := keys[i+1:]
			for i := 0; i < x.Len(); i++ {
				out = append(out, collect(x.Index(i), k)...)
			}
			return
		} else if key != "" {
			x = x.MapIndex(reflect.ValueOf(key))
		}
	}
	out = append(out, x)
	return
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
