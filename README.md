# wechatslim

Simple, slim wechat client.

[Docs](https://pkg.go.dev/github.com/caiguanhao/wechatslim)

[Wechat Mini Program Docs](https://developers.weixin.qq.com/miniprogram/dev/api-backend/open-api/data-analysis/visit-trend/analysis.getDailyVisitTrend.html)

```go
import "github.com/caiguanhao/wechatslim"

var data struct {
	Date                         string  `json:"ref_date"`
	SessionsCount                int     `json:"session_cnt"`
	PageViews                    int     `json:"visit_pv"`
	UniqueVisitors               int     `json:"visit_uv"`
	NewUniqueVisitors            int     `json:"visit_uv_new"`
	SecondsOnAppPerSession       float64 `json:"stay_time_session"`
	SecondsOnAppPerUniqueVisitor float64 `json:"stay_time_uv"`
	AveragePageDepth             float64 `json:"visit_depth"`
}

ctx := context.Background()
date := time.Now().AddDate(0, 0, -1).Format("20060102")
wechat := wechatslim.New("wx0000000000000000", "00000000000000000000000000000000")
wechat.Debug = true // show request and response body
wechat.MustNewRequest(ctx, "POST",
	wechatslim.UrlAnalysisGetDailyVisitTrend,
	wechatslim.ReqBodyAnalysisGetDailyVisitTrend{
		BeginDate: date,
		EndDate:   date,
	},
).MustDo(&data, "list.*")
fmt.Println(data)
```
