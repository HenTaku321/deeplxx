package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type DeepLReq struct {
	Text        []string `json:"text"`
	TargetLang  string   `json:"target_lang"`
	TagHandling string   `json:"tag_handling"`
}

type DeepLResp struct {
	Translations []struct {
		DetectedSourceLang string `json:"detected_source_lang"`
		Text               string `json:"text"`
	} `json:"translations"`
	Message string `json:"message"`
}

type DeepLXReq struct {
	Text        string `json:"text"`
	SourceLang  string `json:"source_lang"`
	TargetLang  string `json:"target_lang"`
	TagHandling string `json:"tag_handling"`
}

type DeepLXResp struct {
	Code         int      `json:"code"`
	ID           int      `json:"ID"`
	Data         string   `json:"data"`
	Alternatives []string `json:"alternatives"`
}

type safeAliveKeysAndURLs struct {
	keys, urls []string
	mu         sync.RWMutex
}

func (dlxReq DeepLXReq) post(u string) (DeepLXResp, time.Duration, error) {
	j, err := json.Marshal(dlxReq)
	if err != nil {
		return DeepLXResp{}, 0, err
	}

	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(j))
	if err != nil {
		return DeepLXResp{}, 0, err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return DeepLXResp{}, 0, err
	}
	endTime := time.Since(startTime)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return DeepLXResp{}, 0, errors.New(resp.Status)
	}

	dlxResp := DeepLXResp{}

	if err = json.NewDecoder(resp.Body).Decode(&dlxResp); err != nil {
		return DeepLXResp{}, 0, err
	}

	return dlxResp, endTime, nil
}

func (dReq DeepLReq) post(key string) (DeepLResp, time.Duration, error) {
	j, err := json.Marshal(dReq)
	if err != nil {
		return DeepLResp{}, 0, err
	}

	var req *http.Request

	if strings.HasSuffix(key, ":fx") {
		req, err = http.NewRequest("POST", "https://api-free.deepl.com/v2/translate", bytes.NewReader(j))
		if err != nil {
			return DeepLResp{}, 0, err
		}
	} else {
		req, err = http.NewRequest("POST", "https://api.deepl.com/v2/translate", bytes.NewReader(j))
		if err != nil {
			return DeepLResp{}, 0, err
		}
	}

	req.Header.Set("Authorization", "DeepL-Auth-Key "+key)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return DeepLResp{}, 0, err
	}
	endTime := time.Since(startTime)
	defer resp.Body.Close()

	dResp := DeepLResp{}

	if err = json.NewDecoder(resp.Body).Decode(&dResp); err != nil {
		return DeepLResp{}, 0, err
	}

	return dResp, endTime, nil
}

func (saku *safeAliveKeysAndURLs) removeKeyOrURL(isKey bool, keyOrURL string) {
	var slice *[]string

	saku.mu.RLock()
	if isKey {
		slice = &saku.keys
	} else {
		slice = &saku.urls
	}
	saku.mu.RUnlock()

	for i, v := range *slice {
		if v == keyOrURL {
			saku.mu.Lock()
			(*slice)[i] = (*slice)[len(*slice)-1]
			*slice = (*slice)[:len(*slice)-1]
			saku.mu.Unlock()
			return
		}
	}
}

func parseKeysAndURLs() ([]string, []string, error) {
	var keys []string
	var urls []string

	file, err := os.Open("apis.txt")
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var isEmpty = true
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(text, "#") || strings.HasPrefix(text, "//") {
			continue
		}

		isEmpty = false

		if strings.HasPrefix(text, "http") {
			urls = append(urls, text)
		} else {
			keys = append(keys, text)
		}
	}

	if isEmpty {
		return nil, nil, errors.New("apis.txt为空")
	}

	if scanner.Err() != nil {
		return nil, nil, scanner.Err()
	}

	return keys, urls, nil
}

func checkAlive(isKey bool, keyOrURL string) (bool, error) {
	if isKey {
		dReq := DeepLReq{
			Text:       []string{"test"},
			TargetLang: "zh",
		}

		dResp, _, err := dReq.post(keyOrURL)
		if err != nil {
			if err == io.EOF {
				slog.Debug("key无效", "key", keyOrURL, "message", err)
			}
			return false, nil
		}

		if dResp.Message == "Quota Exceeded" && dResp.Translations == nil {
			slog.Debug("key余额不足", "key", keyOrURL, "message", dResp.Message)
			return false, nil
		} else if dResp.Translations == nil {
			slog.Debug("key未知原因不可用", "key", keyOrURL, "message", dResp.Message)
			return false, nil
		}
	} else {
		dlxReq := DeepLXReq{
			Text:       "test",
			SourceLang: "en",
			TargetLang: "zh",
		}

		dlxResp, _, err := dlxReq.post(keyOrURL)

		if err != nil {
			slog.Debug("url不可用", "url", keyOrURL, "message", err)
			return false, nil // 无需返回错误
		}

		if dlxResp.Code != http.StatusOK {
			slog.Debug("url不可用", "url", keyOrURL, "message", "http状态码不等于200")
			return false, nil
		}
	}

	return true, nil
}

var isChecking bool
var errIsChecking = errors.New("正在检测中")

func runCheck(saku *safeAliveKeysAndURLs) (int, int, error) {
	if isChecking {
		return 0, 0, errIsChecking
	}

	isChecking = true
	defer func() { isChecking = false }()

	var aliveKeys, aliveURLs []string

	keys, urls, err := parseKeysAndURLs()
	if err != nil {
		slog.Error(err.Error())
		return 0, 0, err
	}

	var wg sync.WaitGroup

	for _, key := range keys {
		wg.Add(1)
		go func(k string) {
			defer wg.Done()
			isAlive, err := checkAlive(true, k)
			if err != nil {
				slog.Error(err.Error())
				return
			}

			if isAlive {
				saku.mu.Lock()
				aliveKeys = append(aliveKeys, k)
				saku.mu.Unlock()
			}
		}(key)
	}

	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			isAlive, err := checkAlive(false, u)
			if err != nil {
				slog.Error(err.Error())
				return
			}

			if isAlive {
				saku.mu.Lock()
				aliveURLs = append(aliveURLs, u)
				saku.mu.Unlock()
			}
		}(url)
	}

	wg.Wait()

	saku.mu.Lock()
	saku.keys, saku.urls = aliveKeys, aliveURLs
	saku.mu.Unlock()

	slog.Info("可用数量检测", "总共key数量", len(keys), "可用key数量", len(saku.keys), "总共url数量", len(urls), "可用url数量", len(saku.urls))

	return len(keys), len(urls), nil
}

func containsChinese(text string) bool {
	re := regexp.MustCompile(`\p{Han}`)
	return re.MatchString(text)
}

var errGoogleTranslateFailed = errors.New("谷歌翻译失败")

func googleTranslate(sourceText, sourceLang, targetLang string) (string, time.Duration, error) {
	var text []string
	var result []interface{}

	u := "https://translate.googleapis.com/translate_a/single?client=gtx&sl=" +
		sourceLang + "&tl=" + targetLang + "&dt=t&q=" + url.QueryEscape(sourceText)

	startTime := time.Now()
	resp, err := http.Get(u)
	if err != nil {
		return "", 0, err
	}
	endTime := time.Since(startTime)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	bReq := strings.Contains(string(body), `<title>Error 400 (Bad Request)`)
	if bReq {
		return "", 0, errGoogleTranslateFailed
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", 0, errGoogleTranslateFailed
	}

	if len(result) > 0 {
		inner := result[0]
		for _, slice := range inner.([]interface{}) {
			for _, translatedText := range slice.([]interface{}) {
				text = append(text, fmt.Sprintf("%v", translatedText))
				break
			}
		}
		cText := strings.Join(text, "")

		return cText, endTime, nil
	} else {
		return "", 0, errGoogleTranslateFailed
	}
}

func handleForward(saku *safeAliveKeysAndURLs, enableCheckContainsChinese bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Error(err.Error())
			return
		}

	reTranslate:

		saku.mu.RLock()
		if len(saku.keys) == 0 && len(saku.urls) == 0 {
			saku.mu.RUnlock()

			slog.Debug("无可用key和url, 开始重新检测")

			_, _, err = runCheck(saku)
			if err != nil {
				if errors.Is(err, errIsChecking) {
					slog.Debug("已在检测中")
					http.Error(w, "无可用key和url", http.StatusInternalServerError)
					return
				}

				slog.Error(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			saku.mu.RLock()
			if len(saku.keys) == 0 && len(saku.urls) == 0 {
				saku.mu.RUnlock()
				slog.Error("无可用key和url")
				http.Error(w, "无可用key和url", http.StatusInternalServerError)
				return
			} else {
				saku.mu.RUnlock()
			}
		} else {
			saku.mu.RUnlock()
		}

		var use int // 0 = key, 1 = url

		saku.mu.RLock()
		if len(saku.keys) > 0 && len(saku.urls) > 0 {
			use = rand.IntN(2)
		} else if len(saku.keys) == 0 {
			use = 1
		} else if len(saku.urls) == 0 {
			use = 0
		}
		saku.mu.RUnlock()

		var (
			dlxReq   DeepLXReq
			dlxResp  DeepLXResp
			duration time.Duration
		)

		var key, u string

		if err = json.NewDecoder(bytes.NewReader(reqBody)).Decode(&dlxReq); err != nil {
			slog.Warn("请求体无效")
			http.Error(w, "请求体无效", http.StatusBadRequest)
			return
		}

		if use == 0 {
			saku.mu.RLock()
			keyIndex := rand.IntN(len(saku.keys))
			key = (saku.keys)[keyIndex]
			saku.mu.RUnlock()

			dReq := DeepLReq{}
			dReq.Text = make([]string, 1)
			dReq.TargetLang = dlxReq.TargetLang
			dReq.Text[0] = dlxReq.Text

			var dResp DeepLResp

			dResp, duration, err = dReq.post(key)
			if err != nil {
				if dResp.Message == "" {
					slog.Warn("删除一个不可用的key, 并重新翻译", "key", key, "message", err.Error(), "text", dlxReq.Text)
				} else {
					slog.Warn("删除一个不可用的key, 并重新翻译", "key", key, "message", dResp.Message, "text", dlxReq.Text)
				}

				saku.removeKeyOrURL(true, key)

				goto reTranslate
			}

			dlxResp.Alternatives = make([]string, 1)
			dlxResp.Code = http.StatusOK
			dlxResp.Data = dResp.Translations[0].Text
			dlxResp.Alternatives[0] = dResp.Translations[0].Text
		} else {
			saku.mu.RLock()
			urlIndex := rand.IntN(len(saku.urls))
			u = saku.urls[urlIndex]
			saku.mu.RUnlock()

			dlxResp, duration, err = dlxReq.post(u)
			if err != nil || dlxResp.Code != http.StatusOK {
				if err != nil {
					slog.Warn("删除一个不可用的url, 并重新翻译", "url", u, "message", err.Error(), "text", dlxReq.Text)
				} else {
					slog.Warn("删除一个不可用的url, 并重新翻译", "url", u, "message", "http状态码不等于200", "text", dlxReq.Text)
				}

				saku.removeKeyOrURL(false, u)

				goto reTranslate
			}
		}

		var usedGoogleTranslate bool

		if enableCheckContainsChinese {
			if !containsChinese(dlxResp.Data) {
				slog.Debug("检测到漏译, 尝试使用谷歌翻译", "text", dlxResp.Data)

				var googleTranslateText string

				googleTranslateText, duration, err = googleTranslate(dlxReq.Text, dlxReq.SourceLang, dlxReq.TargetLang)
				if err != nil {
					slog.Warn("谷歌翻译失败", "message", err.Error())
				} else {
					dlxResp.Data = googleTranslateText
					usedGoogleTranslate = true
				}
			}
		}

		j, err := json.Marshal(dlxResp)
		if err != nil {
			slog.Error(err.Error())
			http.Error(w, "出错了", http.StatusInternalServerError)
			return
		}

		if enableCheckContainsChinese {
			slog.Debug(dlxResp.Data, "key", key, "url", u, "usedGoogleTranslate", usedGoogleTranslate, "latency", duration)
		} else {
			slog.Debug(dlxResp.Data, "key", key, "url", u, "usedGoogleTranslate", false, "latency", duration)
		}

		fmt.Fprintln(w, string(j))
	}
}

func handleCheckAlive(saku *safeAliveKeysAndURLs) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Debug(r.RemoteAddr + "请求了该端点")

		totalKeys, totalURLs, err := runCheck(saku)
		if err != nil {
			if errors.Is(err, errIsChecking) {
				slog.Warn("已在检测中")
				http.Error(w, "已在检测中, 请稍后重试", http.StatusServiceUnavailable)
				return
			}

			slog.Warn(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = w.Write([]byte(fmt.Sprintf("可用数量检测, 总共key数量:%d, 可用key数量:%d, 总共url数量:%d, 可用url数量:%d\n",
			totalKeys, len(saku.keys), totalURLs, len(saku.urls))))
		if err != nil {
			slog.Warn(err.Error())
			return
		}
	}
}

func main() {
	enableJSONOutput, enableDebug, enableCheckContainsChinese := parseArgs()
	slog.SetDefault(newLogger(enableJSONOutput, enableDebug))

	saku := &safeAliveKeysAndURLs{}

	_, _, err := runCheck(saku)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			_, _, err = runCheck(saku)
			if err != nil {
				if errors.Is(err, errIsChecking) {
					slog.Warn("已在检测中")
					continue
				}
				slog.Error(err.Error())
			}
		}
	}()

	http.HandleFunc("/", handleForward(saku, enableCheckContainsChinese))
	http.HandleFunc("/check-alive", handleCheckAlive(saku))

	slog.Info("服务运行在http://localhost:9000")
	err = http.ListenAndServe(":9000", nil)
	if err != nil {
		panic(err)
	}
}

func newLogger(enableJSON, enableDebug bool) *slog.Logger {
	var handler slog.Handler

	handlerOptions := &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().Format(time.DateTime))
			}
			return a
		},
	}

	if enableDebug {
		handlerOptions.Level = slog.LevelDebug
	}

	if enableJSON {
		handler = slog.NewJSONHandler(os.Stdout, handlerOptions)
	} else {
		handler = slog.NewTextHandler(os.Stdout, handlerOptions)
	}

	return slog.New(handler)
}

func parseArgs() (enableJSONOutput, enableDebug, enableCheckContainsChinese bool) {
	flag.BoolVar(&enableJSONOutput, "j", false, "输出JSON格式")
	flag.BoolVar(&enableDebug, "d", false, "输出调试信息")
	flag.BoolVar(&enableCheckContainsChinese, "c", false, "检测是否漏译, 目标语言非中文请勿启用")

	flag.Parse()

	return
}
