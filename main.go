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
	"os"
	"strings"
	"sync"
	"time"
)

type DeepLReq struct {
	Text       []string `json:"text"`
	TargetLang string   `json:"target_lang"`
}

type DeepLResp struct {
	Translations []struct {
		DetectedSourceLang string `json:"detected_source_lang"`
		Text               string `json:"text"`
	} `json:"translations"`
	Message string `json:"message"`
}

type DeepLXReq struct {
	Text       string `json:"text"`
	SourceLang string `json:"source_lang"`
	TargetLang string `json:"target_lang"`
}

type DeepLXResp struct {
	Code         int      `json:"code"`
	ID           int      `json:"ID"`
	Data         string   `json:"data"`
	Alternatives []string `json:"alternatives"`
}

func (dlxReq DeepLXReq) post(u string) (DeepLXResp, error) {
	j, err := json.Marshal(dlxReq)
	if err != nil {
		return DeepLXResp{}, err
	}

	resp, err := http.Post(u, "application/json", bytes.NewReader(j))
	if err != nil {
		return DeepLXResp{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return DeepLXResp{}, errors.New(resp.Status)
	}

	dlxResp := DeepLXResp{}

	if err = json.NewDecoder(resp.Body).Decode(&dlxResp); err != nil {
		return DeepLXResp{}, err
	}

	return dlxResp, nil
}

func (dReq DeepLReq) post(key string) (DeepLResp, error) {
	j, err := json.Marshal(dReq)
	if err != nil {
		return DeepLResp{}, err
	}

	req, err := http.NewRequest("POST", "https://api-free.deepl.com/v2/translate", bytes.NewReader(j))
	if err != nil {
		return DeepLResp{}, err
	}
	req.Header.Set("Authorization", "DeepL-Auth-Key "+key)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return DeepLResp{}, err
	}
	defer resp.Body.Close()

	dResp := DeepLResp{}

	if err = json.NewDecoder(resp.Body).Decode(&dResp); err != nil {
		return DeepLResp{}, err
	}

	return dResp, nil
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
		isEmpty = false
		if strings.HasPrefix(scanner.Text(), "http") {
			urls = append(urls, scanner.Text())
		} else {
			keys = append(keys, scanner.Text())
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

func checkAlive(keyOrURL string) (bool, error) {
	if strings.HasPrefix(keyOrURL, "http") {

		dlxReq := DeepLXReq{
			Text:       "test",
			SourceLang: "en",
			TargetLang: "zh",
		}

		dlxResp, err := dlxReq.post(keyOrURL)

		if err != nil || dlxResp.Code != http.StatusOK {
			slog.Debug("url不可用", "url", keyOrURL, "message", err)
			return false, nil // 无需返回错误
		}

		return true, nil
	} else {
		dReq := DeepLReq{
			Text:       []string{"test"},
			TargetLang: "zh",
		}

		dResp, err := dReq.post(keyOrURL)
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

	}

	return true, nil
}

func handleForward(aliveKeys, aliveURLs []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(aliveKeys) == 0 && len(aliveURLs) == 0 {
			slog.Error("无可用key和url")
			http.Error(w, "无可用key和url", http.StatusInternalServerError)
			return
		}

		var use int // 0 = key, 1 = url

		if len(aliveKeys) > 0 && len(aliveURLs) > 0 {
			use = rand.IntN(2)
		} else if len(aliveKeys) == 0 {
			use = 1
		} else if len(aliveURLs) == 0 {
			use = 0
		}

		var (
			dlxReq  DeepLXReq
			dlxResp DeepLXResp
			err     error
		)

		var key, u string

		if err = json.NewDecoder(r.Body).Decode(&dlxReq); err != nil {
			slog.Warn("请求体无效")
			http.Error(w, "请求体无效", http.StatusBadRequest)
			return
		}

		if use == 0 {
			keyIndex := rand.IntN(len(aliveKeys))
			key = aliveKeys[keyIndex]

			dReq := DeepLReq{}
			dReq.Text = make([]string, 1)
			dReq.TargetLang = dlxReq.TargetLang
			dReq.Text[0] = dlxReq.Text

			dResp, err := dReq.post(key)
			if err != nil {
				slog.Warn("删除一个不可用的key", "key", key, "message", dResp.Message)
				http.Error(w, dResp.Message, http.StatusBadRequest)

				aliveKeys[keyIndex] = aliveKeys[len(aliveKeys)-1]
				aliveKeys = aliveURLs[:len(aliveKeys)-1]

				return
			}

			dlxResp.Alternatives = make([]string, 1)
			dlxResp.Code = http.StatusOK
			dlxResp.Data = dResp.Translations[0].Text
			dlxResp.Alternatives[0] = dResp.Translations[0].Text
		} else {
			urlIndex := rand.IntN(len(aliveURLs))
			u = aliveURLs[urlIndex]

			dlxResp, err = dlxReq.post(u)
			if err != nil || dlxResp.Code != http.StatusOK {
				slog.Warn("删除一个不可用的url", "url", u, "message", err.Error())
				http.Error(w, err.Error(), http.StatusBadRequest)

				aliveURLs[urlIndex] = aliveURLs[len(aliveURLs)-1]
				aliveURLs = aliveURLs[:len(aliveURLs)-1]

				return
			}
		}

		j, err := json.Marshal(dlxResp)
		if err != nil {
			slog.Error(err.Error())
			http.Error(w, "出错了", http.StatusInternalServerError)
			return
		}

		slog.Debug(dlxResp.Data, "key", key, "url", u)
		fmt.Fprintln(w, string(j))
	}
}

func runCheck(keys, urls []string) ([]string, []string) {
	var mu sync.Mutex
	var aliveKeys []string
	var aliveURLs []string
	var wg sync.WaitGroup

	for _, key := range keys {
		wg.Add(1)
		go func(k string) {
			defer wg.Done()
			isAlive, err := checkAlive(k)
			if err != nil {
				slog.Error(err.Error())
				return
			}

			if isAlive {
				mu.Lock()
				aliveKeys = append(aliveKeys, k)
				mu.Unlock()
			}
		}(key)
	}

	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			isAlive, err := checkAlive(u)
			if err != nil {
				slog.Error(err.Error())
				return
			}

			if isAlive {
				mu.Lock()
				aliveURLs = append(aliveURLs, u)
				mu.Unlock()
			}
		}(url)
	}

	wg.Wait()

	slog.Info(fmt.Sprintf("一共%d个key, 可用%d个key, 一共%d个url, 可用%d个url",
		len(keys), len(aliveKeys), len(urls), len(aliveURLs)))

	return aliveKeys, aliveURLs
}

func main() {
	slog.SetDefault(newLogger(parseArgs()))

	keys, urls, err := parseKeysAndURLs()
	if err != nil {
		panic(err)
	}

	aliveKeys, aliveURLs := runCheck(keys, urls)

	ticker := time.NewTicker(time.Hour * 2)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			aliveKeys, aliveURLs = runCheck(keys, urls)
		}
	}()

	http.HandleFunc("/", handleForward(aliveKeys, aliveURLs))

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

func parseArgs() (enableJSONOutput, enableDebug bool) {
	flag.BoolVar(&enableJSONOutput, "j", false, "输出JSON格式")
	flag.BoolVar(&enableDebug, "d", false, "输出调试信息")

	flag.Parse()

	return
}
