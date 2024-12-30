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

func open() ([]string, []string, error) {
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
		u := keyOrURL

		dlxReq := DeepLXReq{
			Text:       "test",
			SourceLang: "en",
			TargetLang: "zh",
		}

		dlxResp := DeepLXResp{}

		j, err := json.Marshal(dlxReq)
		if err != nil {
			return false, err
		}

		resp, err := http.Post(u, "application/json", bytes.NewReader(j))
		if err != nil {
			return false, nil // 无需返回错误信息
		}
		defer resp.Body.Close()

		if err = json.NewDecoder(resp.Body).Decode(&dlxResp); err != nil {
			return false, err
		}

		return true, nil
	} else {
		key := keyOrURL

		dReq := DeepLReq{
			Text:       []string{"test"},
			TargetLang: "zh",
		}

		dResp := DeepLResp{}

		j, err := json.Marshal(dReq)
		if err != nil {
			return false, err
		}

		req, err := http.NewRequest("POST", "https://api-free.deepl.com/v2/translate", bytes.NewReader(j))
		if err != nil {
			return false, err
		}
		req.Header.Set("Authorization", "DeepL-Auth-Key "+key)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()

		if err = json.NewDecoder(resp.Body).Decode(&dResp); err != nil {
			if err == io.EOF {
				slog.Debug("key已失效", "key", key, "message", err)
				return false, nil
			}
			return false, err
		}

		if dResp.Message == "Quota Exceeded" && dResp.Translations == nil {
			slog.Debug("key余额不足", "key", key, "message", dResp.Message)
			return false, nil
		} else if dResp.Translations == nil {
			slog.Debug("key未知原因不可用", "key", key, "message", dResp.Message)
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
			dReq    DeepLReq
			dResp   DeepLResp
			dlxResp DeepLXResp
		)

		var key, u string

		if err := json.NewDecoder(r.Body).Decode(&dlxReq); err != nil {
			slog.Warn("请求体无效")
			http.Error(w, "请求体无效", http.StatusBadRequest)
			return
		}

		if use == 0 {
			dReq.Text = make([]string, 1)
			dReq.TargetLang = dlxReq.TargetLang
			dReq.Text[0] = dlxReq.Text

			j, err := json.Marshal(dReq)
			if err != nil {
				slog.Error(err.Error())
				http.Error(w, "出错了", http.StatusInternalServerError)
				return
			}

			req, err := http.NewRequest("POST", "https://api-free.deepl.com/v2/translate", bytes.NewReader(j))
			if err != nil {
				slog.Error(err.Error())
				http.Error(w, "出错了", http.StatusInternalServerError)
				return
			}

			var randKeyIndex int

			if len(aliveKeys) == 1 {
				randKeyIndex = 0
			} else {
				randKeyIndex = rand.IntN(len(aliveKeys) - 1)
			}

			key = aliveKeys[randKeyIndex]

			req.Header.Set("Authorization", "DeepL-Auth-Key "+key)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				slog.Error(err.Error())
				http.Error(w, "出错了", http.StatusGatewayTimeout)
				return
			}
			defer resp.Body.Close()

			if err = json.NewDecoder(resp.Body).Decode(&dResp); err != nil {
				if err == io.EOF {
					slog.Debug("key已失效", "key", key, "message", err)
					return
				}
				http.Error(w, dlxReq.Text, http.StatusBadRequest)
				return
			}

			if dResp.Message == "Quota Exceeded" && dResp.Translations == nil {
				aliveKeys = append(aliveKeys[:randKeyIndex], aliveKeys[randKeyIndex+1:]...)
				slog.Warn("已删除一个余额不足的key", "key", key, "message", dResp.Message)
				return
			} else if dResp.Translations == nil {
				aliveKeys = append(aliveKeys[:randKeyIndex], aliveKeys[randKeyIndex+1:]...)
				slog.Warn("已删除一个未知原因不可用的key", "key", key, "message", dResp.Message)
				return
			}

			if dResp.Translations != nil {
				dlxResp.Alternatives = make([]string, 1)
				dlxResp.Code = 200
				dlxResp.Data = dResp.Translations[0].Text
				dlxResp.Alternatives[0] = dResp.Translations[0].Text
			} else {
				slog.Error("转发失败", "message", dResp.Message)
				http.Error(w, dResp.Message, http.StatusBadRequest)
				return
			}
		} else {
			j, err := json.Marshal(dlxReq)
			if err != nil {
				slog.Error(err.Error())
				http.Error(w, "出错了", http.StatusInternalServerError)
				return
			}

			var randURLIndex int

			if len(aliveURLs) == 1 {
				randURLIndex = 0
			} else {
				randURLIndex = rand.IntN(len(aliveURLs) - 1)
			}

			u = aliveURLs[randURLIndex]

			resp, err := http.Post(u, "application/json", bytes.NewReader(j))
			if err != nil {
				slog.Error(err.Error())
				http.Error(w, "出错了", http.StatusGatewayTimeout)
				return
			}
			defer resp.Body.Close()

			if err = json.NewDecoder(resp.Body).Decode(&dlxResp); err != nil {
				slog.Error(err.Error())
				http.Error(w, "出错了", http.StatusInternalServerError)
				return
			}

			if dlxResp.Code != 200 {
				aliveURLs = append(aliveURLs[:randURLIndex], aliveURLs[randURLIndex+1:]...)
				slog.Warn("已删除一个未知原因不可用的url", "url", aliveKeys[randURLIndex], "code", dlxResp.Code)
				return
			}
		}

		j, err := json.Marshal(dlxResp)
		if err != nil {
			slog.Error(err.Error())
			http.Error(w, "出错了", http.StatusInternalServerError)
			return
		}

		slog.Debug(string(j), "key", key, "url", u)
		fmt.Fprintln(w, string(j))
	}
}

func runCheck(keys, urls []string) ([]string, []string) {
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
			}

			if isAlive {
				aliveKeys = append(aliveKeys, k)
			} else {
				slog.Warn("key不可用", "key", k)
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
			}

			if isAlive {
				aliveURLs = append(aliveURLs, u)
			} else {
				slog.Warn("url不可用", "url", u)
			}
		}(url)
	}

	wg.Wait()
	slog.Info(fmt.Sprintf("一共%d个key, 可用%d个key, 一共%d个url, 可用%d个url", len(keys), len(aliveKeys), len(urls), len(aliveURLs)))

	return aliveKeys, aliveURLs
}

func main() {
	slog.SetDefault(newLogger(parseArgs()))

	keys, urls, err := open()
	if err != nil {
		panic(err)
	}

	aliveKeys, aliveURLs := runCheck(keys, urls)

	ticker := time.NewTicker(time.Hour * 3)
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
