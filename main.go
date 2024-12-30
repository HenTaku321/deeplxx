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

func open() ([]string, error) {
	var keys []string
	file, err := os.Open("keys.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var isEmpty = true
	for scanner.Scan() {
		isEmpty = false
		keys = append(keys, scanner.Text())
	}

	if isEmpty {
		return nil, errors.New("keys.txt为空")
	}

	if scanner.Err() != nil {
		return nil, scanner.Err()
	}

	return keys, nil
}

func checkAlive(key string) (bool, error) {
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

	return true, nil
}

func handleForward(aliveKeys []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(aliveKeys) == 0 {
			slog.Error("无可用key")
			return
		}

		var (
			dlxReq  DeepLXReq
			dReq    DeepLReq
			dResp   DeepLResp
			dlxResp DeepLXResp
		)

		if err := json.NewDecoder(r.Body).Decode(&dlxReq); err != nil {
			http.Error(w, "请求体无效", http.StatusBadRequest)
			return
		}

		dReq.Text = make([]string, 1)
		dReq.TargetLang = dlxReq.TargetLang
		dReq.Text[0] = dlxReq.Text

		j, err := json.Marshal(dReq)
		if err != nil {
			http.Error(w, "出错了", http.StatusInternalServerError)
			return
		}

		req, err := http.NewRequest("POST", "https://api-free.deepl.com/v2/translate", bytes.NewReader(j))
		if err != nil {
			http.Error(w, "出错了", http.StatusInternalServerError)
			return
		}

		randKeyIndex := rand.IntN(len(aliveKeys) - 1)

		req.Header.Set("Authorization", "DeepL-Auth-Key "+aliveKeys[randKeyIndex])
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "出错了", http.StatusGatewayTimeout)
			return
		}
		defer resp.Body.Close()

		if err = json.NewDecoder(resp.Body).Decode(&dResp); err != nil {
			if err == io.EOF {
				slog.Debug("key已失效", "key", aliveKeys[randKeyIndex], "message", err)
				return
			}
			http.Error(w, dlxReq.Text, http.StatusBadRequest)
			return
		}

		if dResp.Message == "Quota Exceeded" && dResp.Translations == nil {
			aliveKeys = append(aliveKeys[:randKeyIndex], aliveKeys[randKeyIndex+1:]...)
			slog.Warn("已删除一个余额不足的key", "key", aliveKeys[randKeyIndex], "message", dResp.Message)
		} else if dResp.Translations == nil {
			aliveKeys = append(aliveKeys[:randKeyIndex], aliveKeys[randKeyIndex+1:]...)
			slog.Warn("已删除一个未知原因不可用的key", "key", aliveKeys[randKeyIndex], "message", dResp.Message)
		}

		if dResp.Translations != nil {
			dlxResp.Alternatives = make([]string, 1)
			dlxResp.Code = 200
			dlxResp.Data = dResp.Translations[0].Text
			dlxResp.Alternatives[0] = dResp.Translations[0].Text
		} else {
			http.Error(w, dResp.Message, http.StatusBadRequest)
			return
		}

		j, err = json.Marshal(dlxResp)
		if err != nil {
			http.Error(w, "出错了", http.StatusInternalServerError)
			return
		}

		slog.Debug(string(j))
		fmt.Fprintln(w, string(j))
	}
}

func runCheck(keys []string) []string {
	var aliveKeys []string
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

	wg.Wait()
	slog.Info(fmt.Sprintf("一共%d个, 可用%d个", len(keys), len(aliveKeys)))
	return aliveKeys
}

func main() {
	slog.SetDefault(newLogger(parseArgs()))

	keys, err := open()
	if err != nil {
		panic(err)
	}

	aliveKeys := runCheck(keys)

	ticker := time.NewTicker(time.Hour * 3)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			aliveKeys = runCheck(keys)
		}
	}()

	http.HandleFunc("/", handleForward(aliveKeys))

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
