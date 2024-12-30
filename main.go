package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

	i := 0
	for scanner.Scan() {
		i++
		keys = append(keys, scanner.Text())
	}

	if i == 0 {
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
		return false, err
	}
	if dResp.Message != "" {
		return false, errors.New(dResp.Message + ", 别删可能是这个月用完了")
	}

	return true, nil
}

func handleForward(aliveKeys []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(aliveKeys) == 0 {
			fmt.Println("无可用key")
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
			http.Error(w, dlxReq.Text, http.StatusBadRequest)
			return
		}

		if dResp.Message == "Quota Exceeded" && dResp.Translations == nil {
			aliveKeys = append(aliveKeys[:randKeyIndex], aliveKeys[randKeyIndex+1:]...)
			fmt.Println("已删除一个失效的key")
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

		fmt.Println(string(j))
		fmt.Fprintln(w, string(j))
	}
}

func runCheck(keys []string) []string {
	var mu sync.Mutex
	var aliveKeys []string
	var wg sync.WaitGroup

	for _, key := range keys {
		wg.Add(1)
		go func(k string) {
			defer wg.Done()
			isAlive, err := checkAlive(k)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			}

			if isAlive {
				mu.Lock()
				aliveKeys = append(aliveKeys, k)
				mu.Unlock()
			} else {
				fmt.Println(k, "不可用")
			}
		}(key)
	}

	wg.Wait()
	fmt.Printf("一共%d个, 可用%d个\n", len(keys), len(aliveKeys))
	return aliveKeys
}

func main() {
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

	fmt.Println("服务运行在http://localhost:9000")
	err = http.ListenAndServe(":9000", nil)
	if err != nil {
		panic(err)
	}

}
