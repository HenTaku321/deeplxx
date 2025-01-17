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

var (
	errDeepLStatusNotOK                  = errors.New("")
	errDeepLQuotaExceeded                = errors.New("quota exceeded")
	errDeepLUnavailableForUnknownReasons = errors.New("unavailable for unknown reasons")
	errDeepLXStatusNotOK                 = errors.New("")
	errIsChecking                        = errors.New("currently checking")
)

type deepLReq struct {
	Text        []string `json:"text"`
	TargetLang  string   `json:"target_lang"`
	TagHandling string   `json:"tag_handling"`
}

type deepLResp struct {
	Translations []struct {
		DetectedSourceLang string `json:"detected_source_lang"`
		Text               string `json:"text"`
	} `json:"translations"`
	Message string `json:"message"`
}

type deepLXReq struct {
	Text        string `json:"text"`
	SourceLang  string `json:"source_lang"`
	TargetLang  string `json:"target_lang"`
	TagHandling string `json:"tag_handling"`
}

type deepLXResp struct {
	Code         int      `json:"code"`
	ID           int      `json:"id"`
	Data         string   `json:"data"`
	Alternatives []string `json:"alternatives"`
}

type safeAliveKeysAndURLs struct {
	keys, urls     []string
	mu             sync.RWMutex
	isCheckingBool bool
}

type posts struct {
	deepLReq
	deepLXReq
	*http.Client
}

func (p posts) deepL(key string) (deepLResp, error) {
	j, err := json.Marshal(p.deepLReq)
	if err != nil {
		return deepLResp{}, err
	}

	var req *http.Request

	if strings.HasSuffix(key, ":fx") {
		req, err = http.NewRequest("POST", "https://api-free.deepl.com/v2/translate", bytes.NewReader(j))
		if err != nil {
			return deepLResp{}, err
		}
	} else {
		req, err = http.NewRequest("POST", "https://api.deepl.com/v2/translate", bytes.NewReader(j))
		if err != nil {
			return deepLResp{}, err
		}
	}

	req.Header.Set("Authorization", "DeepL-Auth-Key "+key)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.Client.Do(req)
	if err != nil {
		return deepLResp{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return deepLResp{}, errors.Join(errDeepLStatusNotOK, errors.New(resp.Status))
	}

	lResp := deepLResp{}

	if err = json.NewDecoder(resp.Body).Decode(&lResp); err != nil {
		return deepLResp{}, err
	}

	if lResp.Translations == nil {
		if lResp.Message == "Quota Exceeded" {
			return deepLResp{}, errDeepLQuotaExceeded
		} else {
			return deepLResp{}, errDeepLUnavailableForUnknownReasons
		}
	}

	return lResp, nil
}

func (p posts) deepLX(u string) (deepLXResp, error) {
	j, err := json.Marshal(p.deepLXReq)
	if err != nil {
		return deepLXResp{}, err
	}

	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(j))
	if err != nil {
		return deepLXResp{}, err
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		return deepLXResp{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return deepLXResp{}, errors.Join(errDeepLXStatusNotOK, errors.New(resp.Status))
	}

	lxResp := deepLXResp{}

	if err = json.NewDecoder(resp.Body).Decode(&lxResp); err != nil {
		return deepLXResp{}, err
	}

	if lxResp.Code != http.StatusOK {
		return deepLXResp{}, errors.Join(errDeepLXStatusNotOK, errors.New(resp.Status))
	}

	return lxResp, nil
}

func (p posts) checkAlive(isKey bool, keyOrURL string) (bool, error) {
	if isKey {
		lResp, err := p.deepL(keyOrURL)
		if err != nil {
			if errors.Is(err, io.EOF) {
				slog.Debug("deepl key is invalid", "key", keyOrURL, "error message", err.Error())
				return false, nil
			}
			if errors.Is(err, errDeepLStatusNotOK) {
				slog.Debug("deepl key status not ok", "key", keyOrURL, "error message", strings.TrimPrefix(err.Error(), "\n"))
				return false, nil
			}
			if errors.Is(err, errDeepLQuotaExceeded) {
				slog.Debug("deepl key has quota exceeded", "key", keyOrURL, "error message", err.Error())
				return false, nil
			}
			if errors.Is(err, errDeepLUnavailableForUnknownReasons) {
				slog.Debug("deepl key is unavailable for unknown reason", "key", keyOrURL, "error message", lResp.Message)
				return false, nil
			}
			return false, err
		}
	} else {
		_, err := p.deepLX(keyOrURL)
		if err != nil {
			if errors.Is(err, errDeepLXStatusNotOK) {
				slog.Debug("deeplx url is unavailable", "url", keyOrURL, "error message", strings.TrimPrefix(err.Error(), "\n"))
				return false, nil
			}
			return false, err
		}
	}

	return true, nil
}

func (saku *safeAliveKeysAndURLs) removeKeyOrURL(isKey bool, keyOrURL string) bool {
	var slice *[]string
	indexToRemove := -1

	saku.mu.RLock()
	if isKey {
		slice = &saku.keys
	} else {
		slice = &saku.urls
	}
	for i, v := range *slice {
		if v == keyOrURL {
			indexToRemove = i
			break
		}
	}
	saku.mu.RUnlock()

	if indexToRemove == -1 {
		return false
	}

	saku.mu.Lock()
	(*slice)[indexToRemove] = (*slice)[len(*slice)-1]
	*slice = (*slice)[:len(*slice)-1]
	saku.mu.Unlock()

	return true
}

func (saku *safeAliveKeysAndURLs) isChecking() bool {
	saku.mu.RLock()
	defer saku.mu.RUnlock()
	if saku.isCheckingBool {
		return true
	}
	return false
}

func (saku *safeAliveKeysAndURLs) setIsChecking(b bool) {
	saku.mu.Lock()
	defer saku.mu.Unlock()
	saku.isCheckingBool = b
}

func (saku *safeAliveKeysAndURLs) runCheck() (int, int, error) {
	if saku.isChecking() {
		return 0, 0, errIsChecking
	}

	saku.setIsChecking(true)
	defer func() { saku.setIsChecking(false) }()

	p := posts{
		deepLReq: deepLReq{
			Text:       []string{"Hi"},
			TargetLang: "zh",
		},
		deepLXReq: deepLXReq{
			Text:       "Hi",
			SourceLang: "en",
			TargetLang: "zh",
		},
		Client: &http.Client{Timeout: 5 * time.Second},
	}

	var aliveKeys, aliveURLs []string

	keys, urls, err := parseKeysAndURLs()
	if err != nil {
		return 0, 0, err
	}

	var wg sync.WaitGroup
	var mu = &sync.Mutex{}

	for _, key := range keys {
		wg.Add(1)
		go func(k string) {
			defer wg.Done()
			isAlive, err := p.checkAlive(true, k)
			if err != nil {
				slog.Error("error running check available", "key", k, "error message", err.Error())
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
			isAlive, err := p.checkAlive(false, u)
			if err != nil {
				slog.Error("error available check", "url", u, "error message", err.Error())
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

	saku.keys, saku.urls = aliveKeys, aliveURLs

	saku.mu.RLock()
	slog.Info("available check", "all keys count", len(keys), "available keys count", len(saku.keys), "all urls count", len(urls), "available urls count", len(saku.urls))
	saku.mu.RUnlock()

	return len(keys), len(urls), nil
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
		return nil, nil, errors.New("apis.txt is empty")
	}

	if scanner.Err() != nil {
		return nil, nil, scanner.Err()
	}

	return keys, urls, nil
}

func googleTranslate(sourceText, sourceLang, targetLang string) (string, error) {
	var text []string
	var result []interface{}

	u := "https://translate.googleapis.com/translate_a/single?client=gtx&sl=" +
		sourceLang + "&tl=" + targetLang + "&dt=t&q=" + url.QueryEscape(sourceText)

	resp, err := http.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	bReq := strings.Contains(string(body), `<title>Error 400 (Bad Request)`)
	if resp.StatusCode == http.StatusBadRequest || bReq {
		return "", errors.New("400 Bad Request")
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", err
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

		return cText, nil
	} else {
		return "", err
	}
}

func (saku *safeAliveKeysAndURLs) handleTranslate(retargetLanguageName *regexp.Regexp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Error("error reading request", "error message", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var forceUseDeepL bool

	reTranslate:

		saku.mu.RLock()
		if len(saku.keys) == 0 && len(saku.urls) == 0 {
			saku.mu.RUnlock()

			slog.Debug("no available keys and urls, start rechecking")

			_, _, err = saku.runCheck()
			if err != nil {
				if errors.Is(err, errIsChecking) {
					slog.Debug("currently rechecking")
					http.Error(w, "no available keys or urls, currently rechecking", http.StatusInternalServerError)
					return
				}

				slog.Error("error running check available", "error message", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			saku.mu.RLock()
			if len(saku.keys) == 0 && len(saku.urls) == 0 {
				saku.mu.RUnlock()
				slog.Error("no available keys and urls")
				http.Error(w, "no available keys and urls", http.StatusInternalServerError)
				return
			}
			saku.mu.RUnlock()
		} else {
			saku.mu.RUnlock()
		}

		var use int // 0 = key, 1 = url, 2 = accidentally no key when force use deepL translations

		if !forceUseDeepL {
			saku.mu.RLock()
			if len(saku.keys) > 0 && len(saku.urls) > 0 {
				use = rand.IntN(2)
			} else if len(saku.keys) == 0 {
				use = 1
			} // else if len(saku.urls) == 0 {
			//	use = 0
			//}
			saku.mu.RUnlock()
		}

		var (
			lxReq  deepLXReq
			lxResp deepLXResp

			key, u string
		)

		if err = json.NewDecoder(bytes.NewReader(reqBody)).Decode(&lxReq); err != nil || lxReq.Text == "" {
			slog.Warn("invalid request body")
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		saku.mu.RLock()
		if len(saku.keys) == 0 && forceUseDeepL == true {
			use = 2
		}
		saku.mu.RUnlock()

		if use == 0 {
			saku.mu.RLock()
			keyIndex := rand.IntN(len(saku.keys))
			key = (saku.keys)[keyIndex]
			saku.mu.RUnlock()

			lReq := deepLReq{}
			lReq.Text = make([]string, 1)
			lReq.TargetLang = lxReq.TargetLang
			lReq.Text[0] = lxReq.Text

			p := posts{
				deepLReq: lReq,
				Client:   &http.Client{},
			}

			lResp, err := p.deepL(key)
			if err != nil {
				if saku.removeKeyOrURL(true, key) {
					slog.Warn("remove an unavailable key and retranslate", "key", key, "error message", lResp.Message, "text", lxReq.Text, "latency", time.Since(startTime))
				}
				goto reTranslate
			}

			if len(lResp.Translations) == 0 {
				slog.Warn("deepl translate failed, retranslate", "error message", lResp.Message, "text", lxReq.Text, "latency", time.Since(startTime))
				goto reTranslate
			}

			lxResp.Alternatives = make([]string, 1)
			lxResp.Code = http.StatusOK
			lxResp.Data = lResp.Translations[0].Text
			lxResp.Alternatives[0] = lResp.Translations[0].Text
		} else if use == 1 {
			saku.mu.RLock()
			urlIndex := rand.IntN(len(saku.urls))
			u = saku.urls[urlIndex]
			saku.mu.RUnlock()

			p := posts{
				deepLXReq: lxReq,
				Client:    &http.Client{Timeout: 5 * time.Second},
			}

			lxResp, err = p.deepLX(u)
			if err != nil {
				if saku.removeKeyOrURL(false, u) {
					if err != nil {
						slog.Warn("remove an unavailable url and retranslate", "url", u, "error message", err.Error(), "text", lxReq.Text, "latency", time.Since(startTime))
					}
				}
				goto reTranslate
			}
		}

		var usedGoogleTranslate bool

		if retargetLanguageName != nil && use == 1 || use == 2 {
			if !retargetLanguageName.MatchString(lxResp.Data) {
				saku.mu.RLock()
				if use == 1 && len(saku.keys) > 0 {
					saku.mu.RUnlock()
					slog.Debug("detected deeplx missing translation, force use deepl translate", "text", lxResp.Data, "url", u, "latency", time.Since(startTime))
					forceUseDeepL = true
					goto reTranslate
				}
				saku.mu.RUnlock()

				slog.Debug("detected deepl is also missing translation, or has no available key, retranslate with google translate", "text", lxResp.Data, "key", key, "latency", time.Since(startTime))

				googleTranslateText, err := googleTranslate(lxReq.Text, lxReq.SourceLang, lxReq.TargetLang)
				if err != nil {
					slog.Warn("google translate failed, the result did not change", "error message", err.Error(), "latency", time.Since(startTime))
				} else {
					lxResp.Data = googleTranslateText
					usedGoogleTranslate = true
				}
			}
		}

		j, err := json.Marshal(lxResp)
		if err != nil {
			slog.Error("error marshalling json", "error message", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		slog.Debug("translation info", "text", lxResp.Data, "key", key, "url", u, "force used deepl", forceUseDeepL, "used google translate", usedGoogleTranslate, "latency", time.Since(startTime), "client", r.RemoteAddr)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, string(j))
	}
}

func (saku *safeAliveKeysAndURLs) handleCheckAlive() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Debug(r.RemoteAddr + " request of rechecking")

		totalKeys, totalURLs, err := saku.runCheck()
		if err != nil {
			if errors.Is(err, errIsChecking) {
				slog.Warn("currently rechecking")
				http.Error(w, "currently rechecking, try again later", http.StatusServiceUnavailable)
				return
			}

			slog.Error("error running check available","error message",err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		saku.mu.RLock()
		defer saku.mu.RUnlock()
		_, err = w.Write([]byte(fmt.Sprintf("all keys count:%d, available keys count:%d, all urls count:%d, available urls count:%d\n",
			totalKeys, len(saku.keys), totalURLs, len(saku.urls))))
		if err != nil {
			slog.Error("error writing response","error message",err.Error())
			return
		}
	}
}

var retargetLanguageName *regexp.Regexp

func main() {
	enableJSONOutput, enableDebug, targetLanguageName := parseArgs()
	slog.SetDefault(newLogger(enableJSONOutput, enableDebug))

	if targetLanguageName != "" {
		retargetLanguageName = regexp.MustCompile(fmt.Sprintf("\\p{%s}", targetLanguageName))
	} else {
		retargetLanguageName = nil
	}

	saku := &safeAliveKeysAndURLs{}

	_, _, err := saku.runCheck()
	if err != nil {
		slog.Error("error running check available","error message",err.Error())
		return
	}

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			_, _, err = saku.runCheck()
			if err != nil {
				if errors.Is(err, errIsChecking) {
					slog.Warn("currently rechecking")
					continue
				}
				slog.Error("error running check available","error message",err.Error())
			}
		}
	}()

	http.HandleFunc("/", saku.handleTranslate(retargetLanguageName))
	http.HandleFunc("/check-alive", saku.handleCheckAlive())

	slog.Info("server running on http://localhost:9000")
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

func parseArgs() (enableJSONOutput, enableDebug bool, targetLanguageName string) {
	flag.BoolVar(&enableJSONOutput, "j", false, "output JSON format")
	flag.BoolVar(&enableDebug, "d", false, "output debugging message")
	flag.StringVar(&targetLanguageName, "D", "", "(suggest enabling if you will use deeplx, because it will result in more missing translation)detect for missing translations of target language, check your target language name in https://fo.wikipedia.org/wiki/Fyrimynd:ISO_15924_script_codes_and_related_Unicode_data")

	flag.Parse()

	return
}
