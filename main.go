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
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	errDeepLQuotaExceeded                = errors.New("quota exceeded")
	errDeepLUnavailableForUnknownReasons = errors.New("unavailable for unknown reasons")
	errIsChecking                        = errors.New("currently checking")
)

type deepLReq struct {
	Text               []string `json:"text"`
	SourceLang         string   `json:"source_lang"`
	TargetLang         string   `json:"target_lang"`
	TagHandling        string   `json:"tag_handling"`
	Context            string   `json:"context"`
	ModelType          string   `json:"model_type"`
	SplitSentences     string   `json:"split_sentences"`
	PreserveFormatting bool     `json:"preserve_formatting"`
	Formality          string   `json:"formality"`
	GlossaryID         string   `json:"glossary_id"`
	OutlineDetection   bool     `json:"outline_detection"`
}

type deepLResp struct {
	Translations []struct {
		DetectedSourceLang string `json:"detected_source_lang"`
		Text               string `json:"text"`
	} `json:"translations"`
	Message string `json:"message"`
}

type deepLXReq struct {
	Text               string `json:"text"`
	SourceLang         string `json:"source_lang"`
	TargetLang         string `json:"target_lang"`
	TagHandling        string `json:"tag_handling"`
	Context            string `json:"context"`
	ModelType          string `json:"model_type"`
	SplitSentences     string `json:"split_sentences"`
	PreserveFormatting bool   `json:"preserve_formatting"`
	Formality          string `json:"formality"`
	GlossaryID         string `json:"glossary_id"`
	OutlineDetection   bool   `json:"outline_detection"`
}

type deepLXResp struct {
	Code         int      `json:"code"`
	ID           int      `json:"id"`
	Data         string   `json:"data"`
	Alternatives []string `json:"alternatives"`
}

type safeAvailableKeysAndURLs struct {
	keys, urls     []string
	mu             sync.RWMutex
	isCheckingBool bool
}

type posts struct {
	lReq     deepLReq
	lxReq    deepLXReq
	lClient  *http.Client
	lXClient *http.Client
}

func (d *deepLReq) checkDeepLSourceLangIsAllowed() bool {
	sl := strings.ToLower(d.SourceLang)
	if sl == "bg" || sl == "cs" || sl == "da" || sl == "de" || sl == "el" || sl == "en" || sl == "es" || sl == "et" || sl == "fi" || sl == "fr" || sl == "hu" || sl == "id" || sl == "it" || sl == "ja" || sl == "ko" || sl == "lt" || sl == "lv" || sl == "nb" || sl == "nl" || sl == "pl" || sl == "pt" || sl == "ro" || sl == "ru" || sl == "sk" || sl == "sl" || sl == "sv" || sl == "tr" || sl == "uk" || sl == "zh" {
		return true
	}
	return false
}

func (p *posts) deepL(key string) (deepLResp, int, error) {
	j, err := json.Marshal(p.lReq)
	if err != nil {
		return deepLResp{}, 0, err
	}

	var req *http.Request

	if strings.HasSuffix(key, ":fx") {
		req, err = http.NewRequest("POST", "https://api-free.deepl.com/v2/translate", bytes.NewReader(j))
		if err != nil {
			return deepLResp{}, 0, err
		}
	} else {
		req, err = http.NewRequest("POST", "https://api.deepl.com/v2/translate", bytes.NewReader(j))
		if err != nil {
			return deepLResp{}, 0, err
		}
	}

	req.Header.Set("Authorization", "DeepL-Auth-Key "+key)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.lClient.Do(req)
	if err != nil {
		p.lClient.CloseIdleConnections()
		slog.Debug("cleared http connection pool of deepl")
		return deepLResp{}, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return deepLResp{}, resp.StatusCode, nil
	}

	lResp := deepLResp{}

	if err = json.NewDecoder(resp.Body).Decode(&lResp); err != nil {
		return deepLResp{}, resp.StatusCode, err
	}

	if len(lResp.Translations) == 0 {
		if lResp.Message == "Quota Exceeded" {
			return deepLResp{}, resp.StatusCode, errDeepLQuotaExceeded
		} else {
			return deepLResp{}, resp.StatusCode, errDeepLUnavailableForUnknownReasons
		}
	}

	return lResp, resp.StatusCode, nil
}

func (p *posts) deepLX(u string) (deepLXResp, int, error) {
	j, err := json.Marshal(p.lxReq)
	if err != nil {
		return deepLXResp{}, 0, err
	}

	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(j))
	if err != nil {
		return deepLXResp{}, 0, err
	}

	resp, err := p.lXClient.Do(req)
	if err != nil {
		p.lXClient.CloseIdleConnections()
		slog.Debug("cleared http connection pool of deeplx")
		return deepLXResp{}, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return deepLXResp{}, resp.StatusCode, nil
	}

	lxResp := deepLXResp{}

	if err = json.NewDecoder(resp.Body).Decode(&lxResp); err != nil {
		return deepLXResp{}, resp.StatusCode, err
	}

	return lxResp, resp.StatusCode, nil
}

func (p *posts) checkAvailable(isKey bool, keyOrURL string) (bool, error) {
	if isKey {
		lResp, lRespCode, err := p.deepL(keyOrURL)

		if err != nil {
			if errors.Is(err, io.EOF) {
				slog.Debug("deepl key is invalid", "key", keyOrURL, "error message", err.Error())
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

		if lRespCode != http.StatusOK {
			if lRespCode >= http.StatusInternalServerError {
				return p.checkAvailable(isKey, keyOrURL)
			} else if lRespCode == http.StatusForbidden {
				slog.Debug("deepl key is invalid", "key", keyOrURL)
				return false, nil
			} else {
				return false, errors.New("HTTP " + strconv.Itoa(lRespCode))
			}
		}
	} else {
		_, lxRespCode, err := p.deepLX(keyOrURL)

		if err != nil {
			return false, err
		}

		if lxRespCode != http.StatusOK {
			if lxRespCode >= http.StatusInternalServerError {
				return p.checkAvailable(isKey, keyOrURL)
			} else {
				return false, errors.New("HTTP " + strconv.Itoa(lxRespCode))
			}
		}
	}

	return true, nil
}

func (p *posts) googleTranslate() (string, error) {
	var text []string
	var responseData []interface{}
	var sb strings.Builder

	sb.WriteString("https://translate.googleapis.com/translate_a/single?client=gtx&dt=t&sl=")
	sb.WriteString(p.lxReq.SourceLang)
	sb.WriteString("&tl=")
	sb.WriteString(p.lxReq.TargetLang)
	sb.WriteString("&dt=t")
	if p.lxReq.TagHandling != "" {
		sb.WriteString("&format=")
		sb.WriteString(p.lxReq.TagHandling)
	}
	sb.WriteString("&q=")
	sb.WriteString(url.QueryEscape(p.lxReq.Text))

	resp, err := p.lClient.Get(sb.String())
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

	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return "", err
	}

	if len(responseData) > 0 {
		r := responseData[0]
		if inner, ok := r.([]interface{}); ok {
			for _, slice := range inner {
				for _, translatedText := range slice.([]interface{}) {
					text = append(text, fmt.Sprintf("%v", translatedText))
					break
				}
			}
		} else if r == nil { // html only
			return p.lxReq.Text, nil
		} else {
			return "", fmt.Errorf("unexpected response structure: %v", r)
		}
		cText := strings.Join(text, "")
		return cText, nil
	} else {
		return "", err
	}
}

func (sakau *safeAvailableKeysAndURLs) removeKeyOrURL(isKey bool, keyOrURL string) bool {
	var slice *[]string
	indexToRemove := -1

	sakau.mu.Lock()
	defer sakau.mu.Unlock()

	if isKey {
		slice = &sakau.keys
	} else {
		slice = &sakau.urls
	}
	for i, v := range *slice {
		if v == keyOrURL {
			indexToRemove = i
			break
		}
	}

	if indexToRemove == -1 {
		return false
	}

	(*slice)[indexToRemove] = (*slice)[len(*slice)-1]
	*slice = (*slice)[:len(*slice)-1]

	return true
}

func (sakau *safeAvailableKeysAndURLs) isChecking() bool {
	sakau.mu.RLock()
	defer sakau.mu.RUnlock()
	if sakau.isCheckingBool {
		return true
	}
	return false
}

func (sakau *safeAvailableKeysAndURLs) setIsChecking(b bool) {
	sakau.mu.Lock()
	defer sakau.mu.Unlock()
	sakau.isCheckingBool = b
}

func (sakau *safeAvailableKeysAndURLs) runCheck(needOutput bool) (int, int, error) {
	if sakau.isChecking() {
		return 0, 0, errIsChecking
	}

	if needOutput {
		slog.Debug("no available keys and urls, start rechecking")
	}

	sakau.setIsChecking(true)
	defer func() { sakau.setIsChecking(false) }()

	p := posts{
		deepLReq{
			Text:       []string{"Hi"},
			TargetLang: "zh",
		},
		deepLXReq{
			Text:       "Hi",
			SourceLang: "en",
			TargetLang: "zh",
		},
		&http.Client{Timeout: 5 * time.Second},
		&http.Client{Timeout: 5 * time.Second},
	}

	keys, urls, err := parseKeysAndURLs()
	if err != nil {
		return 0, 0, err
	}

	var availableKeys, availableURLs []string
	var checkedFreeKey, checkedProKey bool
	var wg sync.WaitGroup
	var mu = &sync.Mutex{}

	for _, key := range keys {
		if !checkedFreeKey && strings.HasSuffix(key, ":fx") { // the requests in goroutine can reuse this connection
			isAvailable, err := p.checkAvailable(true, key)
			if err != nil {
				slog.Warn("error checking available", "key", key, "error message", err.Error())
				return 0, 0, err
			}

			checkedFreeKey = true

			if isAvailable {
				availableKeys = append(availableKeys, key)
			}

			continue
		} else if !checkedProKey && !strings.HasSuffix(key, ":fx") {
			isAvailable, err := p.checkAvailable(true, key)
			if err != nil {
				slog.Warn("error checking available", "key", key, "error message", err.Error())
				return 0, 0, err
			}

			checkedProKey = true

			if isAvailable {
				availableKeys = append(availableKeys, key)
			}

			continue
		}

		wg.Add(1)
		go func(k string) {
			defer wg.Done()
			isAvailable, err := p.checkAvailable(true, k)
			if err != nil {
				slog.Warn("error checking available", "key", k, "error message", err.Error())
				return
			}

			if isAvailable {
				mu.Lock()
				availableKeys = append(availableKeys, k)
				mu.Unlock()
			}
		}(key)
	}

	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			isAvailable, err := p.checkAvailable(false, u)
			if err != nil {
				slog.Warn("error checking available", "url", u, "error message", err.Error())
				return
			}

			if isAvailable {
				mu.Lock()
				availableURLs = append(availableURLs, u)
				mu.Unlock()
			}
		}(url)
	}

	wg.Wait()

	sakau.mu.Lock()
	sakau.keys, sakau.urls = availableKeys, availableURLs
	sakau.mu.Unlock()

	slog.Info("available check", "all keys count", len(keys), "available keys count", len(availableKeys), "all urls count", len(urls), "available urls count", len(availableURLs))

	return len(keys), len(urls), nil
}

func (sakau *safeAvailableKeysAndURLs) getRandomKey() string {
	sakau.mu.RLock()
	defer sakau.mu.RUnlock()
	if len(sakau.keys) == 0 {
		return ""
	}
	return sakau.keys[rand.IntN(len(sakau.keys))]
}

func (sakau *safeAvailableKeysAndURLs) getRandomURL() string {
	sakau.mu.RLock()
	defer sakau.mu.RUnlock()
	if len(sakau.urls) == 0 {
		return ""
	}
	return sakau.urls[rand.IntN(len(sakau.urls))]
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

func (sakau *safeAvailableKeysAndURLs) handleTranslate(retargetLanguageName *regexp.Regexp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Error("error reading request", "error message", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var (
			lxReq  deepLXReq
			lxResp deepLXResp

			forceUseDeepL, usedGoogleTranslate bool

			googleTranslateText string
			googleTranslateErr  error
			googleTranslateDone = make(chan struct{})
		)

		if err = json.NewDecoder(bytes.NewReader(reqBody)).Decode(&lxReq); err != nil || lxReq.Text == "" {
			slog.Warn("invalid request body", "client", r.RemoteAddr)
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		lReq := deepLReq{
			TargetLang:         lxReq.TargetLang,
			TagHandling:        lxReq.TagHandling,
			Context:            lxReq.Context,
			Formality:          lxReq.Formality,
			GlossaryID:         lxReq.GlossaryID,
			OutlineDetection:   lxReq.OutlineDetection,
			PreserveFormatting: lxReq.PreserveFormatting,
			SplitSentences:     lxReq.SplitSentences,
			Text:               []string{lxReq.Text},
		}

		if lReq.checkDeepLSourceLangIsAllowed() {
			lReq.SourceLang = lxReq.SourceLang
		}

		p := posts{
			lReq,
			lxReq,
			&http.Client{Timeout: 5 * time.Second},
			&http.Client{Timeout: 5 * time.Second},
		}

		go func() {
			googleTranslateText, googleTranslateErr = p.googleTranslate()
			googleTranslateDone <- struct{}{}
		}()

	reTranslate:

		if sakau.getRandomKey() == "" && sakau.getRandomURL() == "" {

			_, _, err = sakau.runCheck(true)
			if err != nil {
				if errors.Is(err, errIsChecking) {
					//slog.Debug("currently rechecking") // too much output
					http.Error(w, "no available keys or urls, currently rechecking, try again later", http.StatusInternalServerError)
					return
				}

				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if sakau.getRandomKey() == "" && sakau.getRandomURL() == "" {
				slog.Error("no available keys and urls")
				http.Error(w, "no available keys and urls", http.StatusInternalServerError)
				return
			}
		}

		var use int // 0 = key, 1 = url, 2 = accidentally no key when force use deepL translations

		if !forceUseDeepL {
			sakau.mu.RLock()
			if len(sakau.keys) > 0 && len(sakau.urls) > 0 {
				use = rand.IntN(2)
			} else if len(sakau.keys) == 0 {
				use = 1
			} // else if len(sakau.urls) == 0 {
			//	use = 0
			//}
			sakau.mu.RUnlock()
		}

		var key, u string

		if sakau.getRandomKey() == "" && forceUseDeepL {
			use = 2
		}

		if use == 0 {
			key = sakau.getRandomKey()

			if !strings.HasSuffix(key, ":fx") && lReq.checkDeepLSourceLangIsAllowed() {
				p.lReq.ModelType = "prefer_quality_optimized"
			}

			lResp, lRespCode, err := p.deepL(key)

			if lRespCode >= http.StatusInternalServerError {
				slog.Debug("deepl server response code not ok, retranslate", "url", u, "error message", err, "text", lxReq.Text, "latency", time.Since(startTime).String())
				goto reTranslate
			}

			if err != nil || lRespCode != http.StatusOK {
				if sakau.removeKeyOrURL(true, key) {
					slog.Warn("remove an unavailable key and retranslate", "key", key, "error message", err, "text", lxReq.Text, "latency", time.Since(startTime).String())
				}
				goto reTranslate
			}

			lxResp.Alternatives = make([]string, 1)
			lxResp.Code = http.StatusOK
			lxResp.Data = lResp.Translations[0].Text
			lxResp.Alternatives[0] = lResp.Translations[0].Text
		} else if use == 1 {
			u = sakau.getRandomURL()

			var lxRespCode int
			lxResp, lxRespCode, err = p.deepLX(u)

			if lxRespCode != http.StatusOK && lxRespCode >= http.StatusInternalServerError {
				slog.Debug("deeplx server response code not ok, retranslate", "url", u, "error message", err, "text", lxReq.Text, "latency", time.Since(startTime).String())
				goto reTranslate
			}

			if err != nil {
				if sakau.removeKeyOrURL(false, u) {
					slog.Warn("remove an unavailable url and retranslate", "url", u, "error message", err, "text", lxReq.Text, "latency", time.Since(startTime).String())
				}
				goto reTranslate
			}
		}

		if retargetLanguageName != nil && !retargetLanguageName.MatchString(lxResp.Data) {
			if use == 1 && sakau.getRandomKey() != "" {
				//slog.Debug("detected deeplx missing translation, force use deepl translate", "text", lxResp.Data, "url", u, "latency", time.Since(startTime).String())
				forceUseDeepL = true
				goto reTranslate
			}

			//if forceUseDeepL {
			//	slog.Debug("detected deepl is also missing translation, or has no available key, using google translate", "text", lxResp.Data, "key", key, "latency", time.Since(startTime).String())
			//} else {
			//	slog.Debug("detected deepl is missing translation, using google translate", "text", lxResp.Data, "key", key, "latency", time.Since(startTime).String())
			//}

			<-googleTranslateDone
			if googleTranslateErr != nil {
				slog.Warn("google translate failed, the response did not change", "text", lxResp.Data, "error message", googleTranslateErr.Error(), "latency", time.Since(startTime).String())
			} else if !retargetLanguageName.MatchString(googleTranslateText) {
				//slog.Debug("detected google is also missing translation, the response did not change", "text", googleTranslateText, "latency", time.Since(startTime).String())
				usedGoogleTranslate = true
			} else {
				lxResp.Data = googleTranslateText
				usedGoogleTranslate = true
			}
		}

		j, err := json.Marshal(lxResp)
		if err != nil {
			slog.Error("error marshalling json", "error message", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		slog.Debug("translation info", "text", lxResp.Data, "key", key, "url", u, "force used deepl", forceUseDeepL, "used google translate", usedGoogleTranslate, "latency", time.Since(startTime).String(), "client", r.RemoteAddr)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, string(j))
	}
}

func (sakau *safeAvailableKeysAndURLs) handleCheckAvailable(w http.ResponseWriter, r *http.Request) {
	slog.Debug(r.RemoteAddr + " request for rechecking")

	totalKeys, totalURLs, err := sakau.runCheck(false)
	if err != nil {
		if errors.Is(err, errIsChecking) {
			slog.Warn("currently rechecking")
			http.Error(w, "currently rechecking, try again later", http.StatusServiceUnavailable)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sakau.mu.RLock()
	defer sakau.mu.RUnlock()
	_, err = w.Write([]byte(fmt.Sprintf("all keys count:%d, available keys count:%d, all urls count:%d, available urls count:%d\n",
		totalKeys, len(sakau.keys), totalURLs, len(sakau.urls))))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		slog.Error("error writing response", "error message", err.Error())
		return
	}
}

func (sakau *safeAvailableKeysAndURLs) handleGetAvailableKeysAndURLsCount(w http.ResponseWriter, r *http.Request) {
	slog.Debug(r.RemoteAddr + " request for get available keys and urls count")

	sakau.mu.RLock()
	defer sakau.mu.RUnlock()

	_, err := w.Write([]byte(fmt.Sprintf("available keys count:%d, available urls count:%d\n",
		len(sakau.keys), len(sakau.urls))))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		slog.Error("error writing response", "error message", err.Error())
		return
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

	sakau := &safeAvailableKeysAndURLs{}

	_, _, err := sakau.runCheck(false)
	if err != nil {
		return
	}

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			_, _, err = sakau.runCheck(false)
			if err != nil {
				if errors.Is(err, errIsChecking) {
					slog.Warn("currently rechecking")
					continue
				}
			}
		}
	}()

	http.HandleFunc("/translate", sakau.handleTranslate(retargetLanguageName))
	http.HandleFunc("/check-available", sakau.handleCheckAvailable)
	http.HandleFunc("/", sakau.handleGetAvailableKeysAndURLsCount)

	slog.Info("server running on http://localhost:9000")
	err = http.ListenAndServe(":9000", nil)
	if err != nil {
		slog.Error(err.Error())
		return
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
