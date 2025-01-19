## 介绍
使多个DeepL Free/Pro API可以通过DeepLX调用, 调用顺序为随机

更新: 现已支持混合其他DeepLX URL

当你拥有很多个DeepL Free/Pro API或DeepLX URL时, 这个程序就很有用

## 注意
只适用于DeeplX调用而不是DeepL

在部署前请编辑apis.txt, 一行填入一个DeepL Free/Pro API或DeepLX URL

[推荐设置一个目标语言, 用于检测漏译, DeepLX的漏译概率更大](https://fo.wikipedia.org/wiki/Fyrimynd:ISO_15924_script_codes_and_related_Unicode_data)

## 部署

### Docker部署
```
docker run -d -v ./apis.txt:/apis.txt -p 9000:9000 hentaku/deepl-keys-to-deeplx --D 目标语言
```
### 本机部署
```
go build main.go && nohup ./main -D=目标语言 &
```

## 使用
和DeepLX一致

请求localhost:9000/check-available可重新测活一次

请求localhost:9000/translate可翻译

默认路径为可用Keys和URLs数量
