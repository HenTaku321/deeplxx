## 介绍
使多个DeepL keys可以通过DeepLX调用, 调用顺序为随机

当你拥有很多个DeepL keys, 并且担心某一个key失效或超额导致你需要手动更换时, 这个程序就很有用

## 注意
只适用于DeeplX而不是DeepL

在部署前请编辑keys.txt, 一行填入一个key

## 部署

### Docker部署
```
sudo docker run -d -v ./keys.txt:/keys.txt -p 9000:9000 hentaku/deepl-keys-to-deeplx
```
### 本机部署
```
go build main.go && nohup ./main &
```

## 使用
和DeepLX一致
