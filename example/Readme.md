# 测试示例

这是一个测试用的demo，用来演示tls的流量劫持功能。

## 修改配置

修改 `tls_client.c` 中的 `SERVER_HOST` 为你的域名。

## 编译 
```bash
make
# make VERIFY=0
```

VERIFY=0 表示不验证服务器证书，默认会验证。

## 运行

运行服务
```bash
./tls_server # 服务器运行
```

网关流量劫持
```bash
iptables -t nat -A PREROUTING -p tcp --dport 6666 -j REDIRECT --to-port 6666
```

```bash
python mtls.py --listen-port 6666 -s plugins/log.py
```

客户端运行
```bash
./tls_client
```


可以看到整个数据流量的交互。