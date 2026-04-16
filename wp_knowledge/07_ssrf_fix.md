# SSRF 修复约束

## 机器可读标签
- 适用family: ssrf
- 适用语言: php, python, java, node, go
- 文档角色: 主文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于服务端主动请求链路；若问题是文件路径访问或模板包含，不应套用本文件。

## 漏洞判断信号
- 用户可控 URL 被服务端直接请求。
- 只校验字符串前缀，未限制协议、主机、端口和解析后的 IP。
- 存在访问内网、回环地址、元数据地址或任意重定向的可能。

## 项目级主线修法
- 主线是协议限制 + 主机 / IP 校验 + 端口白名单。
- 对解析后的 IP 做内网、回环、链路本地地址拦截。
- 必要时只允许访问业务白名单主机。
- 保持原有接口成功 / 失败响应结构，不要为了修洞改掉整个代理逻辑。

## 局部补丁 / 临时缓解
- 过渡期可先启用严格主机白名单并暂时关闭重定向跟随。
- 临时 DNS 缓存或字符串前缀拦截只能降险，不能替代解析后 IP 校验。

## 项目级联动提醒
- 通常需要一起改：HTTP 客户端封装、DNS 解析层、代理配置、重定向策略。
- 只修某个请求入口而不修公共请求库，会在其他入口保留同类 SSRF 风险。

## 最小修补示例
项目级主线示例（推荐）：
```python
u = urlparse(url)
if u.scheme not in ("http", "https"):
    raise ValueError("bad scheme")
host_ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
if host_ip.is_private or host_ip.is_loopback or host_ip.is_link_local:
    raise ValueError("internal blocked")
```

## 不推荐做法
- 不要只做字符串 `contains("127.0.0.1")` 这类拦截。
- 不要忽略 DNS 解析后的真实 IP。
- 不要把所有请求都改成固定 URL，导致业务不可用。

## 检索关键词
- `ssrf mainline`
- `scheme host port allowlist`
- `block private loopback ip`
- `dns resolved ip check`
