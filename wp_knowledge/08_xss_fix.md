# XSS 修复约束

## 机器可读标签
- 适用family: xss
- 适用语言: php, python, java, node, frontend_js
- 文档角色: 主文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于输出上下文编码与安全 sink；若问题是模板注入执行语义，优先看 SSTI 文档。

## 漏洞判断信号
- 用户输入进入 HTML、属性、URL、脚本上下文且未做对应编码。
- 前端直接写 `innerHTML`、`document.write`，后端输出原始 HTML 片段。
- 接口返回字段被前端直接当 HTML 渲染。

## 项目级主线修法
- 主线是按上下文输出编码 + 使用安全 sink。
- 服务端模板优先用自动转义；前端优先用 `textContent`、`innerText`、安全模板绑定。
- 如果业务确实需要富文本，必须明确限定可信来源或做成熟的 HTML 清洗。
- 保持原有响应字段和接口格式，不要因为修洞改成完全不同的页面流。

## 局部补丁 / 临时缓解
- 过渡期可先将高风险渲染位点改为纯文本输出，临时关闭富文本直出。
- 关键字过滤和字符串替换仅可短期缓解，不能替代上下文编码与安全 sink。

## 项目级联动提醒
- 通常需要一起改：服务端模板输出、前端 DOM 写入点、富文本清洗组件、共享渲染函数。
- 只修后端或只修前端一端，会导致跨层输出编码策略不一致。

## 最小修补示例
项目级主线示例（推荐）：
```python
from markupsafe import escape
return render_template("profile.html", nickname=escape(nickname))
```

```javascript
document.getElementById("msg").textContent = userInput;
```

## 不推荐做法
- 不要继续用 `innerHTML` 再补一层脆弱替换。
- 不要只拦 `<script>` 关键字。
- 不要把页面整体改成纯文本响应。

## 检索关键词
- `xss output encoding mainline`
- `safe sink textcontent`
- `template autoescape`
- `html attribute url context encoding`
