# 通用 SSTI 修复约束

## 机器可读标签
- 适用family: ssti
- 适用语言: python, php, java, node
- 文档角色: 主文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件是模板注入通用主线；Python/Jinja 细节优先看 `15_python_ssti_jinja_fix.md`，动态包含/模板路径选择优先看 `21_dynamic_include_fix.md`。不适合模板文件目标选择本身。

## 漏洞判断信号
- 用户输入被拼接进模板源码，再交给模板引擎解释执行。
- 使用 `render_template_string`、`Template(...)`、字符串拼模板、动态模板片段拼接。
- 模板变量和值没有分层，数据和模板边界混在一起。

## 项目级主线修法
- 主线统一为“固定模板 + context 变量”。
- 模板内容要固定，用户输入只能作为变量传入，不参与模板语法生成。
- 保持原有页面路由、返回类型和模板变量名称习惯。
- 如果接口原本返回 HTML，就继续返回 HTML；不要为修洞改成纯文本或 JSON。

## 局部补丁 / 临时缓解
- 过渡期可临时关闭高风险动态模板入口，并限制模板来源。
- 危险关键字拦截仅可短期止血，不能替代固定模板与上下文变量边界。

## 项目级联动提醒
- 通常需要一起改：模板渲染助手、页面控制器、模板加载配置、共享 context 构造层。
- 只修单个页面渲染点而不修公共模板工具，会导致其他页面复现同类问题。

## 最小修补示例
项目级主线示例（推荐）：
```python
name = request.args.get("name", "guest")
return render_template("hello.html", name=name)
```

## 不推荐做法
- 不要把 denylist、危险关键字拦截、`{{`/`}}` 过滤当主修法。
- 不要继续拼接模板字符串后再侥幸加一层正则。
- 不要为了修洞把整套模板渲染逻辑重写成完全不同的页面流。

## 检索关键词
- `ssti general mainline`
- `fixed template context`
- `template data boundary`
- `template injection repair`
