# Python / Jinja SSTI 修复约束

## 机器可读标签
- 适用family: ssti_python_jinja
- 适用语言: python
- 文档角色: 专项文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于 Python/Jinja 模板注入细节；通用模板主线先看 `03_ssti_fix_wp.md`，动态模板文件选择看 `21_dynamic_include_fix.md`。不适合模板文件路径选择与包含目录约束场景。

## 漏洞判断信号
- 用户输入被拼接进 `render_template_string`、Jinja `Template`、f-string 模板源码。
- 代码把输入既当模板又当数据，导致上下文边界失效。
- 修复建议仍然在拼模板字符串，只是加了一层关键词过滤。

## 项目级主线修法
- 主线统一为“固定模板 + context 变量”。
- 优先改用固定模板文件；如果必须用 `render_template_string`，模板字符串也必须固定。
- 用户输入只作为变量传递，不参与模板语法生成。
- 保持原页面路由、返回类型和已有模板变量名称。

## 局部补丁 / 临时缓解
- 过渡期可临时停用动态模板字符串入口，并限制模板来源。
- denylist 过滤仅可临时止血，不能替代固定模板与上下文变量分层。

## 项目级联动提醒
- 通常需要一起改：Jinja 渲染函数、共用模板 helper、输入预处理层、模板目录配置。
- 只修单个 `render_template_string` 调用点而不修公共 helper，会导致其他入口复发。

## 最小修补示例
项目级主线示例（推荐）：
```python
template = "Hello {{ name }}"
name = request.args.get("name", "Guest")
return render_template_string(template, name=name)
```

## 不推荐做法
- 不要继续 `template = f"Hello {name}"` 这类拼接。
- 不要把 denylist、危险关键字拦截、脆弱正则当主修法。
- 不要为了修洞把原页面改成完全不同的纯文本接口。

## 检索关键词
- `python jinja ssti mainline`
- `render_template_string fixed template`
- `jinja context variable only`
- `no template concatenation`
