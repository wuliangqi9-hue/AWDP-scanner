# 动态包含 / 动态模板选择修复约束

## 机器可读标签
- 适用family: dynamic_include
- 适用语言: php, python, java, node
- 文档角色: 专项文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于模板/包含目标选择链路；通用 SSTI 语义执行风险先看 `03_ssti_fix_wp.md` 或 `15_python_ssti_jinja_fix.md`，文件读取路径风险优先看 `10_lfi_path_traversal_fix.md`。不适合仅模板表达式执行语义与压缩包解压落盘场景。

## 漏洞判断信号
- 用户输入直接决定 `include/require/import` 路径或模板名。
- 模板选择支持任意路径拼接，而不是固定模板 ID 映射。
- 代码把模板选择与文件读取混用，缺少目录边界。

## 项目级主线修法
- 项目级主线是模板 ID 白名单映射，不允许用户输入直接参与路径拼接。
- 文件型包含必须做基准目录 + 归一化路径校验。
- 模板型渲染只允许固定模板集合，用户输入仅作为业务参数。

## 局部补丁 / 临时缓解
- 过渡期可临时限制可选模板集合并关闭高风险动态后缀拼接。
- `basename`、简单后缀过滤只能短期降险，不能替代模板 ID 映射与目录边界校验。

## 项目级联动提醒
- 模板选择逻辑和模板目录约束必须联动修改，不能只改其中一端。
- 通常需要一起改：路由层 view 参数映射、模板加载器、模板目录配置、回退模板策略。
- 只修选择逻辑不修加载器，或只修加载器不修映射，都可能留下跨文件不一致风险。

## 最小修补示例
项目级主线示例（推荐）：
```php
$map = [
    'home' => 'home.php',
    'profile' => 'profile.php',
];
$key = $_GET['view'] ?? 'home';
$file = $map[$key] ?? $map['home'];
require __DIR__ . '/templates/' . $file;
```

## 不推荐做法
- 不要继续 `include $_GET['page']` 这类直连路径。
- 不要只用 `basename` 当完整修复。
- 不要让下载、预览、模板选择共用一套宽松路径规则。

## 检索关键词
- `dynamic include mainline`
- `template id allowlist mapping`
- `template path selection`
- `include loader directory boundary`
