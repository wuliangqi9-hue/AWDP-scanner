# 文件包含 / 路径穿越修复约束

## 机器可读标签
- 适用family: path_traversal_lfi
- 适用语言: php, python, java, node, go
- 文档角色: 主文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于读取/下载/预览类路径访问；解压落盘场景优先看 `13_zip_slip_path_traversal_fix.md`，动态模板选择场景优先看 `21_dynamic_include_fix.md`。

## 漏洞判断信号
- 用户可控文件名或路径直接进入 `include`、`require`、文件读取或下载接口。
- 拼接路径后未做归一化校验，或只靠 `../` 字符串过滤。
- 允许通过参数访问任意模板、日志、配置或上传目录文件。

## 项目级主线修法
- 主线是 `realpath` / `commonpath` / 白名单映射。
- 先把基准目录固定，再校验归一化后的最终路径仍位于基准目录内。
- 若业务只允许有限文件，优先改成文件名白名单映射。
- 保持原有文件响应类型、下载逻辑和错误返回格式。

## 局部补丁 / 临时缓解
- 过渡期可增加路径字符约束、后缀约束、访问频率限制。
- `basename`、字符约束、黑名单过滤只能过渡降险，不能替代最终路径归一化与目录边界校验。

## 项目级联动提醒
- 若同一基准目录或路径校验工具被多个下载/预览/模板接口共享，必须联动统一修正。
- 通常需要一起改：路径拼接点、归一化校验函数、目录白名单配置、错误返回分支。
- 只修某个读取端而不修公共路径工具，会导致跨文件策略不一致和残留穿越入口。

## 最小修补示例
项目级主线示例（最终态推荐）：
```php
$base = realpath('/var/www/data');
$target = realpath($base . '/' . $name);
if ($target === false || strpos($target, $base) !== 0) {
    http_response_code(403);
    exit;
}
```

## 不推荐做法
- 不要只替换 `../` 或只删斜杠。
- 不要把所有路径都强行改成一个固定文件。
- 不要改变原有下载 / 查看接口的返回类型。

## 边界场景提醒
- 有 `realpath` 不等于一定安全，必须校验归一化后的目标路径是否仍在基准目录内。
- `basename` 只能减小风险，不等于完整修复。
- 编码转换前后都要看最终目标路径，不要只校验原始输入串。
- 黑名单 `../` 过滤不能替代最终路径归一化校验。
- 下载、预览、模板选择、文件读取是不同子场景，基准目录和白名单要分开配置。

## 检索关键词
- `path traversal read download mainline`
- `realpath commonpath boundary check`
- `base directory allowlist mapping`
- `path normalization final target`
