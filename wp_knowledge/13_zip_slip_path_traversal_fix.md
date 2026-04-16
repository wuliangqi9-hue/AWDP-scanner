# Zip Slip / 解压路径穿越修复约束

## 机器可读标签
- 适用family: zip_slip_path_traversal
- 适用语言: python, java, node, go, php
- 文档角色: 专项文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于压缩包解压落盘链路；读取/下载路径访问优先看 `10_lfi_path_traversal_fix.md`，动态模板包含优先看 `21_dynamic_include_fix.md`。

## 漏洞判断信号
- 压缩包内文件名可控，解压路径直接拼接目标目录。
- 解压前未做归一化路径校验，或只靠 `startswith` 做脆弱比较。
- 解压逻辑一次性读取所有成员，可能同时引入路径穿越和资源耗尽风险。

## 项目级主线修法
- 主线是 `realpath` / `commonpath` 校验每个成员的最终路径。
- 解压时按成员迭代处理，必要时累计大小并限制总量，避免 DoS。
- 入口文件名和保存目录都应使用白名单或安全文件名策略。
- 保持原有上传 / 解压成功失败返回结构。

## 局部补丁 / 临时缓解
- 过渡期可限制压缩包来源、压缩层级和成员数量。
- 这些限制不能替代每个成员路径的归一化校验。

## 项目级联动提醒
- 若解压逻辑在多个任务/服务共用，必须联动统一成员路径校验与大小/数量限制。
- 通常需要一起改：上传入口、解压服务、落盘目录配置、后续预览/下载读取链路。
- 只修解压点而不修后续读取策略，会出现“落盘安全但读取越界”或策略不一致问题。

## 最小修补示例
项目级主线示例（最终态推荐）：
```python
real_base = os.path.realpath(dest_dir)
real_target = os.path.realpath(os.path.join(dest_dir, member.name))
if os.path.commonpath([real_base, real_target]) != real_base:
    raise ValueError("bad archive entry")
```

## 不推荐做法
- 不要只做 `startswith` 比较。
- 不要只过滤 `../` 字符串。
- 不要为了修洞去掉整个解压功能。

## 边界场景提醒
- 有 `realpath` 不等于一定安全，仍要逐成员校验最终目标路径。
- `basename` 只能降低风险，不能覆盖目录穿越、软链接等复杂情况。
- 编码转换前后都要验证最终落盘路径，不能只看原始文件名。
- 黑名单 `../` 过滤不能替代最终路径归一化校验。
- 下载、预览、模板选择、解压是不同子场景，不能共用一套宽松规则。

## 检索关键词
- `zip slip extract mainline`
- `archive member path normalization`
- `commonpath extract boundary`
- `decompression size count limit`
