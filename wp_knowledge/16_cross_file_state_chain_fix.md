# 跨文件状态链 / 读写联动修复约束

## 机器可读标签
- 适用family: cross_file_state_chain
- 适用语言: php, python, java, node, go
- 文档角色: 项目级联动文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于跨文件状态链与 reader/writer 联动修复；若仅单点反序列化替换，优先看 `09_deserialization_fix.md`。

## 漏洞判断信号
- 只改读取格式，不改写入格式。
- `serialize/unserialize` 与 `json_encode/json_decode` 混用。
- 新旧格式并存但没有过渡策略。

## 项目级主线修法
- 必须联动修改 writer 与 reader。
- 必须规划新旧格式兼容窗口。
- 最终要清理旧格式写入与旧解析逻辑。

## 局部补丁 / 临时缓解
- 迁移窗口内可短期保留“新格式优先 + 旧格式兜底”读取分支。
- 该兼容分支仅用于平滑迁移，不能长期保留为默认解析路径。

## 项目级联动提醒
- 通常需要一起改：写入端格式生成、读取端解析、公共状态工具、兼容窗口开关。
- 只改 reader 不改 writer，会触发格式分叉；只改 writer 不改 reader，会触发读取失败或回退到旧危险分支。

## 建议修复顺序
- 写入端先新增安全格式。
- 读取端兼容解析新旧格式。
- 清理旧格式写入。
- 废弃原危险读取逻辑。

## 最小修补示例
过渡期 writer 示例（迁移窗口）：
```php
setcookie('profile', json_encode(['uid' => $uid, 'role' => $role]), 0, '/');
```

过渡期 reader 示例（迁移窗口，非最终态）：
```php
$raw = $_COOKIE['profile'] ?? '{}';
$data = json_decode($raw, true);
if (!is_array($data)) {
    $tmp = @unserialize($raw, ['allowed_classes' => false]);
    $data = is_array($tmp) ? $tmp : [];
}
```

最终态目标说明（迁移完成后）：
- 兼容旧格式的读取分支仅适用于迁移窗口。
- 最终态应移除旧解析分支，仅保留新格式解析与字段校验。

## 不推荐做法
- 不要只修某一个 reader。
- 不要放任项目中同时存在两套不兼容格式。
- 不要无限期保留旧写入和旧解析分支。

## 检索关键词
- `cross file state chain`
- `reader writer consistency`
- `cookie migration`
- `session format migration`
