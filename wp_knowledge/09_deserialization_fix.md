# 反序列化修复约束

## 机器可读标签
- 适用family: deserialization
- 适用语言: php, python, java, node, go
- 文档角色: 主文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于通用反序列化主线迁移；YAML 场景优先看 `20_yaml_deserialization_fix.md`，Java 动态类型/JNDI 场景优先看 `19_jndi_fastjson_fix.md`。

## 漏洞判断信号
- 用户输入直接进入 `pickle`、`unserialize`、`ObjectInputStream` 等反序列化入口。
- 反序列化对象类型不受控，或业务其实只需要普通结构化数据。
- 代码把二进制对象流当作通用输入格式处理。

## 项目级主线修法
- 优先迁移到 JSON / 明确结构数据 / 显式字段解析。
- 不再把对象流作为通用输入格式。
- 对外输入统一收敛到基础类型（字符串、数字、布尔、数组、对象），并在 reader 端做字段级校验。
- 保持原有字段名、响应格式和业务语义，避免为迁移引入兼容性故障。

## 局部补丁 / 临时缓解
- PHP `unserialize` 必须使用 `allowed_classes=false`。
- 需要对象时必须使用类型白名单，并默认禁用对象实例化。
- 仅用于局部止血或迁移窗口，不作为项目级最终方案。

## 项目级联动提醒
- 同一数据结构在多个文件中读写时，必须联动修改 reader 和 writer。
- 共享 `cookie/session/state` 场景下，不应把短期缓解当成最终方案。
- 只改读取端不改写入端，会导致格式不一致、兼容分叉和业务异常。
- 通常需要一起改：状态写入端、状态读取端、历史兼容解析层、旧格式清理任务。

## 最小修补示例
局部补丁示例（仅迁移窗口）：
```php
$data = unserialize($payload, ['allowed_classes' => false]);
```

项目级主线示例（最终态推荐）：
```python
raw = request.get_json(force=True, silent=False)
data = {
	"uid": str(raw.get("uid", "")),
	"role": str(raw.get("role", "user")),
}
```

迁移窗口结束后，应移除对象反序列化兼容分支，不应长期保留 `unserialize(..., allowed_classes=false)` 读取逻辑。

## 不推荐做法
- 不要把 `allowed_classes=false` 当成项目级根治。
- 不要只修读取端，不修写入端。
- 不要把黑名单类名过滤当成临时缓解。
- 不要继续接受任意对象图。
- 不要用黑名单类名过滤当主方案。
- 不要把整个接口直接删掉而不保留原有数据能力。

## 检索关键词
- `deserialization mainline migration`
- `reader writer format migration`
- `allowed_classes false transition`
- `replace object stream with json`
- `objectinputstream explicit type control`
