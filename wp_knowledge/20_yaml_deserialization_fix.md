# YAML 反序列化 / 非安全 YAML 加载修复约束

## 机器可读标签
- 适用family: yaml_deserialization
- 适用语言: python, java, node, php
- 文档角色: 专项文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于 YAML 对象构造与加载安全；通用反序列化主线迁移先看 `09_deserialization_fix.md`，Java 动态类型专项看 `19_jndi_fastjson_fix.md`。不适合 XML 外部实体和 Fastjson/JNDI 远程加载场景。

## 漏洞判断信号
- 用户输入进入 `yaml.load` 等可构造对象的加载入口。
- 配置解析允许自定义标签映射到对象实例。
- 业务只需要键值结构，却启用了全能力 YAML 解析。

## 项目级主线修法
- 项目级主线优先改为 JSON 或仅允许基础类型的 YAML 安全加载。
- Python 使用 `yaml.safe_load`；其他语言使用等价安全模式并限制标签。
- 解析结果必须做显式字段校验，不直接透传到执行或模板层。

## 局部补丁 / 临时缓解
- 过渡期可先将 `yaml.load` 切到 `yaml.safe_load`，并临时限制可接收字段集合。
- `yaml.safe_load` 是下限，不等于可省略结构校验、类型约束和读写链路迁移。

## 项目级联动提醒
- 若 YAML 数据在多个文件被读取/写入/缓存，必须联动迁移存储格式与解析逻辑。
- 通常需要一起改：写入端格式、读取端解析、历史数据兼容、落库字段约束。
- 只改读取端不改写入端，会导致新旧格式并存和业务兼容分叉。

## 最小修补示例
局部补丁示例（仅迁移窗口下限）：
```python
import yaml
cfg = yaml.safe_load(body)
name = str((cfg or {}).get('name', ''))
```

项目级主线示例（最终态推荐）：
```python
import yaml
cfg = yaml.safe_load(body)
validated = schema_validate(cfg, required=["name", "role"])
name = str(validated["name"])
```

迁移窗口结束后，不应把 `yaml.safe_load` 单独当成最终终点，仍需保留结构校验与字段约束。

## 不推荐做法
- 不要继续使用默认 `yaml.load` 处理不可信输入。
- 不要把标签黑名单当成长期主方案。
- 不要只修读取端，不修写入和存储格式。
- 不要把 `yaml.safe_load` 当最终主线终点。

## 检索关键词
- `yaml deserialization mainline`
- `unsafe yaml object construction`
- `safe_load with schema validation`
- `yaml format migration`
