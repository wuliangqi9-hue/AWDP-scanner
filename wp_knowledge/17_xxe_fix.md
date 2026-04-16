# XXE 修复约束

## 机器可读标签
- 适用family: xxe
- 适用语言: php, python, java, node
- 文档角色: 专项文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 否

场景分流提示：本文件用于 XML 外部实体解析风险；若核心问题是 YAML 或通用反序列化迁移，优先看 `20_yaml_deserialization_fix.md` 或 `09_deserialization_fix.md`。不适合命令执行或路径访问场景。

## 漏洞判断信号
- 服务端解析用户可控 XML，且启用了外部实体或 DTD。
- 解析器配置使用默认宽松模式，未显式关闭外部资源访问。
- 业务只需要结构化数据，却长期保留 XML 入口。

## 项目级主线修法
- 项目级主线优先迁移到 JSON 或受限结构化输入。
- 必须禁用外部实体、禁用外部 DTD、禁用网络访问。
- 解析后只提取显式字段，不把 XML 直接映射为任意对象结构。

## 最小修补示例
项目级主线示例（推荐）：
```python
from defusedxml import ElementTree as ET
root = ET.fromstring(xml_data)
order_id = root.findtext('orderId', default='')
```

## 不推荐做法
- 不要只靠关键字拦截 `<!DOCTYPE` 当主方案。
- 不要继续使用默认不安全解析配置。
- 不要在多个解析入口里只修其中一个。

## 检索关键词
- `xxe mainline`
- `disable external entity dtd`
- `safe xml parser config`
- `xml structured migration`
