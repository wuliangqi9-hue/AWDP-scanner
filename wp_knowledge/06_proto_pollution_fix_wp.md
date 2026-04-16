# 原型链污染修复约束

## 机器可读标签
- 适用family: prototype_pollution
- 适用语言: node, javascript
- 文档角色: 主文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于对象合并污染约束；若风险点在模板路径或文件路径拼接，应改查路径/模板类文档。

## 漏洞判断信号
- 用户可控对象被直接合并进全局配置或通用对象。
- 输入键名未限制，允许 `__proto__`、`constructor`、`prototype`。
- 业务把外部 JSON 直接深拷贝或深合并到默认对象。

## 项目级主线修法
- 主线是字段白名单 + 安全目标对象。
- 只接收业务需要的字段，显式拷贝允许键。
- 合并目标尽量使用 `Object.create(null)` 或框架提供的安全合并能力。
- 保持原有字段语义和返回结构，不要为了修洞把整个配置逻辑推翻。

## 局部补丁 / 临时缓解
- 过渡期可先统一拦截 `__proto__`、`constructor`、`prototype` 并收紧输入键集合。
- 这些措施仅作短期止血，不能替代显式字段拷贝与安全目标对象。

## 项目级联动提醒
- 若项目中存在多个“通用 merge 工具”或配置聚合入口，需联动统一键白名单策略。
- 只修单个接口而保留旧 merge 工具，会导致同根因在其他模块复发。

## 最小修补示例
项目级主线示例（推荐）：
```javascript
const allow = new Set(["name", "email", "age"]);
const dst = Object.create(null);
for (const key of Object.keys(input)) {
  if (allow.has(key)) dst[key] = input[key];
}
```

## 不推荐做法
- 不要只拦一个危险键名，其它危险变体仍会漏掉。
- 不要把所有对象输入一刀切禁用，破坏原有更新功能。
- 不要继续用通用深合并直接吃用户对象。

## 检索关键词
- `prototype pollution mainline`
- `safe merge whitelist keys`
- `object create null`
- `forbid proto constructor prototype`
