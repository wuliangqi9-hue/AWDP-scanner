# JNDI / Fastjson / Java 反序列化型远程加载修复约束

## 机器可读标签
- 适用family: jndi_fastjson_deserialization
- 适用语言: java
- 文档角色: 专项文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于 Java 动态类型解析/JNDI 远程加载专项；通用反序列化迁移优先看 `09_deserialization_fix.md`，YAML 场景优先看 `20_yaml_deserialization_fix.md`。不适合 PHP/Python 对象流迁移场景。

## 漏洞判断信号
- 反序列化或 JSON 绑定允许动态类型解析、远程类加载或 JNDI 查找。
- 代码依赖历史默认配置，未显式关闭危险自动类型能力。
- 输入可控字段可影响类名、工厂名、lookup 目标。

## 项目级主线修法
- 项目级主线是升级到安全版本并关闭危险自动类型/远程加载能力。
- 输入解析改为显式 DTO 字段绑定，不允许根据输入决定类型。
- JNDI 相关路径仅允许固定、受控配置，不从请求参数拼接。

## 项目级联动提醒
- 若同一服务链路存在网关、消费端、反序列化工具类，需联动统一版本与配置。
- 只升级单个模块而不统一依赖基线，会保留版本分叉与残留动态类型入口。

## 最小修补示例
项目级主线示例（推荐）：
```java
// 主线：显式 DTO 绑定，而非动态类型反射
UserDTO dto = objectMapper.readValue(body, UserDTO.class);
```

## 不推荐做法
- 不要依赖临时系统参数或网关黑名单作为最终方案。
- 不要保留输入可控的类名或 lookup 目标。
- 不要只在单个模块升级依赖，忽略其它服务版本分叉。

## 检索关键词
- `fastjson jndi mainline`
- `disable autotype dynamic type`
- `java dto explicit binding`
- `remote loading hardening`
