# Java / Node 通用加固约束

## 机器可读标签
- 适用family: hardening
- 适用语言: java, node
- 文档角色: 加固文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于框架默认行为与工程加固；若已定位具体 family（如命令执行、反序列化、路径穿越），优先使用对应 family 文档。本文件不替代具体漏洞家族主文档。

## 漏洞判断信号
- 框架参数绑定过宽、对象属性可任意注入、依赖版本明显脆弱。
- 输入模型缺少 Schema 校验，或默认把整个请求体映射到对象。
- 加固目标不是单点漏洞，而是减少易错默认行为。

## 项目级主线修法
- 主线是框架原生校验、字段白名单、依赖版本锁定。
- Java 优先限制可绑定字段、减少危险反序列化和宽松对象映射。
- Node 优先做 Schema 校验和显式字段选择，不把全量请求体直接透传。
- 加固时不要改掉原路由、原响应结构和业务字段语义。

## 局部补丁 / 临时缓解
- 过渡期可先收紧高风险绑定入口、冻结依赖版本升级窗口并增加审计日志。
- 局部正则拦截或单点禁用字段仅作短期控制，不能替代框架级统一约束。

## 项目级联动提醒
- 通常需要一起改：框架绑定配置、校验中间件、DTO/Schema 定义、依赖基线管理。
- 只修业务接口而不改框架默认配置，会在其他服务或模块继续暴露同类风险。

## 最小修补示例
项目级主线示例（推荐）：
```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("name", "email", "age");
}
```

```javascript
const allow = ["name", "email", "age"];
const filtered = Object.fromEntries(Object.entries(input).filter(([k]) => allow.includes(k)));
```

## 不推荐做法
- 不要新增一堆与业务耦合很强的正则补丁。
- 不要为了“加固”把所有请求字段都禁掉。
- 不要忽略依赖版本和框架默认配置问题。

## 检索关键词
- `java node hardening mainline`
- `java binder allowed fields`
- `node schema explicit fields`
- `dependency baseline pinning`
