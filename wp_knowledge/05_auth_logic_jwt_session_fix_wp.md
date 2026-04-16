# JWT / Session / 鉴权逻辑修复约束

## 机器可读标签
- 适用family: auth_jwt_session
- 适用语言: php, python, java, node, go
- 文档角色: 主文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于鉴权状态可信性与统一入口；若问题核心是状态格式迁移，优先联动 `16_cross_file_state_chain_fix.md` 与 `09_deserialization_fix.md`。

## 漏洞判断信号
- JWT 解码未验签，或只读声明不校验 `iss`、`aud`、过期时间。
- 权限判断散落在多个业务分支里，存在题目化特判或临时绕过。
- Session 用户身份、角色或管理员标记直接取自不可信输入。

## 项目级主线修法
- 主线是验签 + 声明校验 + 统一鉴权入口。
- JWT 至少校验签名、算法、过期时间；需要时补 `issuer` / `audience`。
- Session 权限字段只能来自服务端可信态，不从请求参数直接覆盖。
- 尽量复用现有中间件、装饰器、统一鉴权函数，不要在单个业务分支里拼凑临时规则。

## 局部补丁 / 临时缓解
- 过渡期可增加高风险路由二次鉴权、短期 token 生命周期收缩、异常审计。
- 这些策略只能临时降风险，不能替代统一鉴权入口改造。

## 项目级联动提醒
- 同一 `cookie/session/state` 在多个文件读写时，必须联动修改 reader 和 writer。
- 只修单个入口会导致跨文件状态不一致，出现“部分接口已修、部分接口仍可绕过”的残留风险。
- 通常需要一起改：登录签发端、鉴权中间件、业务读取端、登出/续签逻辑。

## 最小修补示例
项目级主线示例（推荐）：
```python
decoded = jwt.decode(
    token,
    SECRET,
    algorithms=["HS256"],
    audience="awdp",
    issuer="platform",
)
```

## 不推荐做法
- 不要保留题目特化逻辑，如对特定用户名、Cookie 或路由做硬编码放行。
- 不要只靠前端标志位或请求参数决定管理员权限。
- 不要只在单个 controller 打补丁而不统一到中间件或公共鉴权层。
- 不要把修复做成“碰到异常一律当管理员/游客”的临时分支。

## 检索关键词
- `auth state mainline`
- `jwt signature claims verify`
- `session trusted source`
- `cross file auth consistency`
