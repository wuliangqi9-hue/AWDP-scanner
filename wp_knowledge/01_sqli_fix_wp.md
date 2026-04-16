# SQL 注入修复约束

## 机器可读标签
- 适用family: sqli
- 适用语言: php, python, java, node, go
- 文档角色: 主文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于 SQL 注入通用主线修法；若问题本质是对象绑定或反序列化，不应误用本文件。

## 漏洞判断信号
- 用户输入进入 `query`、`execute`、`mysqli_query`、`Statement` 等 SQL 执行点。
- SQL 字符串存在拼接、格式化、模板字符串、`StringBuilder` 直接拼接条件。
- 风险常见于动态 `WHERE`、`ORDER BY`、表名或列名拼接。

## 项目级主线修法
- 主线是参数化 / 预处理。
- `ORDER BY`、表名、列名这类不能参数化的位置，必须做白名单映射。
- 保持原有返回结构、分页逻辑、错误处理和 JSON 格式。
- 如果原接口返回列表、对象或分页结构，修补后不能改成其他类型。

## 局部补丁 / 临时缓解
- 过渡期可临时冻结高风险动态排序字段或复杂筛选组合，先阻断明显危险拼接。
- 关键字拦截或字符约束仅可短期限流，不是参数化替代方案。

## 项目级联动提醒
- 通常需要一起改：DAO/Repository、查询构造工具、分页与排序参数映射层。
- 只修单个查询点而不修公共查询拼接层，会在其他接口保留同类风险。

## 最小修补示例
项目级主线示例（推荐）：
```python
uid = request.args.get("uid", "")
cur.execute("SELECT id, name FROM users WHERE id = ?", (uid,))
```

```php
$stmt = $pdo->prepare("SELECT id, name FROM users WHERE id = :id");
$stmt->execute([':id' => $id]);
```

## 不推荐做法
- 不要把黑名单、关键字拦截、`preg_match` 拦 `select`/`union`/`and` 当主方案。
- 不要为了修洞重写整个查询层或改掉接口返回字段。
- 不要把所有异常统一吞掉，导致原有业务错误语义失真。

## 检索关键词
- `sqli mainline`
- `parameterized query`
- `prepare bind execute`
- `order by allowlist mapping`
