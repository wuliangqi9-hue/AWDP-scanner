# 变量覆盖 / parse_str / extract 修复约束

## 机器可读标签
- 适用family: variable_overwrite
- 适用语言: php
- 文档角色: 专项文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于请求参数覆盖局部变量与状态字段；若状态格式迁移涉及多文件读写，联动查看 `16_cross_file_state_chain_fix.md`。

## 漏洞判断信号
- 使用 `parse_str($input)` 不带目标数组，导致变量注入当前作用域。
- 使用 `extract()` 导入外部数组，覆盖鉴权或业务关键变量。
- 请求参数直接覆盖 `role/is_admin/uid/token` 等状态字段。

## 项目级主线修法
- 项目级主线改为显式字段解析，不把外部输入批量注入局部变量。
- `parse_str` 必须写入独立数组；`extract` 默认禁用，必要时仅对白名单字段使用。
- 状态字段统一从服务端可信源读取，不从请求参数覆盖。

## 项目级联动提醒
- 若项目中有公共参数解析函数、基类 controller、中间件注入逻辑，必须联动统一处理。
- 只修局部页面而不修公共解析层，会在其他入口继续发生变量覆盖。

## 最小修补示例
项目级主线示例（推荐）：
```php
parse_str($query, $params);
$uid = isset($params['uid']) ? (string)$params['uid'] : '';
$action = isset($params['action']) ? (string)$params['action'] : '';
```

## 不推荐做法
- 不要继续 `parse_str($query)` 直接落本地变量。
- 不要对外部输入使用 `extract()` 覆盖当前作用域。
- 不要靠黑名单字段名做补丁式拦截。

## 检索关键词
- `variable overwrite mainline`
- `parse_str target array`
- `extract avoid untrusted input`
- `trusted state field`
