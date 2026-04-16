# 命令执行 / RCE / eval 修复约束

## 机器可读标签
- 适用family: command_execution_rce_eval
- 适用语言: php, python, java, node, go
- 文档角色: 主文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于通用动态执行主线治理；命令参数落地优先看 `11_command_injection_fix.md`，PHP 危险函数细节优先看 `14_php_rce_waf_fix.md`。不适合仅模板路径选择或文件读取路径场景。

## 漏洞判断信号
- 用户输入进入 `system`、`exec`、`shell_exec`、`Runtime.exec`、`subprocess`、`eval`。
- 存在命令拼接、`shell=True`、动态表达式执行、把业务参数直接当代码跑。
- 原逻辑其实只需要几种固定动作，却走了通用执行接口。

## 项目级主线修法
- 优先移除通用执行入口（命令执行、`eval`、动态表达式解释），改成显式业务逻辑。
- 将“用户可控动作”收敛为固定动作映射，不允许输入直接决定执行目标。
- 命令类操作统一遵循参数列表化、`shell=False`、超时与错误处理一致性。

## 局部补丁 / 临时缓解
- 在暂时无法下线执行入口时，可加严格格式校验和最小白名单，先阻断高风险输入。
- `escapeshellarg()`、关键字拦截、正则过滤仅可作为过渡补强，不是项目级主线。

## 项目级联动提醒
- 若动作映射、命令封装、执行网关分散在多个文件，必须联动统一到同一约束层。
- 只改某个 controller 而不改公共执行封装，会出现“部分入口已收敛、部分入口仍可动态执行”的残留风险。

## 最小修补示例
项目级主线示例（推荐）：
```python
action = request.args.get("action", "")
allow = {
    "dns_check": lambda v: subprocess.run(["nslookup", v], shell=False, timeout=3),
}
if action not in allow:
    return jsonify({"error": "bad action"}), 400
```

## 不推荐做法
- 不要把黑名单、关键字拦截、脆弱正则当主方案。
- 不要继续使用 `shell=True`。
- 不要把 `eval` 保留在主流程里再叠加脆弱过滤。
- 不要把局部参数过滤误当成项目级根治。
- 不要因为修洞把整段业务都删掉或改成固定死值返回。

## 检索关键词
- `rce general mainline`
- `remove eval`
- `action mapping governance`
- `mitigation not final`
