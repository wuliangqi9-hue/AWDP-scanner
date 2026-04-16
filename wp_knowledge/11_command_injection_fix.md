# 命令注入修复约束

## 机器可读标签
- 适用family: command_injection
- 适用语言: python, node, java, php, go
- 文档角色: 专项文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于命令参数化落地；通用动态执行治理先看 `04_rce_eval_fix_wp.md`，PHP 危险函数细节看 `14_php_rce_waf_fix.md`。不适合模板执行语义或路径访问类场景。

## 漏洞判断信号
- 请求参数进入系统命令参数、子进程调用或 shell 解释器。
- `subprocess`、`child_process`、`ProcessBuilder` 参数来自未校验输入。
- 业务上只有少数固定动作，但代码允许用户自由拼命令。

## 项目级主线修法
- 统一改为参数列表化调用，禁止 shell 拼接。
- 固定动作映射优先于“任意命令 + 参数过滤”。
- Python / Node / Java 统一要求 `shell=False` 等价策略和明确超时。
- 保持原有接口状态码、JSON 字段和超时策略。

## 局部补丁 / 临时缓解
- 若短期不能彻底改为动作映射，至少做严格格式校验并限制参数范围。
- 过渡期可增加最小权限运行和审计日志，但不能替代主线改造。

## 项目级联动提醒
- 若命令调用分散在多个服务/脚本，需联动收敛到统一动作映射与统一执行封装。
- 通常需要一起改：动作路由层、参数校验层、执行封装层、审计日志层。
- 只修单个入口而保留旧执行封装，会导致同类命令注入在其他入口复现。

## 最小修补示例
项目级主线示例（推荐）：
```python
action = request.args.get("action", "")
target = request.args.get("target", "")
if not re.fullmatch(r"[a-zA-Z0-9.-]{1,64}", target):
    raise ValueError("bad target")
if action == "dns_check":
    subprocess.run(["nslookup", target], shell=False, timeout=3)
else:
    raise ValueError("bad action")
```

## 不推荐做法
- 不要只做黑名单元字符过滤。
- 不要继续 `shell=True` 后再指望转义修补。
- 不要把“参数过滤 + 任意命令入口”当作最终方案。
- 不要直接删掉整个诊断功能而不保留原业务能力。

## 检索关键词
- `command injection mainline`
- `subprocess child_process processbuilder`
- `argument list shell false`
- `action allowlist mapping`
