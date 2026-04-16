# PHP 命令执行修复约束

## 机器可读标签
- 适用family: command_injection_php
- 适用语言: php
- 文档角色: 专项文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于 PHP `system/exec/shell_exec/popen` 专项；通用动态执行治理先看 `04_rce_eval_fix_wp.md`，跨语言命令参数化落地看 `11_command_injection_fix.md`。不适合非 PHP 技术栈的通用修复主线选型。

## 漏洞判断信号
- `system`、`exec`、`shell_exec`、`passthru`、`popen` 接收了用户可控参数。
- 业务仅需要固定诊断动作，却让请求参数直接拼成命令。
- 代码把 WAF 式黑名单当主修法。

## 项目级主线修法
- 优先去除任意命令能力，改成固定动作映射或内部 API。
- 必须调用系统命令时，仅允许固定命令头，用户输入只能进入受限参数位。
- 对参数做白名单或严格格式校验，保持原有 HTTP 状态码和 JSON / 页面响应格式。

## 局部补丁 / 临时缓解
- `escapeshellarg()` 仅作补强，不能替代白名单和动作映射。
- WAF 关键字规则只能作为短期拦截层，不能作为长期主修法。

## 项目级联动提醒
- 若项目存在多个命令调用点，需联动统一到同一 PHP 执行封装和同一参数校验策略。
- 通常需要一起改：控制器入口、公共命令工具函数、异常返回封装、审计记录。
- 只修单个 `system/exec` 调用点而不修公共封装，会保留等价风险入口。

## 最小修补示例
项目级主线示例（推荐）：
```php
$action = $_GET['action'] ?? '';
$ip = $_GET['ip'] ?? '';
if ($action !== 'ping_check') {
    http_response_code(403);
    echo json_encode(['error' => 'bad action']);
    exit;
}
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    http_response_code(403);
    echo json_encode(['error' => 'invalid ip']);
    exit;
}
$cmd = 'ping -c 4 ' . escapeshellarg($ip); // escapeshellarg 仅作参数补强
system($cmd);
```

局部补丁示例（仅迁移窗口）：
```php
// 旧执行入口暂时无法下线时，仅可短期叠加严格参数校验与审计
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    http_response_code(403);
    exit;
}
system('ping -c 4 ' . escapeshellarg($ip));
```

迁移窗口结束后，应移除旧执行入口与过渡补丁分支，不应长期依赖 `escapeshellarg()` 兜底。

## 不推荐做法
- 不要把 `escapeshellarg()` 当项目级根治。
- 不要把 WAF 关键字黑名单当主方案。
- 不要把 `escapeshellarg()` 当成“长期临时缓解”。
- 不要直接 `die()` 破坏原有 API 响应格式。
- 不要继续让用户控制命令名或命令片段。

## 检索关键词
- `php command exec mainline`
- `php system exec shell_exec popen`
- `escapeshellarg transition only`
- `fixed command head allowlist`
