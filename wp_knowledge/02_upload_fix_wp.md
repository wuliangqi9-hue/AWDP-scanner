# 文件上传修复约束

## 机器可读标签
- 适用family: upload
- 适用语言: php, python, java, node, go
- 文档角色: 主文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 是

场景分流提示：本文件用于上传链路约束；若风险点在解压落盘，请优先看 `13_zip_slip_path_traversal_fix.md`。

## 漏洞判断信号
- 直接使用用户提供的文件名、后缀、MIME 或保存路径。
- 上传目录位于 Web 可执行路径，或落盘后可直接访问执行。
- 只校验 `Content-Type`、只做后缀包含判断、未做重命名。

## 项目级主线修法
- 主线是扩展名白名单 + 安全落盘目录 + 随机文件名。
- 优先使用框架提供的安全文件名工具或自定义白名单映射。
- 上传成功或失败后的响应结构要保持原样。
- 如果业务必须保留原文件名，至少只用于展示，不直接作为落盘名。

## 局部补丁 / 临时缓解
- 过渡期可先收紧上传类型、限制上传大小与频率，并关闭可执行目录访问。
- 仅靠 MIME 或后缀黑名单属于短期降险，不能替代主线改造。

## 项目级联动提醒
- 通常需要一起改：上传入口、落盘目录策略、文件元数据入库、预览/下载读取链路。
- 只修上传入口而不修后续读取与执行路径，会留下跨文件一致性风险。

## 最小修补示例
项目级主线示例（推荐）：
```php
$allow = ['jpg', 'jpeg', 'png', 'pdf'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allow, true)) {
    http_response_code(403);
    echo json_encode(['error' => 'file type not allowed']);
    exit;
}
$safeName = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], '/srv/uploads/' . $safeName);
```

## 不推荐做法
- 不要仅依赖 MIME / `Content-Type`。
- 不要只做字符串替换式后缀过滤。
- 不要把上传点整体改成“禁用所有上传”而破坏业务。

## 检索关键词
- `upload security mainline`
- `extension allowlist`
- `safe upload filename`
- `isolated upload directory`
