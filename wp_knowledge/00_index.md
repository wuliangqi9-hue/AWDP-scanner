# AWDP 修复约束知识库索引

本目录不是漏洞判定模板库，也不是题解库，而是“修复约束库”。推荐配合 `AWDP_RAG_MODE=repair_only` 使用：先由扫描器和模型完成定位，再由知识库约束“怎么修、怎么不修坏、哪些文件必须联动改”。

## 导航标签
- 文档角色: 导航文件
- 适用模式: repair_only
- 支持mitigation_only信号: 是
- 支持cross_file_risk信号: 是
- 支持chain_role信号: 是

## 统一使用规则
- 知识库只用于修复约束 / 修复复核，不单独立案。
- 优先最小补丁，不整文件重写。
- 不改变返回值类型、路由、鉴权入口和核心业务逻辑。
- API 接口尽量保持原有 JSON / HTTP 响应格式。
- 优先参数化、白名单、上下文变量、安全 API、框架原生能力。
- 黑名单、关键字拦截、脆弱正则最多只能作为临时缓解，不能作为项目级主线。

## 数据与输入处理（单点修复约束）
- `01_sqli_fix_wp.md`：SQL 注入修复约束
- `02_upload_fix_wp.md`：文件上传修复约束
- `07_ssrf_fix.md`：SSRF 修复约束
- `08_xss_fix.md`：XSS 修复约束
- `17_xxe_fix.md`：XXE 修复约束
- `18_variable_overwrite_fix.md`：变量覆盖 / parse_str / extract 修复约束
- `20_yaml_deserialization_fix.md`：YAML 非安全加载 / 反序列化修复约束

## 模板、执行与动态能力（按场景分工）
- `03_ssti_fix_wp.md`：通用 SSTI 修复约束
- `15_python_ssti_jinja_fix.md`：Python / Jinja SSTI 修复约束
- `21_dynamic_include_fix.md`：动态包含 / 动态模板选择修复约束
- `04_rce_eval_fix_wp.md`：通用动态执行 / eval / RCE 总则
- `11_command_injection_fix.md`：命令注入（参数列表化、shell=False、动作映射）
- `14_php_rce_waf_fix.md`：PHP 命令执行专项（`system/exec/shell_exec/popen`）

## 项目级联动与状态链修复
- `05_auth_logic_jwt_session_fix_wp.md`：JWT / Session / 鉴权状态链修复约束
- `09_deserialization_fix.md`：反序列化修复约束（主线迁移 vs 短期缓解）
- `16_cross_file_state_chain_fix.md`：跨文件状态链 / reader-writer 联动修复约束

## 对象、路径与压缩包
- `06_proto_pollution_fix_wp.md`：原型链污染修复约束
- `10_lfi_path_traversal_fix.md`：文件包含 / 路径穿越修复约束
- `13_zip_slip_path_traversal_fix.md`：Zip Slip / 解压路径穿越修复约束

## 框架与语言加固
- `12_java_node_hardening_fix.md`：Java / Node 通用加固约束
- `19_jndi_fastjson_fix.md`：JNDI / Fastjson / Java 反序列化型远程加载修复约束

## 使用建议
- 选用顺序建议：先看 family 主文档，再看语言/框架专项；若出现 `mitigation_only`、`reader/writer` 联动或跨文件一致性风险，再看项目级联动文档。
- 扫描器出现 `mitigation_only`、`reader/writer` 联动、跨文件一致性风险提示时，优先查“项目级联动与状态链修复”分组。
- 扫描器若识别到 `mitigation_only` / `reader/writer` / `chain_role` / `cross-file consistency risk` / `dynamic_include` / `yaml_deserialization`，应优先将这些信号拼入 repair query 再检索。
- 同一 `cookie/session/state` 在多个文件中读写时，不应只看单点 patch 文档，必须同时检查 reader 和 writer。
- 命令执行相关文档按职责选用：先看 `04` 定主线，再用 `11` 或 `14` 做语言场景落地。
- 反序列化相关文档按职责选用：先看 `09` 定迁移主线，再按 YAML / JNDI / Fastjson 场景细化到 `20` 或 `19`。
- 路径类文档按子场景选用：`10` 偏读取/下载/模板路径选择，`13` 偏解压落盘链路。
- 模板类文档按技术栈选用：通用优先 `03`，Python/Jinja 细节优先 `15`，动态包含场景看 `21`。
- 如果知识库内容与当前语言或业务场景不匹配，应允许忽略，不要强套模板。
