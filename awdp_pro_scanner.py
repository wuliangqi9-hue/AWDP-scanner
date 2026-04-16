import ast
import json
import os
import py_compile
import re
import shutil
import subprocess
import tempfile
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


def _load_local_dotenv():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dotenv_path = os.path.join(script_dir, ".env")
    if not os.path.isfile(dotenv_path):
        return False
    if load_dotenv is None:
        print("注意: 检测到 .env，但未安装 python-dotenv，当前不会自动加载该文件。")
        return False
    load_dotenv(dotenv_path=dotenv_path, override=False)
    return True


_load_local_dotenv()

os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
warnings.filterwarnings("ignore", category=UserWarning)

try:
    from langchain_chroma import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings

    HAS_RAG = True
except ImportError:
    HAS_RAG = False


# ==========================================
# 1. 基础配置与环境变量
# ==========================================
def _resolve_local_path(path_value):
    if os.path.isabs(path_value):
        return path_value
    return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), path_value))


def _get_env_int(name, default, minimum=1):
    raw_value = os.getenv(name, str(default)).strip()
    try:
        value = int(raw_value)
    except ValueError:
        return default
    return max(minimum, value)


def _get_env_float(name, default, minimum=0.0):
    raw_value = os.getenv(name, str(default)).strip()
    try:
        value = float(raw_value)
    except ValueError:
        return default
    return max(minimum, value)


def _get_env_bool(name, default=False):
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _get_env_csv_set(name, default=""):
    raw_value = os.getenv(name, default)
    return {item.strip().lower() for item in str(raw_value or "").split(",") if item.strip()}


def _utc_timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIRECTORY = os.path.join(SCRIPT_DIR, "target_code")
DB_DIRECTORY = os.path.join(SCRIPT_DIR, "chroma_db")
DB_META_PATH = os.path.join(DB_DIRECTORY, ".awdp_db_meta.json")

EMBED_MODEL_NAME = os.getenv("AWDP_EMBED_MODEL_NAME", "all-MiniLM-L6-v2").strip() or "all-MiniLM-L6-v2"
EMBED_MODEL_PATH = _resolve_local_path(
    os.getenv("AWDP_EMBED_MODEL_PATH", os.path.join("models", EMBED_MODEL_NAME)).strip()
)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_API_URL = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE_URL}/api/tags"
OLLAMA_SHOW_URL = f"{OLLAMA_BASE_URL}/api/show"
MODEL_NAME = os.getenv("AWDP_MODEL_NAME", "qwen2.5-coder:14b").strip() or "qwen2.5-coder:14b"

RAG_MODE = (os.getenv("AWDP_RAG_MODE", "repair_only").strip().lower() or "repair_only")
if RAG_MODE not in {"off", "prejudge", "repair_only"}:
    RAG_MODE = "repair_only"

RAG_DB_ROLE_EXPECTED = "repair_constraints_only"
DETECTION_PROMPT_VERSION = "detection-v5"
REPAIR_PROMPT_VERSION = "repair-human-v2"
REPORT_FORMAT_VERSION = "v7"

MAX_WORKERS = _get_env_int("AWDP_MAX_WORKERS", 1)
OLLAMA_TIMEOUT = _get_env_int("AWDP_OLLAMA_TIMEOUT", 180)
BASE_NUM_PREDICT = _get_env_int("AWDP_OLLAMA_NUM_PREDICT", 768)
DETECTION_NUM_PREDICT = _get_env_int("AWDP_DETECTION_NUM_PREDICT", min(512, BASE_NUM_PREDICT))
REPAIR_NUM_PREDICT = _get_env_int("AWDP_REPAIR_NUM_PREDICT", BASE_NUM_PREDICT)
MODEL_RETRIES = _get_env_int("AWDP_MODEL_RETRIES", 2)
FULL_FILE_MODEL_CHAR_LIMIT = _get_env_int("AWDP_FULL_FILE_MODEL_CHAR_LIMIT", 6000)
MAX_MODEL_INPUT_CHARS = _get_env_int("AWDP_MAX_MODEL_INPUT_CHARS", 9000)
SNIPPET_CONTEXT_LINES = _get_env_int("AWDP_SNIPPET_CONTEXT_LINES", 12)
RAG_TOP_K = _get_env_int("AWDP_RAG_TOP_K", 2)
RAG_SCORE_THRESHOLD = _get_env_float("AWDP_RAG_SCORE_THRESHOLD", 1.2)
MIN_VULN_CONFIDENCE = _get_env_float("AWDP_MIN_VULN_CONFIDENCE", 0.7)

ALLOWED_EXTENSIONS = {".php", ".py", ".java", ".js", ".go", ".jsp"}
SCAN_UPLOADS = _get_env_bool("AWDP_SCAN_UPLOADS", True)
IGNORE_DIRS = {"vendor", "node_modules", ".git", "static", "images", "__pycache__"}
if not SCAN_UPLOADS:
    IGNORE_DIRS.add("uploads")
IGNORE_DIRS.update(_get_env_csv_set("AWDP_EXTRA_IGNORE_DIRS", ""))


def _compiled_patterns(patterns):
    return [(re.compile(pattern, re.I), label) for pattern, label in patterns]


def _compile_regexes(patterns):
    return [re.compile(pattern, re.I) for pattern in patterns]


LANGUAGE_RULES = {
    ".py": {
        "lang_name": "Python",
        "lang_hint": "不要改变 Flask/Django 路由、返回值类型、异常流程和关键中间件行为。",
        "danger_keywords": {
            "eval",
            "exec",
            "os",
            "subprocess",
            "popen",
            "sqlite3",
            "execute",
            "render_template_string",
            "pickle",
            "yaml",
            "unsafe_load",
            "requests",
            "httpx",
            "urllib",
            "urlopen",
            "open",
        },
        "input_sources": {
            "request",
            "args",
            "form",
            "json",
            "values",
            "headers",
            "cookies",
            "files",
            "input",
            "url",
            "data",
        },
        "patterns": _compiled_patterns(
            [
                (r"\b(eval|exec)\s*\(", "动态执行"),
                (r"\bos\.(system|popen)\s*\(", "命令执行"),
                (r"\bsubprocess\.(Popen|run|call|check_output|check_call)\s*\(", "子进程调用"),
                (r"render_template_string\s*\(", "模板注入"),
                (r"\.execute\s*\([^)]*(\+|%|format\s*\(|f[\"'])", "疑似拼接 SQL"),
                (r"\bpickle\.loads\s*\(", "反序列化"),
                (r"\byaml\.(unsafe_load|full_load)\s*\(", "YAML 反序列化"),
                (r"\byaml\.load\s*\((?![^)\n]*Loader\s*=\s*yaml\.SafeLoader)", "YAML 反序列化"),
                (r"\b(open|send_file)\s*\(", "目录穿越 / 文件访问"),
                (r"\.save\s*\(", "文件上传"),
                (r"\b(requests|httpx)\.(get|post|request)\s*\(", "SSRF / 外部请求"),
                (r"\burllib\.request\.urlopen\s*\(", "SSRF / 外部请求"),
            ]
        ),
    },
    ".php": {
        "lang_name": "PHP",
        "lang_hint": "不要改变原函数签名、路由行为和返回值类型，优先做最小补丁。",
        "danger_keywords": {
            "eval",
            "system",
            "exec",
            "shell_exec",
            "passthru",
            "mysqli_query",
            "query",
            "_FILES",
            "move_uploaded_file",
            "unserialize",
            "simplexml_load_string",
            "simplexml_load_file",
            "curl_exec",
            "curl_setopt",
            "extract",
            "parse_str",
        },
        "input_sources": {
            "_GET",
            "_POST",
            "_REQUEST",
            "_COOKIE",
            "_SERVER",
            "_FILES",
            "php://input",
            "file_get_contents",
        },
        "patterns": _compiled_patterns(
            [
                (r"\b(eval|system|exec|shell_exec|passthru)\s*\(", "命令执行"),
                (r"\b(mysqli_query|mysql_query)\s*\(", "疑似原始 SQL"),
                (r"->query\s*\(", "疑似原始 SQL"),
                (r"\b(include|require)(_once)?\s*\(", "动态包含"),
                (r"\bmove_uploaded_file\s*\(", "文件上传"),
                (r"\b(file_put_contents|fopen|copy|rename)\s*\(", "文件写入"),
                (r"\b(file_get_contents|readfile|fopen|SplFileObject)\s*\(", "目录穿越 / 文件访问"),
                (r"\bunserialize\s*\(", "反序列化"),
                (r"\b(simplexml_load_string|simplexml_load_file)\s*\(", "XXE"),
                (r"->loadXML\s*\(", "XXE"),
                (r"\b(curl_exec|curl_multi_exec)\s*\(", "SSRF / 外部请求"),
                (r"\bcurl_setopt\s*\([^)]*CURLOPT_URL", "SSRF / 外部请求"),
                (r"\bextract\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE|SERVER)\b", "变量覆盖"),
                (r"\bparse_str\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\b", "变量覆盖"),
                (r"\bparse_str\s*\([^,]+,\s*\$GLOBALS\b", "变量覆盖"),
            ]
        ),
    },
    ".js": {
        "lang_name": "JavaScript",
        "lang_hint": "不要随意改变 Node/Express 路由、异步流程和返回结构。",
        "danger_keywords": {
            "eval",
            "Function",
            "exec",
            "spawn",
            "innerHTML",
            "query",
            "__proto__",
            "Object.assign",
            "axios",
            "fetch",
            "fs",
            "path",
            "files",
        },
        "input_sources": {"req", "request", "body", "query", "params", "location", "document", "window", "files"},
        "patterns": _compiled_patterns(
            [
                (r"child_process\.(exec|execSync|spawn|spawnSync)\s*\(", "命令执行"),
                (r"\beval\s*\(", "动态执行"),
                (r"\bnew\s+Function\s*\(", "动态执行"),
                (r"innerHTML\s*=", "DOM XSS"),
                (r"\bquery\s*\([^)]*(\+|`)", "疑似拼接 SQL"),
                (r"(__proto__|prototype|constructor)\b", "原型链污染"),
                (r"\bObject\.assign\s*\(", "原型链污染"),
                (r"\b(fetch|axios\.(get|post|request)|http\.request|https\.request)\s*\(", "SSRF / 外部请求"),
                (r"\b(req\.files?|multer)\b", "文件上传"),
                (r"\bfs\.(readFile|readFileSync|createReadStream|open|stat)\s*\(", "目录穿越 / 文件访问"),
                (r"\bfs\.(writeFile|writeFileSync|createWriteStream|rename|renameSync)\s*\(", "文件写入"),
                (r"\bpath\.(join|resolve|normalize)\s*\(", "目录穿越 / 路径拼接"),
            ]
        ),
    },
    ".java": {
        "lang_name": "Java",
        "lang_hint": "不要修改 Servlet/Spring 路由映射、方法签名和框架关键配置。",
        "danger_keywords": {
            "Runtime",
            "ProcessBuilder",
            "Statement",
            "executeQuery",
            "executeUpdate",
            "readObject",
            "XMLDecoder",
            "lookup",
            "parseObject",
            "MultipartFile",
            "transferTo",
        },
        "input_sources": {"request", "getParameter", "getHeader", "getQueryString", "getCookies", "RequestBody", "body", "MultipartFile", "getPart"},
        "patterns": _compiled_patterns(
            [
                (r"Runtime\.getRuntime\(\)\.exec\s*\(", "命令执行"),
                (r"\bProcessBuilder\s*\(", "命令执行"),
                (r"\bStatement\s+\w+\s*=", "原始 SQL Statement"),
                (r"\.execute(Query|Update)?\s*\([^)]*(\+|StringBuilder)", "疑似拼接 SQL"),
                (r"\b(getPart|transferTo)\s*\(", "文件上传"),
                (r"\b(Files\.write|FileOutputStream)\b", "文件写入"),
                (r"\breadObject\s*\(", "反序列化"),
                (r"\bXMLDecoder\b", "反序列化"),
                (r"\blookup\s*\(", "JNDI / 外部查找"),
                (r"\b(parseObject|parseArray)\s*\(", "Fastjson 反序列化"),
            ]
        ),
    },
    ".go": {
        "lang_name": "Go",
        "lang_hint": "不要改变 HTTP handler、状态码和主要数据结构。",
        "danger_keywords": {"exec", "template", "Query", "Command", "Unmarshal", "Decode", "http.Get"},
        "input_sources": {"FormValue", "Query", "Header", "Body", "body", "URL", "PostForm"},
        "patterns": _compiled_patterns(
            [
                (r"exec\.Command\s*\(", "命令执行"),
                (r"template\.(Must|New)\s*\(", "模板渲染"),
                (r"\b(Query|Exec)\s*\([^)]*(\+|fmt\.Sprintf)", "疑似拼接 SQL"),
                (r"\b(yaml|xml)\.Unmarshal\s*\(", "反序列化 / 复杂解码"),
                (r"\bgob\.NewDecoder\s*\(", "反序列化 / 复杂解码"),
                (r"\bjson\.Unmarshal\s*\(", "JSON 解码"),
                (r"\bjson\.NewDecoder\s*\(", "JSON 解码"),
                (r"\bvar\s+\w+\s+(?:interface\{\}|any)\b", "泛型反序列化容器"),
                (r"\bmap\s*\[\s*string\s*\]\s*interface\{\}", "泛型反序列化容器"),
                (r"\bhttp\.(Get|Post)\s*\(", "SSRF / 外部请求"),
            ]
        ),
    },
    ".jsp": {
        "lang_name": "JSP",
        "lang_hint": "不要改变 JSP/Servlet 路由和容器关键行为。",
        "danger_keywords": {"Runtime", "Statement", "executeQuery", "out", "request"},
        "input_sources": {"request", "getParameter", "getHeader", "session", "body"},
        "patterns": _compiled_patterns(
            [
                (r"Runtime\.getRuntime\(\)\.exec\s*\(", "命令执行"),
                (r"\.execute(Query|Update)?\s*\([^)]*(\+|StringBuilder)", "疑似拼接 SQL"),
                (r"out\.print(ln)?\s*\(", "输出回显"),
            ]
        ),
    },
}


SECONDARY_LABEL_FAMILY_MAP = {
    "命令执行": "command_exec",
    "子进程调用": "command_exec",
    "SSRF / 外部请求": "ssrf",
    "XXE": "xxe",
    "YAML 反序列化": "deserialization",
    "变量覆盖": "variable_overwrite",
    "反序列化": "deserialization",
    "JNDI / 外部查找": "jndi",
    "Fastjson 反序列化": "jndi",
    "疑似原始 SQL": "sqli",
    "原始 SQL Statement": "sqli",
    "DOM XSS": "xss",
    "文件上传": "upload",
    "文件写入": "file_write",
    "目录穿越 / 文件访问": "path_traversal",
    "目录穿越 / 路径拼接": "path_traversal",
    "动态包含": "dynamic_include",
}


SECONDARY_RISK_RULES = {
    ".py": [
        {
            "family": "path_traversal",
            "name": "file_read",
            "summary": "疑似用户输入参与路径拼接或文件读取",
            "input_patterns": _compile_regexes(
                [
                    r"request\.(args|form|values|headers|cookies)",
                    r"\binput\s*\(",
                    r"sys\.argv",
                ]
            ),
            "sink_patterns": _compile_regexes(
                [
                    r"\bopen\s*\(",
                    r"\bsend_file\s*\(",
                    r"\bFileResponse\s*\(",
                ]
            ),
            "context_patterns": _compile_regexes(
                [
                    r"os\.path\.(join|normpath|abspath|realpath|commonpath)",
                    r"pathlib\.Path",
                ]
            ),
            "weak_patterns": _compile_regexes(
                [
                    r"replace\s*\(\s*['\"]\.\./['\"]",
                    r"replace\s*\(\s*['\"]\.\.\\['\"]",
                    r"\.\.\s+not\s+in",
                    r"startswith\s*\(",
                    r"re\.(sub|match|search)\s*\(",
                ]
            ),
            "notes": {
                "context": "检测到路径拼接或规范化处理",
                "weak": "存在黑名单式过滤或脆弱正则",
            },
        },
        {
            "family": "hardening",
            "name": "dynamic_import",
            "summary": "疑似用户输入参与动态模块加载",
            "input_patterns": _compile_regexes(
                [
                    r"request\.(args|form|values|headers|cookies)",
                    r"\binput\s*\(",
                    r"sys\.argv",
                ]
            ),
            "sink_patterns": _compile_regexes(
                [
                    r"\b__import__\s*\(",
                    r"importlib\.(import_module|reload)\s*\(",
                ]
            ),
            "context_patterns": _compile_regexes([r"format\s*\(", r"f[\"']", r"\+\s*[A-Za-z_][\w]*"]),
            "weak_patterns": _compile_regexes([r"replace\s*\(", r"startswith\s*\(", r"re\.(sub|match|search)\s*\("]),
            "notes": {
                "context": "模块名来自字符串拼接或格式化",
                "weak": "仅看到表面过滤，仍需人工确认加载目标是否受控",
            },
        },
    ],
    ".php": [
        {
            "family": "path_traversal",
            "name": "file_read",
            "summary": "疑似用户输入参与路径拼接或文件读取",
            "input_patterns": _compile_regexes([r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b"]),
            "sink_patterns": _compile_regexes(
                [
                    r"\b(file_get_contents|readfile|fopen|SplFileObject)\s*\(",
                    r"\b(move_uploaded_file)\s*\(",
                ]
            ),
            "context_patterns": _compile_regexes(
                [
                    r"\b(realpath|dirname|basename)\s*\(",
                    r"DIRECTORY_SEPARATOR",
                ]
            ),
            "weak_patterns": _compile_regexes(
                [
                    r"str_replace\s*\(\s*['\"]\.\./['\"]",
                    r"strpos\s*\([^)]*['\"]\.\.['\"]",
                    r"preg_replace\s*\([^)]*\.\.",
                    r"(rawurl|url)decode\s*\(",
                    r"iconv\s*\(",
                ]
            ),
            "notes": {
                "context": "检测到路径标准化、basename/realpath 或目录拼接",
                "weak": "存在黑名单式过滤、解码或编码转换",
            },
        },
        {
            "family": "upload",
            "related_families": ["file_write"],
            "name": "file_upload",
            "summary": "疑似上传文件名、类型或目标路径直接参与落盘",
            "input_patterns": _compile_regexes([r"\$_FILES\b"]),
            "sink_patterns": _compile_regexes([r"\bmove_uploaded_file\s*\(", r"\b(copy|rename)\s*\("]),
            "context_patterns": _compile_regexes(
                [
                    r"\$_FILES\[['\"][A-Za-z0-9_\-]+['\"]\]\[['\"](name|type|tmp_name|size)['\"]\]",
                    r"\b(upload|uploads|attachment|media|image|avatar)\b",
                    r"\b(pathinfo|basename)\s*\(",
                ]
            ),
            "weak_patterns": _compile_regexes(
                [
                    r"\$_FILES\[['\"][A-Za-z0-9_\-]+['\"]\]\[['\"]type['\"]\]",
                    r"\b(in_array|preg_match|strpos)\s*\(",
                    r"\b(pathinfo|basename)\s*\(",
                ]
            ),
            "notes": {
                "context": "检测到上传元数据、文件名或上传目录参与落盘",
                "weak": "仅看到 MIME/后缀局部校验或 basename/pathinfo，仍需确认是否已做随机文件名与隔离目录",
            },
        },
        {
            "family": "file_write",
            "related_families": ["upload", "path_traversal"],
            "name": "file_write",
            "summary": "疑似用户输入参与文件写入、覆盖或落盘路径选择",
            "input_patterns": _compile_regexes([r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"]),
            "sink_patterns": _compile_regexes([r"\b(file_put_contents|fopen|copy|rename)\s*\("]),
            "context_patterns": _compile_regexes(
                [
                    r"\b(realpath|dirname|basename|pathinfo)\s*\(",
                    r"DIRECTORY_SEPARATOR",
                    r"\b(upload|uploads|storage|cache|template|data)\b",
                ]
            ),
            "weak_patterns": _compile_regexes(
                [
                    r"str_replace\s*\(",
                    r"preg_replace\s*\(",
                    r"(rawurl|url)decode\s*\(",
                    r"\b(pathinfo|basename)\s*\(",
                ]
            ),
            "notes": {
                "context": "检测到写入 API 与路径/文件名处理逻辑",
                "weak": "仅看到表面过滤、basename/pathinfo 或解码逻辑，需人工确认写入根目录约束是否稳定",
            },
        },
        {
            "family": "dynamic_include",
            "related_families": ["path_traversal"],
            "name": "dynamic_include",
            "summary": "疑似用户输入参与动态包含或模板选择",
            "input_patterns": _compile_regexes([r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b"]),
            "sink_patterns": _compile_regexes([r"\b(include|require)(_once)?\s*\("]),
            "context_patterns": _compile_regexes(
                [
                    r"templates?",
                    r"views?",
                    r"\.php['\"]?\s*;",
                    r"DIRECTORY_SEPARATOR",
                    r"__DIR__",
                ]
            ),
            "weak_patterns": _compile_regexes(
                [
                    r"str_replace\s*\(",
                    r"basename\s*\(",
                    r"realpath\s*\(",
                    r"preg_replace\s*\(",
                    r"\.\s*\$[A-Za-z_][\w]*\s*\.\s*['\"]\.php['\"]",
                ]
            ),
            "notes": {
                "context": "检测到模板目录或动态模板后缀拼接",
                "weak": "仅看到局部过滤或包装，仍需人工复核是否为固定模板映射",
            },
        },
    ],
    ".js": [
        {
            "family": "path_traversal",
            "name": "file_read",
            "summary": "疑似用户输入参与文件读取或下载路径构造",
            "input_patterns": _compile_regexes([r"req\.(query|params|body|headers|cookies)"]),
            "sink_patterns": _compile_regexes(
                [
                    r"fs\.(readFile|readFileSync|createReadStream|open|stat)\s*\(",
                    r"res\.sendFile\s*\(",
                ]
            ),
            "context_patterns": _compile_regexes([r"path\.(join|resolve|normalize)\s*\("]),
            "weak_patterns": _compile_regexes(
                [
                    r"replace\s*\(\s*['\"]\.\./['\"]",
                    r"includes\s*\(\s*['\"]\.\.['\"]",
                    r"indexOf\s*\(\s*['\"]\.\.['\"]",
                    r"decodeURI(Component)?\s*\(",
                ]
            ),
            "notes": {
                "context": "检测到 path.join/resolve/normalize 等上下文",
                "weak": "存在黑名单式过滤或解码逻辑",
            },
        },
        {
            "family": "hardening",
            "name": "dynamic_import",
            "summary": "疑似用户输入参与动态 require/import",
            "input_patterns": _compile_regexes([r"req\.(query|params|body|headers|cookies)"]),
            "sink_patterns": _compile_regexes(
                [
                    r"\brequire\s*\(\s*(?!['\"])[^)]+",
                    r"\bimport\s*\(\s*(?!['\"])[^)]+",
                ]
            ),
            "context_patterns": _compile_regexes(
                [
                    r"path\.(join|resolve|normalize)\s*\(",
                    r"`[^`]*\$\{",
                    r"\+\s*[A-Za-z_$][\w$]*",
                ]
            ),
            "weak_patterns": _compile_regexes(
                [
                    r"replace\s*\(",
                    r"includes\s*\(\s*['\"]\.\.['\"]",
                    r"startsWith\s*\(",
                ]
            ),
            "notes": {
                "context": "模块路径来自拼接、模板字符串或 path API",
                "weak": "仅看到表面过滤，需人工确认动态加载目标是否固定",
            },
        },
    ],
    ".java": [
        {
            "family": "path_traversal",
            "name": "file_read",
            "summary": "疑似用户输入参与文件路径构造",
            "input_patterns": _compile_regexes([r"(getParameter|getHeader)\s*\("]),
            "sink_patterns": _compile_regexes(
                [
                    r"Files\.(readAllBytes|newInputStream)\s*\(",
                    r"new\s+File(InputStream|Reader)?\s*\(",
                ]
            ),
            "context_patterns": _compile_regexes([r"Paths\.get\s*\(", r"normalize\s*\("]),
            "weak_patterns": _compile_regexes([r"replace\s*\(\s*['\"]\.\./['\"]", r"contains\s*\(\s*['\"]\.\.['\"]"]),
            "notes": {
                "context": "检测到 Paths.get/normalize 等路径上下文",
                "weak": "存在黑名单式过滤",
            },
        },
        {
            "family": "hardening",
            "name": "dynamic_class_loading",
            "summary": "疑似用户输入参与动态类加载",
            "input_patterns": _compile_regexes([r"(getParameter|getHeader)\s*\("]),
            "sink_patterns": _compile_regexes([r"Class\.forName\s*\(", r"loadClass\s*\("]),
            "context_patterns": _compile_regexes([r"StringBuilder", r"\+\s*\w+", r"format\s*\("]),
            "weak_patterns": _compile_regexes([r"replace\s*\(", r"contains\s*\("]),
            "notes": {
                "context": "类名可能由字符串拼接得到",
                "weak": "仅看到表面过滤，需人工确认加载目标是否受控",
            },
        },
    ],
    ".go": [
        {
            "family": "path_traversal",
            "name": "file_read",
            "summary": "疑似用户输入参与文件路径构造",
            "input_patterns": _compile_regexes(
                [
                    r"FormValue\s*\(",
                    r"Query\(\)\.Get\s*\(",
                    r"Header\.Get\s*\(",
                ]
            ),
            "sink_patterns": _compile_regexes(
                [
                    r"os\.(Open|ReadFile)\s*\(",
                    r"ioutil\.ReadFile\s*\(",
                ]
            ),
            "context_patterns": _compile_regexes([r"filepath\.(Join|Clean|Abs)\s*\("]),
            "weak_patterns": _compile_regexes(
                [
                    r"strings\.Replace[^\\n]*\.\.",
                    r"Contains\s*\([^)]*['\"]\.\.['\"]",
                ]
            ),
            "notes": {
                "context": "检测到 filepath.Join/Clean/Abs",
                "weak": "存在黑名单式过滤",
            },
        }
    ],
    ".jsp": [
        {
            "family": "path_traversal",
            "name": "file_read",
            "summary": "疑似用户输入参与文件路径构造或包含",
            "input_patterns": _compile_regexes([r"request\.(getParameter|getHeader)\s*\("]),
            "sink_patterns": _compile_regexes(
                [
                    r"getResourceAsStream\s*\(",
                    r"Files\.(readAllBytes|newInputStream)\s*\(",
                    r"new\s+FileInputStream\s*\(",
                ]
            ),
            "context_patterns": _compile_regexes([r"Paths\.get\s*\(", r"normalize\s*\("]),
            "weak_patterns": _compile_regexes([r"replace\s*\(\s*['\"]\.\./['\"]", r"contains\s*\(\s*['\"]\.\.['\"]"]),
            "notes": {
                "context": "检测到路径规范化逻辑",
                "weak": "存在黑名单式过滤",
            },
        }
    ],
}


BOUNDARY_COMBO_RULES = {
    ".py": {
        "input_patterns": _compile_regexes(
            [
                r"request\.(args|form|values|headers|cookies)",
                r"\binput\s*\(",
                r"sys\.argv",
            ]
        ),
        "context_patterns": _compile_regexes(
            [
                r"os\.path\.(join|normpath|abspath|realpath|commonpath)",
                r"pathlib\.Path",
                r"\bbasename\s*\(",
                r"\bdirname\s*\(",
            ]
        ),
        "weak_patterns": _compile_regexes(
            [
                r"replace\s*\(",
                r"startswith\s*\(",
                r"\.\.\s+not\s+in",
                r"re\.(sub|match|search)\s*\(",
                r"(url|unquote|quote|decode|encode)",
            ]
        ),
        "sink_patterns": _compile_regexes(
            [
                r"\bopen\s*\(",
                r"\bsend_file\s*\(",
                r"\bFileResponse\s*\(",
            ]
        ),
    },
    ".php": {
        "input_patterns": _compile_regexes([r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b"]),
        "context_patterns": _compile_regexes(
            [
                r"\b(realpath|dirname|basename)\s*\(",
                r"DIRECTORY_SEPARATOR",
                r"\b(normalize|resolve)\s*\(",
            ]
        ),
        "weak_patterns": _compile_regexes(
            [
                r"str_replace\s*\(",
                r"preg_replace\s*\(",
                r"strpos\s*\(",
                r"(rawurl|url)decode\s*\(",
                r"iconv\s*\(",
            ]
        ),
        "sink_patterns": _compile_regexes(
            [
                r"\b(file_get_contents|readfile|fopen|SplFileObject)\s*\(",
                r"\b(include|require)(_once)?\s*\(",
            ]
        ),
    },
}


WRITE_CHAIN_CANDIDATE_RULES = {
    ".php": {
        "input_patterns": _compile_regexes([r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b"]),
        "format_patterns": _compile_regexes(
            [
                r"\bserialize\s*\(",
                r"\bjson_encode\s*\(",
                r"\bbase64_encode\s*\(",
                r"\byaml_(emit|dump)\s*\(",
            ]
        ),
        "write_patterns": _compile_regexes(
            [
                r"\bsetcookie\s*\(",
                r"\$_SESSION\[['\"][A-Za-z0-9_\-]+['\"]\]\s*=",
                r"\$_COOKIE\[['\"][A-Za-z0-9_\-]+['\"]\]\s*=",
                r"<input[^>]*type=['\"]hidden['\"][^>]*name=['\"][A-Za-z0-9_\-]+['\"]",
            ]
        ),
    },
    ".py": {
        "input_patterns": _compile_regexes([r"request\.(args|form|values|headers|cookies)", r"\binput\s*\("]),
        "format_patterns": _compile_regexes(
            [
                r"\bjson\.dumps\s*\(",
                r"\bbase64\.(b64encode|urlsafe_b64encode)\s*\(",
                r"\byaml\.(dump|safe_dump)\s*\(",
                r"\bpickle\.dumps\s*\(",
            ]
        ),
        "write_patterns": _compile_regexes(
            [
                r"\.set_cookie\s*\(",
                r"\bsession\[['\"][A-Za-z0-9_\-]+['\"]\]\s*=",
            ]
        ),
    },
    ".js": {
        "input_patterns": _compile_regexes([r"req\.(query|params|body|headers|cookies)"]),
        "format_patterns": _compile_regexes(
            [
                r"JSON\.stringify\s*\(",
                r"\b(btoa|Buffer\.from)\s*\(",
                r"\byaml\.(dump|stringify)\s*\(",
            ]
        ),
        "write_patterns": _compile_regexes(
            [
                r"res\.cookie\s*\(",
                r"(sessionStorage|localStorage)\.setItem\s*\(",
                r"document\.cookie\s*=",
            ]
        ),
    },
}


# 高危 Sink 兜底规则:
# 1. 仅在模型给出 safe 判定后触发。
# 2. 命中极高危 Sink，且同一局部代码块中没有明显过滤/约束函数时，
#    强制把 safe 提升为 needs_manual_review，避免 AI 因上下文理解偏差漏掉明显危险点。
# 3. 该机制用于“收漏”而不是“直接定罪”，命中后默认进入人工复核，不直接提升为高危。
# 4. 上传、文件写入、路径读取这类业务常见操作，优先结合约束模式与 secondary risk 分级判断，
#    避免把普通日志写入、缓存写入、受控上传流程一刀切升级为高危。
HARD_OVERRIDE_RULES = {
    ".php": [
        {
            "pattern": re.compile(r"\bmove_uploaded_file\s*\(", re.I),
            "family": "upload",
            "vuln_type": "Unsafe file upload",
            "label": "move_uploaded_file",
        },
        {
            "pattern": re.compile(r"\bunserialize\s*\(", re.I),
            "family": "deserialization",
            "vuln_type": "Unsafe deserialization",
            "label": "unserialize",
        },
        {
            "pattern": re.compile(r"\b(eval|system|exec|shell_exec|passthru)\s*\(", re.I),
            "family": "command_exec",
            "vuln_type": "Command execution / RCE",
            "label": "dangerous_exec",
        },
        {
            "pattern": re.compile(r"\bfile_put_contents\s*\(", re.I),
            "family": "file_write",
            "vuln_type": "Unsafe file write",
            "label": "file_put_contents",
        },
        {
            "pattern": re.compile(r"\b(include|require)(_once)?\s*\(", re.I),
            "family": "dynamic_include",
            "vuln_type": "Dynamic include / template path",
            "label": "dynamic_include",
        },
    ],
    ".py": [
        {
            "pattern": re.compile(r"\b(eval|exec)\s*\(", re.I),
            "family": "command_exec",
            "vuln_type": "Command execution / RCE",
            "label": "dangerous_exec",
        },
        {
            "pattern": re.compile(r"\bpickle\.loads\s*\(", re.I),
            "family": "deserialization",
            "vuln_type": "Unsafe deserialization",
            "label": "pickle.loads",
        },
    ],
    ".js": [
        {
            "pattern": re.compile(r"\b(eval|Function)\s*\(", re.I),
            "family": "command_exec",
            "vuln_type": "Command execution / RCE",
            "label": "dynamic_exec",
        },
        {
            "pattern": re.compile(r"child_process\.(exec|execSync)\s*\(", re.I),
            "family": "command_exec",
            "vuln_type": "Command execution / RCE",
            "label": "child_process.exec",
        },
    ],
    ".java": [
        {
            "pattern": re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(", re.I),
            "family": "command_exec",
            "vuln_type": "Command execution / RCE",
            "label": "Runtime.exec",
        },
        {
            "pattern": re.compile(r"\bProcessBuilder\s*\(", re.I),
            "family": "command_exec",
            "vuln_type": "Command execution / RCE",
            "label": "ProcessBuilder",
        },
        {
            "pattern": re.compile(r"\breadObject\s*\(", re.I),
            "family": "deserialization",
            "vuln_type": "Unsafe deserialization",
            "label": "readObject",
        },
        {
            "pattern": re.compile(r"\bXMLDecoder\b", re.I),
            "family": "deserialization",
            "vuln_type": "Unsafe deserialization",
            "label": "XMLDecoder",
        },
        {
            "pattern": re.compile(r"\blookup\s*\(", re.I),
            "family": "jndi",
            "vuln_type": "JNDI / Fastjson",
            "label": "lookup",
        },
        {
            "pattern": re.compile(r"\b(parseObject|parseArray)\s*\(", re.I),
            "family": "jndi",
            "vuln_type": "JNDI / Fastjson",
            "label": "parseObject",
        },
    ],
    ".go": [
        {
            "pattern": re.compile(r"\bexec\.Command\s*\(", re.I),
            "family": "command_exec",
            "vuln_type": "Command execution / RCE",
            "label": "exec.Command",
        },
        {
            "pattern": re.compile(r"\b(yaml|xml)\.Unmarshal\s*\(", re.I),
            "family": "deserialization",
            "vuln_type": "Unsafe deserialization",
            "label": "yaml/xml.Unmarshal",
        },
        {
            "pattern": re.compile(r"\bgob\.NewDecoder\s*\(", re.I),
            "family": "deserialization",
            "vuln_type": "Unsafe deserialization",
            "label": "gob.NewDecoder",
        },
    ],
    ".jsp": [
        {
            "pattern": re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(", re.I),
            "family": "command_exec",
            "vuln_type": "Command execution / RCE",
            "label": "Runtime.exec",
        },
        {
            "pattern": re.compile(r"\.execute(Query|Update)?\s*\([^)]*(\+|StringBuilder)", re.I),
            "family": "sqli",
            "vuln_type": "SQL injection",
            "label": "Statement.execute",
        },
        {
            "pattern": re.compile(r"request\.getRequestDispatcher\s*\([^)]*\)\.(include|forward)\s*\(", re.I),
            "family": "dynamic_include",
            "vuln_type": "Dynamic include / template path",
            "label": "RequestDispatcher.include",
        },
        {
            "pattern": re.compile(r"<jsp:include\b[^>]*page\s*=", re.I),
            "family": "dynamic_include",
            "vuln_type": "Dynamic include / template path",
            "label": "jsp:include",
        },
        {
            "pattern": re.compile(r"new\s+File(InputStream|Reader)\s*\(", re.I),
            "family": "path_traversal",
            "vuln_type": "Path traversal / unsafe file read",
            "label": "FileInputStream",
        },
    ],
}


HARD_OVERRIDE_CONSTRAINT_PATTERNS = {
    "upload": _compile_regexes(
        [
            r"\b(allow|allowed|whitelist|allowlist|safe_ext|safe_mime|allowed_exts?|allowed_types?)\b",
            r"\b(pathinfo|finfo_file|mime_content_type|secure_filename|getClientOriginalExtension)\s*\(",
            r"\b(random_bytes|bin2hex|uniqid|uuid|sha1|md5)\s*\(",
            r"\b(upload_root|upload_dir|storage_root|base_dir)\b",
        ]
    ),
    "command_exec": _compile_regexes(
        [
            r"\b(allowlist|whitelist|allowed_(cmd|command|action)s?|command_map|cmd_map|action_map)\b",
            r"\bshell\s*=\s*False\b",
            r"\bsubprocess\.(run|Popen)\s*\(\s*\[",
            r"\bexec\.Command\s*\(\s*['\"][A-Za-z0-9_./-]+['\"]",
            r"\bProcessBuilder\s*\(\s*(?:new\s+String\[\]\s*\{)?\s*['\"][A-Za-z0-9_./-]+['\"]",
        ]
    ),
    "deserialization": _compile_regexes(
        [
            r"\ballowed_classes\b",
            r"\bSafeLoader\b",
            r"\byaml\.safe_load\s*\(",
            r"\b(json_decode|json\.loads|json\.parse|json\.Unmarshal)\s*\(",
            r"\b(dto|schema|field_whitelist|allowed_fields?)\b",
            r"\b(autoTypeSupport|autotype)\s*=\s*false\b",
        ]
    ),
    "jndi": _compile_regexes(
        [
            r"\b(autoTypeSupport|autotype)\s*=\s*false\b",
            r"\bsetAutoTypeSupport\s*\(\s*false\s*\)",
            r"\b(allowlist|whitelist|allowed_classes|allowed_hosts?|trusted_factory)\b",
        ]
    ),
    "path_traversal": _compile_regexes(
        [
            r"\b(realpath|commonpath|abspath|safe_join)\s*\(",
            r"\b(base_dir|basedir|base_path|allowed_dir|root_dir|storage_root|upload_root|template_root)\b",
            r"\b(strings\.HasPrefix|HasPrefix|startswith)\s*\(",
            r"\$[a-zA-Z_]\w*\s*\[\s*\$[a-zA-Z_]\w*\s*\]",
            r"\barray_key_exists\s*\(",
        ]
    ),
    "file_write": _compile_regexes(
        [
            r"\b(allowlist|whitelist|allowed_files?|file_map|safe_targets?)\b",
            r"\b(array_key_exists|isset)\s*\([^)]*(allowed|file_map|safe_targets?)",
            r"\b(realpath|commonpath|abspath|safe_join)\s*\(",
            r"\b(base_dir|basedir|base_path|allowed_dir|root_dir|storage_root|upload_root)\b",
            r"\b(strings\.HasPrefix|HasPrefix|startswith)\s*\(",
            r"\$[a-zA-Z_]\w*\s*\[\s*\$[a-zA-Z_]\w*\s*\]",
            r"\barray_key_exists\s*\(",
        ]
    ),
    "dynamic_include": _compile_regexes(
        [
            r"\b(allowlist|whitelist|allowed_templates?|allowed_views?|template_map|view_map|include_map|safe_templates?)\b",
            r"\b(in_array|array_key_exists)\s*\([^)]*(allowed|template_map|view_map|include_map)",
            r"\b(fixed_template|fixed_view|static_template|static_view)\b",
            r"\bgetRequestDispatcher\s*\(\s*['\"][A-Za-z0-9_./-]+['\"]",
            r"\$[a-zA-Z_]\w*\s*\[\s*\$[a-zA-Z_]\w*\s*\]",
            r"\barray_key_exists\s*\(",
        ]
    ),
    "sqli": _compile_regexes(
        [
            r"\bprepare\s*\(",
            r"\bPreparedStatement\b",
            r"\b(bind_param|bindValue|bindParam|setString|setInt|setLong)\s*\(",
            r"\b(parameterized|prepared statement|参数化|预处理)\b",
        ]
    ),
    "xss": _compile_regexes(
        [
            r"\b(htmlspecialchars|htmlentities|escapeHtml|escapeHTML|encodeForHTML)\s*\(",
            r"\b(textContent|innerText|createTextNode)\b",
            r"\b(autoescape|auto_escape)\b",
        ]
    ),
}

HARD_OVERRIDE_CONSTRAINT_HINTS = {
    "upload": "扩展名白名单、随机文件名、隔离上传目录或 MIME/内容校验",
    "command_exec": "命令白名单、动作映射、固定命令头或非 shell 参数列表",
    "deserialization": "allowed_classes / safe_load / DTO / JSON 迁移约束",
    "jndi": "AutoType 关闭、受控工厂或类白名单约束",
    "path_traversal": "realpath/commonpath/base dir/safe_join 根路径约束",
    "file_write": "写入根目录约束、safe_join 或前缀校验",
    "dynamic_include": "固定模板映射、白名单视图选择或受控 include map",
    "sqli": "预处理语句、参数绑定或参数化查询",
    "xss": "上下文编码、escape API 或 textContent/innerText 输出",
}

HARD_OVERRIDE_CONTEXT_WINDOWS = {
    "upload": (4, 6),
    "command_exec": (3, 5),
    "deserialization": (4, 6),
    "jndi": (4, 6),
    "path_traversal": (4, 6),
    "file_write": (4, 6),
    "dynamic_include": (4, 6),
    "sqli": (3, 5),
    "xss": (3, 4),
}

PATH_ROOT_CONSTRAINT_PATTERNS = _compile_regexes([r"\b(realpath|commonpath|abspath|safe_join)\s*\("])
PATH_BASE_DIR_PATTERNS = _compile_regexes([r"\b(base_dir|basedir|base_path|allowed_dir|root_dir|storage_root|upload_root|template_root)\b"])
PATH_PREFIX_CHECK_PATTERNS = _compile_regexes([r"\b(strings\.HasPrefix|HasPrefix|startswith)\s*\("])

POLLUTED_SOURCE_CONTEXT_WINDOWS = (3, 5)


# 全局高污染源判定:
# 该标记不直接证明漏洞成立，只用于“边界放行”阶段降低过度保守的门槛。
PROJECT_POLLUTION_SAFE_PATTERNS = _compile_regexes(
    [
        r"\b(intval|floatval|boolval|abs|htmlspecialchars|htmlentities|filter_var)\s*\(",
        r"\b(realpath|basename|dirname|commonpath|abspath|safe_join)\s*\(",
        r"\b(allowlist|whitelist|schema|validator|validate|allowed_classes)\b",
        r"\b(json_decode|json.loads|json\.parse)\s*\(",
    ]
)

PROJECT_HIGH_POLLUTION_CONTAINERS = {
    "cookie",
    "query",
    "form",
    "request",
    "param",
    "header",
    "body",
    "json",
    "payload",
    "upload",
}


HEURISTIC_SOURCE_PATTERNS = {
    ".php": _compile_regexes([r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b", r"\$_SESSION\[['\"][A-Za-z0-9_\-]+['\"]\]"]),
    ".py": _compile_regexes([r"request\.(args|form|values|headers|cookies|json|data|files)\b", r"request\.get_json\s*\(", r"\binput\s*\("]),
    ".js": _compile_regexes([r"req\.(query|params|body|headers|cookies|files?)\b", r"document\.cookie\b"]),
    ".java": _compile_regexes([r"(getParameter|getHeader|getPart)\s*\(", r"MultipartFile\b", r"@RequestBody\b", r"(request|req)\.(getInputStream|getReader)\s*\("]),
    ".go": _compile_regexes([r"FormValue\s*\(", r"FormFile\s*\(", r"Query\(\)\.Get\s*\(", r"Header\.Get\s*\(", r"\.Body\b", r"json\.NewDecoder\(\s*\w+\.Body\s*\)\.Decode\s*\("]),
    ".jsp": _compile_regexes([r"request\.(getParameter|getHeader)\s*\(", r"request\.getInputStream\s*\(", r"request\.getReader\s*\("]),
}


ROOT_CAUSE_INPUT_PATTERNS = [
    (re.compile(r"\$_(?P<source>GET|POST|REQUEST|COOKIE|SERVER)\[['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\]", re.I), lambda m: f"{m.group('source').lower()}:{m.group('key').lower()}"),
    (re.compile(r"\$_FILES\[['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\]\[['\"](?P<field>name|type|tmp_name|size)['\"]\]", re.I), lambda m: f"upload:{m.group('key').lower()}.{m.group('field').lower()}"),
    (re.compile(r"\$_SESSION\[['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\]", re.I), lambda m: f"session:{m.group('key').lower()}"),
    (re.compile(r"request\.(?P<source>args|form|values|headers|cookies)\.get\(\s*['\"](?P<key>[A-Za-z0-9_\-]+)['\"]", re.I), lambda m: f"{m.group('source').lower()}:{m.group('key').lower()}"),
    (re.compile(r"request\.(?P<source>args|form|values|headers|cookies)\[['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\]", re.I), lambda m: f"{m.group('source').lower()}:{m.group('key').lower()}"),
    (re.compile(r"request\.(?P<source>json|data)\.get\(\s*['\"](?P<key>[A-Za-z0-9_\-]+)['\"]", re.I), lambda m: f"{m.group('source').lower()}:{m.group('key').lower()}"),
    (re.compile(r"request\.(?P<source>json|data)\[['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\]", re.I), lambda m: f"{m.group('source').lower()}:{m.group('key').lower()}"),
    (re.compile(r"request\.files\[['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\]", re.I), lambda m: f"upload:{m.group('key').lower()}"),
    (re.compile(r"request\.get_json\s*\(\s*\)\.get\(\s*['\"](?P<key>[A-Za-z0-9_\-]+)['\"]", re.I), lambda m: f"json:{m.group('key').lower()}"),
    (re.compile(r"(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*request\.(?P<source>json|data)\b", re.I), lambda m: f"{m.group('source').lower()}:{m.group('alias').lower()}"),
    (re.compile(r"(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*request\.get_json\s*\(", re.I), lambda m: f"json:{m.group('alias').lower()}"),
    (re.compile(r"req\.(?P<source>query|params|body|headers|cookies)\.(?P<key>[A-Za-z0-9_\-]+)", re.I), lambda m: f"{m.group('source').lower()}:{m.group('key').lower()}"),
    (re.compile(r"req\.(?P<source>query|params|body|headers|cookies)\[['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\]", re.I), lambda m: f"{m.group('source').lower()}:{m.group('key').lower()}"),
    (re.compile(r"req\.files?\[['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\]", re.I), lambda m: f"upload:{m.group('key').lower()}"),
    (re.compile(r"(?:const|let|var)\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*req\.(?P<source>body|query|params|headers|cookies)\b", re.I), lambda m: f"{m.group('source').lower()}:{m.group('alias').lower()}"),
    (re.compile(r"(getParameter|FormValue|Query\(\)\.Get)\(\s*['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\s*\)", re.I), lambda m: f"param:{m.group('key').lower()}"),
    (re.compile(r"getHeader\(\s*['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\s*\)", re.I), lambda m: f"header:{m.group('key').lower()}"),
    (re.compile(r"getPart\(\s*['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\s*\)", re.I), lambda m: f"upload:{m.group('key').lower()}"),
    (re.compile(r"@RequestBody\s+[A-Za-z_][\w<>\[\], ?]*\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*)", re.I), lambda m: f"body:{m.group('alias').lower()}"),
    (re.compile(r"request\.(getInputStream|getReader)\s*\(", re.I), lambda _m: "body"),
    (re.compile(r"json\.NewDecoder\(\s*\w+\.Body\s*\)\.Decode\(\s*&(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*\)", re.I), lambda m: f"body:{m.group('alias').lower()}"),
    (re.compile(r"(sessionStorage|localStorage)\.getItem\(\s*['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\s*\)", re.I), lambda m: f"{m.group(1).lower()}:{m.group('key').lower()}"),
]


ROOT_CAUSE_STATE_WRITE_PATTERNS = [
    (re.compile(r"\bsetcookie\s*\(\s*['\"](?P<key>[A-Za-z0-9_\-]+)['\"]", re.I), "cookie", lambda m: f"cookie:{m.group('key').lower()}"),
    (re.compile(r"\$_SESSION\[['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\]\s*=", re.I), "session", lambda m: f"session:{m.group('key').lower()}"),
    (re.compile(r"\$_COOKIE\[['\"](?P<key>[A-Za-z0-9_\-]+)['\"]\]\s*=", re.I), "cookie", lambda m: f"cookie:{m.group('key').lower()}"),
    (re.compile(r"res\.cookie\s*\(\s*['\"](?P<key>[A-Za-z0-9_\-]+)['\"]", re.I), "cookie", lambda m: f"cookie:{m.group('key').lower()}"),
    (re.compile(r"(sessionStorage|localStorage)\.setItem\(\s*['\"](?P<key>[A-Za-z0-9_\-]+)['\"]", re.I), None, lambda m: f"{m.group(1).lower()}:{m.group('key').lower()}"),
    (re.compile(r"document\.cookie\s*=\s*['\"]?(?P<key>[A-Za-z0-9_\-]+)=", re.I), "cookie", lambda m: f"cookie:{m.group('key').lower()}"),
    (re.compile(r"<input[^>]*type=['\"]hidden['\"][^>]*name=['\"](?P<key>[A-Za-z0-9_\-]+)['\"]", re.I), "hidden_field", lambda m: f"hidden_field:{m.group('key').lower()}"),
]


ROOT_CAUSE_FORMAT_PATTERNS = [
    (re.compile(r"\b(serialize|unserialize|pickle\.(loads|dumps)|readObject|gob\.NewDecoder|gob\.NewEncoder)\b", re.I), "serialized"),
    (re.compile(r"\b(json_encode|json_decode|json\.(loads|dumps)|json\.Unmarshal|json\.Marshal|JSON\.(parse|stringify))\b", re.I), "json"),
    (re.compile(r"\b(base64_encode|base64_decode|base64\.(b64encode|b64decode|urlsafe_b64encode|urlsafe_b64decode)|atob|btoa)\b", re.I), "base64"),
    (re.compile(r"\b(yaml\.(load|safe_load|dump|safe_dump)|yaml_(emit|parse)|yaml\.dump)\b", re.I), "yaml"),
    (re.compile(r"\b(rawurlencode|rawurldecode|urlencode|urldecode|quote|unquote|decodeURI(Component)?|encodeURI(Component)?)\b", re.I), "url_encoding"),
]


ROOT_CAUSE_API_PATTERNS = [
    (re.compile(r"\bserialize\s*\(", re.I), "serialize"),
    (re.compile(r"\bunserialize\s*\(", re.I), "unserialize"),
    (re.compile(r"\bjson_encode\s*\(", re.I), "json_encode"),
    (re.compile(r"\bbase64_encode\s*\(", re.I), "base64_encode"),
    (re.compile(r"\byaml\.(dump|safe_dump)\s*\(", re.I), "yaml.dump"),
    (re.compile(r"\bsetcookie\s*\(", re.I), "setcookie"),
    (re.compile(r"\bparse_str\s*\(", re.I), "parse_str"),
    (re.compile(r"\bextract\s*\(", re.I), "extract"),
    (re.compile(r"\b(include|require)(_once)?\s*\(", re.I), "include/require"),
    (re.compile(r"\bmove_uploaded_file\s*\(", re.I), "move_uploaded_file"),
    (re.compile(r"\bfile_put_contents\s*\(", re.I), "file_put_contents"),
    (re.compile(r"request\.getRequestDispatcher\s*\([^)]*\)\.(include|forward)\s*\(", re.I), "RequestDispatcher.include"),
    (re.compile(r"<jsp:include\b", re.I), "jsp:include"),
    (re.compile(r"\b(simplexml_load_string|simplexml_load_file)\s*\(", re.I), "simplexml"),
    (re.compile(r"->loadXML\s*\(", re.I), "loadXML"),
    (re.compile(r"\bDOMDocument\b", re.I), "DOMDocument"),
    (re.compile(r"\breadObject\s*\(", re.I), "readObject"),
    (re.compile(r"\bXMLDecoder\b", re.I), "XMLDecoder"),
    (re.compile(r"\blookup\s*\(", re.I), "lookup"),
    (re.compile(r"\b(parseObject|parseArray)\s*\(", re.I), "fastjson"),
    (re.compile(r"\byaml\.(unsafe_load|full_load|load)\s*\(", re.I), "yaml.load"),
    (re.compile(r"\b(curl_exec|curl_multi_exec|requests\.(get|post|request)|httpx\.(get|post|request)|http\.(Get|Post)|fetch|axios\.)", re.I), "outbound_request"),
    (re.compile(r"\b(file_get_contents|readfile|fopen|open|os\.Open|fs\.(readFile|readFileSync|createReadStream)|Files\.readAllBytes|Paths\.get)\b", re.I), "file_read"),
    (re.compile(r"\b(path\.(join|resolve|normalize)|os\.path\.(join|normpath|abspath|realpath)|filepath\.(Join|Clean|Abs))\b", re.I), "path_join"),
    (re.compile(r"\b(eval|exec|shell_exec|passthru|os\.system|subprocess\.(Popen|run|call)|exec\.Command|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b", re.I), "command_exec"),
]


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"


# ==========================================
# 2. 通用工具函数
# ==========================================
def _short_text(text, limit=220):
    value = re.sub(r"\s+", " ", str(text or "").strip())
    if not value:
        return ""
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _join_notes(*items):
    notes = []
    for item in items:
        value = _short_text(item, limit=320)
        if value and value not in notes:
            notes.append(value)
    return " | ".join(notes) if notes else "无"


def _sorted_unique(values):
    unique_values = {str(value).strip() for value in values if str(value or "").strip()}
    return sorted(unique_values)


def _split_csv_set(text):
    return {item.strip() for item in str(text or "").split(",") if item.strip()}


def _mode_nonempty(values, default=""):
    counts = {}
    best_value = ""
    best_count = 0
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        counts[text] = counts.get(text, 0) + 1
        if counts[text] > best_count or (counts[text] == best_count and len(text) > len(best_value)):
            best_value = text
            best_count = counts[text]
    return best_value or default


def _tokenize_for_similarity(text):
    return {token for token in re.findall(r"[a-zA-Z_][\w:-]{2,}", str(text or "").lower()) if token}


def _container_from_identifier(identifier):
    text = str(identifier or "").strip().lower()
    prefix = text.split(":", 1)[0]
    container_map = {
        "cookie": "cookie",
        "cookies": "cookie",
        "session": "session",
        "sessionstorage": "session_storage",
        "localstorage": "local_storage",
        "hidden_field": "hidden_field",
        "hidden": "hidden_field",
        "param": "param",
        "query": "query",
        "args": "query",
        "form": "form",
        "post": "form",
        "get": "query",
        "request": "request",
        "header": "header",
        "headers": "header",
        "body": "body",
        "json": "json",
        "payload": "payload",
        "data": "body",
    }
    return container_map.get(prefix, prefix if ":" in text else container_map.get(text, ""))


def _format_scalar_summary(value):
    if isinstance(value, bool):
        return "是" if value else "否"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value).strip()
    return _short_text(text, limit=80)


def _flatten_structured_summary(value, prefix="", depth=0, limit=8):
    if depth > 2:
        return []
    parts = []
    if isinstance(value, dict):
        for key, item in list(value.items())[:limit]:
            key_text = str(key).strip()
            next_prefix = f"{prefix}{key_text}" if not prefix else f"{prefix}.{key_text}"
            if isinstance(item, (dict, list)):
                parts.extend(_flatten_structured_summary(item, prefix=next_prefix, depth=depth + 1, limit=max(3, limit // 2)))
            else:
                parts.append(f"{next_prefix}: {_format_scalar_summary(item)}")
    elif isinstance(value, list):
        for index, item in enumerate(value[:limit], start=1):
            next_prefix = prefix or f"item{index}"
            if isinstance(item, (dict, list)):
                parts.extend(_flatten_structured_summary(item, prefix=next_prefix, depth=depth + 1, limit=max(3, limit // 2)))
            else:
                parts.append(f"{next_prefix}: {_format_scalar_summary(item)}")
    return parts


def _clean_evidence_text(text):
    raw_text = str(text or "").strip()
    if not raw_text:
        return ""
    if len(raw_text) < 2 or raw_text[0] not in "[{":
        return raw_text

    parsed = {}
    parsed_list = []
    try:
        loaded = json.loads(raw_text)
        if isinstance(loaded, dict):
            parsed = loaded
        elif isinstance(loaded, list):
            parsed_list = loaded
    except Exception:
        literal = _parse_mapping_literal(raw_text)
        if literal:
            parsed = literal
        else:
            try:
                loaded = ast.literal_eval(raw_text)
                if isinstance(loaded, dict):
                    parsed = loaded
                elif isinstance(loaded, list):
                    parsed_list = loaded
            except Exception:
                return raw_text

    structured = parsed if parsed else parsed_list
    if not structured:
        return raw_text

    parts = _flatten_structured_summary(structured)
    if not parts:
        return raw_text
    return "；".join(parts[:8])


def _meaningful_text(value):
    text = _short_text(value, limit=320)
    if text in {"", "无", "否", "未参与", "未进入修复阶段"}:
        return ""
    return text


def _has_any_pattern(text, patterns):
    return any(pattern.search(str(text or "")) for pattern in patterns or [])


def _strip_inline_comment(line, ext):
    return re.sub(r"(//.*|#.*)", "", str(line or "")).strip()


def _get_local_context(lines, center_line_no, ext, radius=3):
    if not lines:
        return {"text": "", "start_line": center_line_no, "end_line": center_line_no, "lines": []}

    start = max(1, center_line_no - radius)
    end = min(len(lines), center_line_no + radius)
    cleaned_lines = []
    for line_no in range(start, end + 1):
        cleaned = _strip_inline_comment(lines[line_no - 1], ext).strip()
        if cleaned:
            cleaned_lines.append(cleaned)
    return {
        "text": "\n".join(cleaned_lines),
        "start_line": start,
        "end_line": end,
        "lines": cleaned_lines,
    }


def _find_pattern_line_matches(code_content, patterns, ext):
    matches = []
    lines = code_content.splitlines()
    for line_no, raw_line in enumerate(lines, start=1):
        line = _strip_inline_comment(raw_line, ext)
        if not line.strip():
            continue
        for pattern in patterns or []:
            if pattern.search(line):
                matches.append((line_no, line.strip()))
                break
    return matches


def _normalize_override_family(family):
    return normalize_vuln_family(family) or str(family or "").strip().lower()


def _get_hard_override_constraint_patterns(family):
    normalized = _normalize_override_family(family)
    return HARD_OVERRIDE_CONSTRAINT_PATTERNS.get(normalized, [])


def _get_hard_override_constraint_hint(family):
    normalized = _normalize_override_family(family)
    return HARD_OVERRIDE_CONSTRAINT_HINTS.get(normalized, "相关白名单或安全约束")


def _get_hard_override_context_radii(family):
    normalized = _normalize_override_family(family)
    return HARD_OVERRIDE_CONTEXT_WINDOWS.get(normalized, (3, 5))


def _has_family_constraint_signal(text, family):
    local_text = str(text or "")
    normalized = _normalize_override_family(family)
    patterns = _get_hard_override_constraint_patterns(normalized)
    if _has_any_pattern(local_text, patterns):
        return True
    if normalized in {"path_traversal", "file_write"}:
        has_strong_root = _has_any_pattern(local_text, PATH_ROOT_CONSTRAINT_PATTERNS)
        has_base_dir = _has_any_pattern(local_text, PATH_BASE_DIR_PATTERNS)
        has_prefix_check = _has_any_pattern(local_text, PATH_PREFIX_CHECK_PATTERNS)
        return has_strong_root or (has_base_dir and has_prefix_check)
    return False


def _collect_stable_local_context(lines, center_line_no, ext, probes=None, primary_radius=3, fallback_radius=5):
    probes = probes or {}
    primary_context = _get_local_context(lines, center_line_no, ext, radius=primary_radius)
    signals = {name: bool(probe(primary_context.get("text", ""))) for name, probe in probes.items()}
    chosen_context = primary_context
    used_radius = primary_radius
    stage = "primary"

    needs_fallback = fallback_radius > primary_radius and (
        not primary_context.get("text") or any(not matched for matched in signals.values())
    )
    if needs_fallback:
        extended_context = _get_local_context(lines, center_line_no, ext, radius=fallback_radius)
        extended_signals = {name: bool(probe(extended_context.get("text", ""))) for name, probe in probes.items()}
        for name, matched in extended_signals.items():
            signals[name] = signals.get(name, False) or matched
        chosen_context = extended_context
        used_radius = fallback_radius
        stage = "extended"

    return {
        "context": chosen_context,
        "signals": signals,
        "used_radius": used_radius,
        "stage": stage,
    }


def _has_local_source_signal(text, ext, lang_ctx=None):
    local_text = str(text or "")
    if _has_any_pattern(local_text, HEURISTIC_SOURCE_PATTERNS.get(ext, [])):
        return True
    for access in collect_state_accesses(local_text, lang_ctx):
        if access.get("role") == "reader":
            return True
    return False


def _normalize_verdict(raw_value):
    value = str(raw_value or "").strip().lower()
    verdict_map = {
        "vulnerable": "vulnerable",
        "unsafe": "vulnerable",
        "yes": "vulnerable",
        "safe": "safe",
        "no": "safe",
        "not_vulnerable": "safe",
        "needs_manual_review": "needs_manual_review",
        "manual_review": "needs_manual_review",
        "review": "needs_manual_review",
        "uncertain": "needs_manual_review",
        "待人工复核": "needs_manual_review",
        "安全": "safe",
        "有漏洞": "vulnerable",
    }
    return verdict_map.get(value, "needs_manual_review")


def _normalize_confidence(raw_value):
    if isinstance(raw_value, (int, float)):
        return max(0.0, min(1.0, float(raw_value)))
    value = str(raw_value or "").strip().lower()
    confidence_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
    if value in confidence_map:
        return confidence_map[value]
    try:
        parsed = float(value)
    except ValueError:
        return 0.0
    if parsed > 1:
        parsed = parsed / 100.0
    return max(0.0, min(1.0, parsed))


def make_check_result(status, detail, tool=""):
    if status not in {"未执行", "通过", "失败"}:
        status = "未执行"
    return {
        "status": status,
        "detail": _short_text(detail or "无", limit=240) or "无",
        "tool": tool or "",
    }


def format_check_result(result):
    if not isinstance(result, dict):
        return _short_text(result or "无", limit=240) or "无"
    tool = f"[{result['tool']}] " if result.get("tool") else ""
    return f"{result.get('status', '未执行')}: {tool}{result.get('detail', '无')}"


def _relative_path(path_value):
    return os.path.relpath(path_value, start=SCRIPT_DIR)


# ==========================================
# 3. 元数据函数
# ==========================================
def load_db_metadata():
    if not os.path.exists(DB_META_PATH):
        return {}
    try:
        with open(DB_META_PATH, "r", encoding="utf-8") as meta_file:
            loaded = json.load(meta_file)
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


# ==========================================
# 4. Ollama / RAG 初始化
# ==========================================
def get_embedding_model_path(required=False):
    if os.path.isdir(EMBED_MODEL_PATH):
        return EMBED_MODEL_PATH

    message = (
        f"本地 embedding 模型目录不存在: {EMBED_MODEL_PATH}。"
        f"请将 `{EMBED_MODEL_NAME}` 放到脚本目录下的 models 目录，或设置 AWDP_EMBED_MODEL_PATH。"
    )
    if required:
        raise FileNotFoundError(message)
    print(f"{Colors.YELLOW}注意: {message}{Colors.RESET}")
    return None


def build_local_embeddings(required=False):
    if not HAS_RAG:
        if required:
            raise RuntimeError("缺少 langchain_chroma 或 langchain_huggingface，无法使用本地向量库。")
        print(f"{Colors.YELLOW}注意: RAG 依赖缺失，已降级为纯规则 + LLM 审计。{Colors.RESET}")
        return None

    model_path = get_embedding_model_path(required=required)
    if not model_path:
        return None

    try:
        return HuggingFaceEmbeddings(
            model_name=model_path,
            model_kwargs={"local_files_only": True},
        )
    except TypeError:
        return HuggingFaceEmbeddings(model_name=model_path)
    except Exception as exc:
        if required:
            raise RuntimeError(f"加载本地 embedding 模型失败: {exc}") from exc
        print(f"{Colors.YELLOW}注意: 本地 embedding 模型加载失败，已禁用 RAG。原因: {exc}{Colors.RESET}")
        return None


def check_ollama_status():
    print(f"{Colors.BLUE}正在检查本地 Ollama 服务与模型状态...{Colors.RESET}")
    try:
        response = requests.get(OLLAMA_TAGS_URL, timeout=5)
    except requests.exceptions.ConnectionError:
        print(f"{Colors.RED}错误: Ollama 服务未启动或不可达，请确认 {OLLAMA_BASE_URL} 可访问。{Colors.RESET}")
        return False
    except requests.exceptions.Timeout:
        print(f"{Colors.RED}错误: Ollama 服务请求超时，请确认服务是否卡死。{Colors.RESET}")
        return False
    except requests.RequestException as exc:
        print(f"{Colors.RED}错误: 检查 Ollama 服务时请求失败: {exc}{Colors.RESET}")
        return False

    if response.status_code != 200:
        print(f"{Colors.RED}错误: Ollama 服务可达，但模型列表请求失败，HTTP {response.status_code}。{Colors.RESET}")
        return False

    try:
        payload = response.json()
    except ValueError:
        print(f"{Colors.RED}错误: Ollama 服务可达，但 /api/tags 返回了无效 JSON。{Colors.RESET}")
        return False

    models = sorted({item.get("name", "").strip() for item in payload.get("models", []) if item.get("name")})
    if MODEL_NAME not in models:
        known_models = ", ".join(models[:8]) if models else "无"
        print(
            f"{Colors.RED}错误: Ollama 服务可达，但目标模型缺失: {MODEL_NAME}。"
            f" 当前已安装模型: {known_models}{Colors.RESET}"
        )
        return False

    try:
        show_response = requests.post(OLLAMA_SHOW_URL, json={"model": MODEL_NAME}, timeout=5)
    except requests.exceptions.Timeout:
        print(f"{Colors.RED}错误: Ollama 服务可达，但模型详情检查超时: {MODEL_NAME}{Colors.RESET}")
        return False
    except requests.RequestException as exc:
        print(f"{Colors.RED}错误: Ollama 服务可达，但模型详情请求失败: {exc}{Colors.RESET}")
        return False

    if show_response.status_code != 200:
        print(f"{Colors.RED}错误: Ollama 服务可达，但模型详情接口返回 HTTP {show_response.status_code}。{Colors.RESET}")
        return False

    print(f"{Colors.GREEN}OK: Ollama 服务可达，目标模型已就绪: {MODEL_NAME}{Colors.RESET}")
    return True


def init_vector_db(db_path):
    if RAG_MODE == "off":
        print(f"{Colors.YELLOW}注意: AWDP_RAG_MODE=off，已禁用本地知识库加载。{Colors.RESET}")
        return None
    if not HAS_RAG:
        print(f"{Colors.YELLOW}注意: RAG 依赖未安装，继续执行但不使用向量库。{Colors.RESET}")
        return None
    if not os.path.exists(db_path):
        print(f"{Colors.YELLOW}注意: 未找到向量库目录 [{db_path}]，继续执行但不使用 RAG。{Colors.RESET}")
        return None

    db_meta = load_db_metadata()
    stored_embed_path = str(db_meta.get("embedding_model_path") or "").strip()
    if stored_embed_path:
        normalized_stored = os.path.normcase(os.path.abspath(_resolve_local_path(stored_embed_path)))
        normalized_current = os.path.normcase(os.path.abspath(EMBED_MODEL_PATH))
        if normalized_stored != normalized_current:
            print(
                f"{Colors.YELLOW}注意: 向量库 embedding 路径与当前扫描配置不一致，已禁用 RAG。"
                f" 向量库={stored_embed_path}，当前={EMBED_MODEL_PATH}{Colors.RESET}"
            )
            return None

    stored_role = str(db_meta.get("knowledge_role") or "").strip()
    if stored_role and stored_role != RAG_DB_ROLE_EXPECTED:
        print(
            f"{Colors.YELLOW}注意: 向量库角色为 `{stored_role}`，与当前策略要求的 "
            f"`{RAG_DB_ROLE_EXPECTED}` 不一致，已禁用 RAG。{Colors.RESET}"
        )
        return None
    if not stored_role and db_meta:
        print(f"{Colors.YELLOW}注意: 向量库缺少 knowledge_role 元数据，建议重建后再使用。{Colors.RESET}")

    embeddings = build_local_embeddings(required=False)
    if embeddings is None:
        return None

    try:
        print(f"{Colors.BLUE}正在连接本地知识库...{Colors.RESET}")
        db = Chroma(persist_directory=db_path, embedding_function=embeddings)
        print(f"{Colors.GREEN}OK: 已启用本地 RAG 参考。{Colors.RESET}\n")
        return db
    except Exception as exc:
        print(f"{Colors.YELLOW}注意: 向量库加载失败，继续执行但不使用 RAG。原因: {exc}{Colors.RESET}\n")
        return None


# ==========================================
# 5. 预筛与代码片段提取
# ==========================================
def get_language_context(ext, code_content):
    rule = LANGUAGE_RULES.get(ext, {})
    cleaned_lines = [_strip_inline_comment(line, ext) for line in code_content.splitlines()]
    cleaned_content = "\n".join(cleaned_lines)
    words = set(re.findall(r"[a-zA-Z_][\w:./-]*", cleaned_content))
    keywords = sorted(words.intersection(rule.get("danger_keywords", set())))
    input_hits = sorted(words.intersection(rule.get("input_sources", set())))

    pattern_hits = []
    hit_lines = []
    pattern_line_map = {}
    for line_no, raw_line in enumerate(code_content.splitlines(), start=1):
        line = _strip_inline_comment(raw_line, ext)
        for pattern, label in rule.get("patterns", []):
            if pattern.search(line):
                hit_lines.append(line_no)
                if label not in pattern_hits:
                    pattern_hits.append(label)
                pattern_line_map.setdefault(label, []).append(line_no)

    return {
        "lang_name": rule.get("lang_name", ext.strip(".").upper() or "Unknown"),
        "lang_hint": rule.get("lang_hint", "不要改变业务逻辑、返回值类型和框架关键行为。"),
        "keywords": keywords,
        "input_hits": input_hits,
        "pattern_hits": pattern_hits,
        "hit_lines": sorted(set(hit_lines)),
        "pattern_line_map": {label: sorted(set(lines)) for label, lines in pattern_line_map.items()},
        "has_input": bool(input_hits),
    }


def extract_relevant_snippet(code_content, hit_lines):
    if len(code_content) <= FULL_FILE_MODEL_CHAR_LIMIT:
        return code_content, "full", "", ""

    lines = code_content.splitlines()
    if not lines:
        return "", "empty", "文件内容为空。", ""

    if not hit_lines:
        head = "\n".join(lines[: max(20, SNIPPET_CONTEXT_LINES * 2)])
        tail = "\n".join(lines[-max(20, SNIPPET_CONTEXT_LINES * 2) :])
        snippet = f"{head}\n\n...\n\n{tail}"
        note = f"文件较长（{len(code_content)} 字符），已截断为首尾片段。"
        if len(snippet) > MAX_MODEL_INPUT_CHARS:
            snippet = snippet[:MAX_MODEL_INPUT_CHARS]
            note += f" 片段仍较长，已进一步裁剪到 {MAX_MODEL_INPUT_CHARS} 字符。"
        return snippet, "truncated", note, "首尾片段"

    selected_ranges = []
    for line_no in hit_lines[:10]:
        start = max(1, line_no - SNIPPET_CONTEXT_LINES)
        end = min(len(lines), line_no + SNIPPET_CONTEXT_LINES)
        if selected_ranges and start <= selected_ranges[-1][1] + 1:
            selected_ranges[-1][1] = max(selected_ranges[-1][1], end)
        else:
            selected_ranges.append([start, end])

    snippet_chunks = []
    focus_parts = []
    for start, end in selected_ranges:
        snippet_chunks.append("\n".join(lines[start - 1 : end]))
        focus_parts.append(f"{start}-{end}")
    snippet = "\n\n...\n\n".join(snippet_chunks)
    note = f"文件较长，仅提取风险片段附近行 {', '.join(focus_parts)} 供模型分析。"
    if len(snippet) > MAX_MODEL_INPUT_CHARS:
        snippet = snippet[:MAX_MODEL_INPUT_CHARS]
        note += f" 片段超长，已裁剪到 {MAX_MODEL_INPUT_CHARS} 字符。"
    return snippet, "snippet", note, ", ".join(focus_parts)


def _match_any_patterns(code_content, patterns, ext=""):
    if not ext:
        return any(pattern.search(code_content) for pattern in patterns or [])
    return bool(_find_pattern_line_matches(code_content, patterns, ext))


def build_project_context(file_records):
    context = {
        "highly_polluted_identifiers": set(),
        "file_flags": {},
    }
    file_identifier_map = {}
    source_primary_radius, source_fallback_radius = POLLUTED_SOURCE_CONTEXT_WINDOWS
    for file_path, code_content in file_records:
        ext = os.path.splitext(file_path)[1].lower()
        lang_ctx = get_language_context(ext, code_content)
        file_identifiers = set()
        source_hits = _find_pattern_line_matches(code_content, HEURISTIC_SOURCE_PATTERNS.get(ext, []), ext)
        lines = code_content.splitlines()

        for line_no, line_text in source_hits:
            sampled = _collect_stable_local_context(
                lines,
                line_no,
                ext,
                probes={"has_identifier": lambda text: bool(extract_input_identifier(text or line_text, lang_ctx))},
                primary_radius=source_primary_radius,
                fallback_radius=source_fallback_radius,
            )
            local_context = sampled.get("context", {})
            identifier = extract_input_identifier(local_context.get("text") or line_text, lang_ctx)
            container = _container_from_identifier(identifier)
            if not identifier:
                continue
            file_identifiers.add(identifier)
            has_local_sanitizer = _has_any_pattern(local_context.get("text"), PROJECT_POLLUTION_SAFE_PATTERNS)
            if container in PROJECT_HIGH_POLLUTION_CONTAINERS and not has_local_sanitizer:
                context["highly_polluted_identifiers"].add(identifier)
        file_identifier_map[_relative_path(file_path)] = sorted(file_identifiers)

    for rel_path, identifiers in file_identifier_map.items():
        context["file_flags"][rel_path] = {
            "identifiers": identifiers,
            "has_highly_polluted_source": bool(set(identifiers).intersection(context["highly_polluted_identifiers"])),
        }
    return context


def _check_highly_polluted_source(code_content, lang_ctx, project_context, file_path):
    current_accesses = collect_state_accesses(code_content, lang_ctx)
    current_identifiers = {access.get("identifier", "") for access in current_accesses if access.get("identifier")}
    if project_context and current_identifiers.intersection(project_context.get("highly_polluted_identifiers", set())):
        return True
    rel_path = _relative_path(file_path)
    file_flag = ((project_context or {}).get("file_flags", {}) or {}).get(rel_path, {})
    if file_flag.get("has_highly_polluted_source"):
        return True

    ext = os.path.splitext(file_path)[1].lower()
    source_hits = _find_pattern_line_matches(code_content, HEURISTIC_SOURCE_PATTERNS.get(ext, []), ext)
    lines = code_content.splitlines()
    source_primary_radius, source_fallback_radius = POLLUTED_SOURCE_CONTEXT_WINDOWS
    for line_no, line_text in source_hits:
        sampled = _collect_stable_local_context(
            lines,
            line_no,
            ext,
            probes={"has_identifier": lambda text: bool(extract_input_identifier(text or line_text, lang_ctx))},
            primary_radius=source_primary_radius,
            fallback_radius=source_fallback_radius,
        )
        local_context = sampled.get("context", {})
        identifier = extract_input_identifier(local_context.get("text") or line_text, lang_ctx)
        container = _container_from_identifier(identifier)
        if container in PROJECT_HIGH_POLLUTION_CONTAINERS and not _has_any_pattern(local_context.get("text"), PROJECT_POLLUTION_SAFE_PATTERNS):
            return True
    return False


def _collect_hard_sink_context(ext, code_content, lang_ctx, is_source_highly_polluted=False):
    rules = HARD_OVERRIDE_RULES.get(ext, [])
    if not rules:
        return {"candidate": False, "summary": "", "line_numbers": [], "families": []}

    line_numbers = []
    families = []
    for rule in rules:
        for line_no, _line_text in _find_pattern_line_matches(code_content, [rule["pattern"]], ext):
            line_numbers.append(line_no)
            families.append(rule.get("family", ""))

    candidate = bool(line_numbers and (lang_ctx.get("has_input") or is_source_highly_polluted))
    summary = ""
    if candidate:
        family_labels = _sorted_unique(VULN_FAMILY_LABELS.get(_normalize_override_family(family), family) for family in families if family)
        summary = "高危 Sink: 输入源 + 极高危汇点，需防止 AI safe 误判"
        if family_labels:
            summary = _join_notes(summary, "相关家族: " + ", ".join(family_labels[:3]))
    return {"candidate": candidate, "summary": summary, "line_numbers": sorted(set(line_numbers))[:6], "families": _sorted_unique(families)}


def _collect_boundary_combo_context(ext, code_content):
    rule = BOUNDARY_COMBO_RULES.get(ext)
    if not rule:
        return {"candidate": False, "summary": "", "categories": []}

    matched_categories = []
    if _match_any_patterns(code_content, rule.get("input_patterns", []), ext):
        matched_categories.append("输入源")
    if _match_any_patterns(code_content, rule.get("context_patterns", []), ext):
        matched_categories.append("路径上下文")
    if _match_any_patterns(code_content, rule.get("weak_patterns", []), ext):
        matched_categories.append("弱过滤/编码转换")
    if _match_any_patterns(code_content, rule.get("sink_patterns", []), ext):
        matched_categories.append("文件读取/路径拼接")

    strict_candidate = bool(
        "输入源" in matched_categories
        and "文件读取/路径拼接" in matched_categories
        and "弱过滤/编码转换" in matched_categories
        and len(matched_categories) >= 3
    )
    candidate = strict_candidate
    summary = ""
    if candidate:
        summary = "边界场景: " + " + ".join(matched_categories)
    return {"candidate": candidate, "summary": summary, "categories": matched_categories}


def _collect_write_chain_context(ext, code_content):
    rule = WRITE_CHAIN_CANDIDATE_RULES.get(ext)
    if not rule:
        return {"candidate": False, "summary": ""}

    has_input = _match_any_patterns(code_content, rule.get("input_patterns", []), ext)
    has_format = _match_any_patterns(code_content, rule.get("format_patterns", []), ext)
    has_write = _match_any_patterns(code_content, rule.get("write_patterns", []), ext)
    candidate = bool(has_input and has_format and has_write)
    summary = ""
    if candidate:
        summary = "状态写入链: 输入源 + 数据格式编码/序列化 + 状态写入"
    return {"candidate": candidate, "summary": summary}


def run_heuristic_prescreen(code_content, file_path="", project_context=None):
    # 启发式前置评估:
    # 1. 在任何模型/知识库预筛之前执行。
    # 2. 只做“是否需要强制送检”的保守判定，不直接替代最终漏洞结论。
    # 3. 这里的 hard_override 用于规则左移，避免文件在前置阶段被直接丢弃。
    ext = os.path.splitext(file_path)[1].lower() if file_path else ""
    lang_ctx = get_language_context(ext, code_content) if ext else {"has_input": False, "input_hits": [], "pattern_hits": [], "hit_lines": []}
    is_source_highly_polluted = _check_highly_polluted_source(code_content, lang_ctx, project_context, file_path) if file_path else False
    lines = code_content.splitlines()
    hard_override_hits = []

    for rule in HARD_OVERRIDE_RULES.get(ext, []):
        family = _normalize_override_family(rule.get("family", ""))
        primary_radius, fallback_radius = _get_hard_override_context_radii(family)
        for line_no, line_text in _find_pattern_line_matches(code_content, [rule["pattern"]], ext):
            sampled = _collect_stable_local_context(
                lines,
                line_no,
                ext,
                probes={
                    "source": lambda text: _has_local_source_signal(text, ext, lang_ctx),
                    "constraint": lambda text: _has_family_constraint_signal(text, family),
                },
                primary_radius=primary_radius,
                fallback_radius=fallback_radius,
            )
            local_context = sampled.get("context", {})
            has_local_constraint = bool(sampled.get("signals", {}).get("constraint"))
            has_local_source = bool(sampled.get("signals", {}).get("source"))
            if has_local_constraint:
                continue
            if not has_local_source and not is_source_highly_polluted:
                continue
            hard_override_hits.append(
                {
                    "family": family,
                    "label": rule.get("label", ""),
                    "line_no": line_no,
                    "line_text": line_text,
                    "start_line": local_context.get("start_line", line_no),
                    "end_line": local_context.get("end_line", line_no),
                    "context_stage": sampled.get("stage", "primary"),
                    "context_radius": sampled.get("used_radius", primary_radius),
                    "reason_hint": _get_hard_override_constraint_hint(family),
                    "override_reason": _join_notes(
                        f"命中 `{rule.get('label', '')}`",
                        f"漏洞家族: {VULN_FAMILY_LABELS.get(family, family or 'unknown')}",
                        f"局部未识别到 {_get_hard_override_constraint_hint(family)}",
                    ),
                }
            )

    reason_parts = []
    if hard_override_hits:
        labels = ", ".join(sorted({hit["label"] for hit in hard_override_hits if hit.get("label")}))
        reason_parts.append(f"高危 Sink 前置命中: {labels}")
        family_labels = ", ".join(
            sorted(
                {
                    VULN_FAMILY_LABELS.get(hit.get("family", ""), hit.get("family", ""))
                    for hit in hard_override_hits
                    if hit.get("family")
                }
            )
        )
        if family_labels:
            reason_parts.append(f"hard override 家族: {family_labels}")
    if is_source_highly_polluted:
        reason_parts.append("输入源被标记为高污染上下文")

    dominant_family = _mode_nonempty([hit.get("family", "") for hit in hard_override_hits])
    dominant_reason = _mode_nonempty([hit.get("override_reason", "") for hit in hard_override_hits])
    return {
        "lang_ctx": lang_ctx,
        "hard_override": bool(hard_override_hits),
        "hard_override_family": dominant_family,
        "hard_override_reason": dominant_reason,
        "is_source_highly_polluted": is_source_highly_polluted,
        "force_deep_scan": bool(hard_override_hits or is_source_highly_polluted),
        "line_numbers": sorted({hit["line_no"] for hit in hard_override_hits}),
        "hits": hard_override_hits,
        "reason": "；".join(reason_parts),
    }


def build_scan_plan(file_path, code_content, project_context=None, heuristic_meta=None):
    ext = os.path.splitext(file_path)[1].lower()
    heuristic_meta = heuristic_meta or {}
    lang_ctx = heuristic_meta.get("lang_ctx") or get_language_context(ext, code_content)
    is_source_highly_polluted = bool(heuristic_meta.get("is_source_highly_polluted")) or _check_highly_polluted_source(
        code_content, lang_ctx, project_context, file_path
    )
    boundary_ctx = _collect_boundary_combo_context(ext, code_content)
    write_chain_ctx = _collect_write_chain_context(ext, code_content)
    hard_sink_ctx = _collect_hard_sink_context(ext, code_content, lang_ctx, is_source_highly_polluted=is_source_highly_polluted)

    evidence_parts = []
    if lang_ctx["input_hits"]:
        evidence_parts.append("输入源: " + ", ".join(lang_ctx["input_hits"][:5]))
    if lang_ctx["keywords"]:
        evidence_parts.append("危险关键字: " + ", ".join(lang_ctx["keywords"][:5]))
    if lang_ctx["pattern_hits"]:
        evidence_parts.append("风险模式: " + ", ".join(lang_ctx["pattern_hits"][:5]))
    if write_chain_ctx["summary"]:
        evidence_parts.append(write_chain_ctx["summary"])
    if boundary_ctx["summary"]:
        evidence_parts.append(boundary_ctx["summary"])
    if hard_sink_ctx["summary"]:
        evidence_parts.append(hard_sink_ctx["summary"])
    if is_source_highly_polluted:
        evidence_parts.append("全局高危污染源: 当前输入标记为高污染上下文")
    if heuristic_meta.get("hard_override"):
        family_label = VULN_FAMILY_LABELS.get(heuristic_meta.get("hard_override_family", ""), heuristic_meta.get("hard_override_family", ""))
        evidence_parts.append(_join_notes("前置启发式: 命中未受保护的高危 Sink", family_label))

    candidate = False
    if ext in {".py", ".php"}:
        candidate = bool(lang_ctx["has_input"] and (lang_ctx["keywords"] or lang_ctx["pattern_hits"]))
    elif ext in {".js", ".java", ".jsp"}:
        candidate = bool(lang_ctx["has_input"] and lang_ctx["pattern_hits"])
    elif ext == ".go":
        pattern_set = set(lang_ctx["pattern_hits"])
        generic_decode = "JSON 解码" in pattern_set and "泛型反序列化容器" in pattern_set
        other_go_risks = bool(pattern_set - {"JSON 解码", "泛型反序列化容器"})
        candidate = bool(lang_ctx["has_input"] and (generic_decode or other_go_risks))
    if (
        not candidate
        and is_source_highly_polluted
        and ext in {".py", ".php", ".js", ".java", ".go", ".jsp"}
        and (
            "路径上下文" in boundary_ctx.get("categories", [])
            or "文件读取/路径拼接" in boundary_ctx.get("categories", [])
        )
    ):
        candidate = True
        boundary_ctx["candidate"] = True
        boundary_ctx["summary"] = "边界场景(高污染源放行): 输入源已被全局标记为高污染，放宽弱过滤要求"
    if not candidate and write_chain_ctx["candidate"]:
        candidate = True
    if not candidate and boundary_ctx["candidate"]:
        candidate = True
    if not candidate and hard_sink_ctx["candidate"]:
        candidate = True
    if not candidate and heuristic_meta.get("force_deep_scan"):
        candidate = True

    if not candidate:
        note = "仅预筛: 未发现稳定的“输入源 + 风险汇点”组合，未调用模型。"
        if len(code_content) > FULL_FILE_MODEL_CHAR_LIMIT:
            note = f"仅预筛: 文件较长（{len(code_content)} 字符），且预筛未命中高风险候选，为保护本地模型未送入 Ollama。"
        return {
            "status": "prescreen_only",
            "lang_ctx": lang_ctx,
            "reason": _short_text("；".join(evidence_parts) or "未命中候选规则。"),
            "snippet": "",
            "snippet_mode": "none",
            "focus": "",
            "note": note,
            "boundary_case": False,
            "is_source_highly_polluted": is_source_highly_polluted,
            "polluted_source_flag": "是" if is_source_highly_polluted else "否",
            "hard_override_family": heuristic_meta.get("hard_override_family", ""),
        }

    candidate_lines = sorted(set(lang_ctx["hit_lines"] + hard_sink_ctx.get("line_numbers", []) + heuristic_meta.get("line_numbers", [])))
    snippet, snippet_mode, snippet_note, focus = extract_relevant_snippet(code_content, candidate_lines)
    return {
        "status": "candidate",
        "lang_ctx": lang_ctx,
        "reason": _short_text("；".join(evidence_parts) or "命中候选规则。"),
        "snippet": snippet,
        "snippet_mode": snippet_mode,
        "focus": focus,
        "note": _join_notes(
            snippet_note or "已送模型: 命中候选规则。",
            heuristic_meta.get("hard_override_reason", ""),
            "触发启发式规则，强制送检" if heuristic_meta.get("force_deep_scan") else "",
        ),
        "boundary_case": boundary_ctx["candidate"],
        "is_source_highly_polluted": is_source_highly_polluted,
        "polluted_source_flag": "是" if is_source_highly_polluted else "否",
        "hard_override_family": heuristic_meta.get("hard_override_family", ""),
    }


def validate_with_command(command, success_detail, tool_name):
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except FileNotFoundError:
        return make_check_result("未执行", f"未找到命令 `{command[0]}`。", tool=tool_name)
    except subprocess.TimeoutExpired:
        return make_check_result("未执行", f"`{command[0]}` 执行超时。", tool=tool_name)
    except Exception as exc:
        return make_check_result("未执行", f"`{command[0]}` 执行失败: {exc}。", tool=tool_name)

    output = _short_text((completed.stdout or "") + " " + (completed.stderr or ""), limit=180)
    if completed.returncode == 0:
        return make_check_result("通过", success_detail, tool=tool_name)
    return make_check_result("失败", f"返回码 {completed.returncode}，输出: {output or '无'}。", tool=tool_name)


def validate_python(file_path, code_content):
    try:
        ast.parse(code_content)
    except SyntaxError as exc:
        return make_check_result("失败", f"AST 解析失败，第 {exc.lineno} 行，{exc.msg}。", tool="python")

    try:
        py_compile.compile(file_path, doraise=True)
        return make_check_result("通过", "ast.parse 与 py_compile 均通过。", tool="python")
    except py_compile.PyCompileError as exc:
        return make_check_result("失败", f"py_compile 失败: {_short_text(exc.msg, 180)}", tool="python")
    except Exception as exc:
        return make_check_result("失败", f"py_compile 失败: {exc}", tool="python")


def validate_java(file_path):
    return make_check_result("通过", "跳过: Java 依赖项目上下文，单文件编译不具备参考性。", tool="javac")


def validate_go(file_path):
    gofmt_path = shutil.which("gofmt")
    if gofmt_path:
        return validate_with_command([gofmt_path, "-e", file_path], "gofmt -e 检查通过。", "gofmt")
    go_path = shutil.which("go")
    if not go_path:
        return make_check_result("未执行", "未找到 go/gofmt，跳过 Go 校验。", tool="go")
    temp_dir = tempfile.mkdtemp(prefix="awdp_go_", dir=SCRIPT_DIR)
    output_path = os.path.join(temp_dir, "awdp_go_check.exe")
    try:
        return validate_with_command([go_path, "build", "-o", output_path, file_path], "go build 检查通过。", "go")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def validate_jsp(file_path):
    jspc_path = shutil.which("jspc")
    if not jspc_path:
        return make_check_result("未执行", "未找到 jspc，JSP 自动验证未执行。", tool="jspc")
    return validate_with_command([jspc_path, file_path], "jspc 检查通过。", "jspc")


def validate_file(file_path, code_content, ext):
    if ext == ".py":
        return validate_python(file_path, code_content)
    if ext == ".php":
        php_path = shutil.which("php")
        if not php_path:
            return make_check_result("未执行", "未找到 php，跳过 php -l。", tool="php")
        return validate_with_command([php_path, "-l", file_path], "php -l 语法检查通过。", "php")
    if ext == ".js":
        node_path = shutil.which("node")
        if not node_path:
            return make_check_result("未执行", "未找到 node，跳过 node --check。", tool="node")
        return validate_with_command([node_path, "--check", file_path], "node --check 语法检查通过。", "node")
    if ext == ".java":
        return validate_java(file_path)
    if ext == ".go":
        return validate_go(file_path)
    if ext == ".jsp":
        return validate_jsp(file_path)

    lang_name = LANGUAGE_RULES.get(ext, {}).get("lang_name", ext.strip(".").upper() or "Unknown")
    return make_check_result("未执行", f"暂未为 {lang_name} 提供自动验证器。", tool="validator")


# ==========================================
# 7. Detection / Repair knowledge helpers
# ==========================================
VULN_FAMILY_LABELS = {
    "sqli": "SQL injection",
    "upload": "Unsafe file upload",
    "file_write": "Unsafe file write",
    "ssti": "Server-side template injection",
    "command_exec": "Command execution / RCE",
    "auth": "JWT / Session / auth logic",
    "proto_pollution": "Prototype pollution",
    "ssrf": "SSRF",
    "xss": "XSS",
    "deserialization": "Unsafe deserialization",
    "xxe": "XXE / external entity",
    "variable_overwrite": "Variable overwrite",
    "jndi": "JNDI / Fastjson",
    "path_traversal": "Path traversal / LFI / Zip Slip",
    "dynamic_include": "Dynamic include / template path",
    "hardening": "Java / Node hardening",
}

REPAIR_MAINLINE_HINTS = {
    "sqli": "优先参数化查询、预处理语句或白名单映射，避免继续拼接 SQL。",
    "upload": "使用扩展名与 MIME 白名单、隔离上传目录和随机文件名，避免直接信任用户文件名。",
    "file_write": "限制目标文件白名单或固定根目录，避免使用用户文件名/路径直接落盘或覆盖。",
    "ssti": "使用固定模板与 context 变量，不要继续拼接模板字符串；denylist 只能作为临时缓解。",
    "command_exec": "优先参数白名单或格式校验，改为参数列表调用并避免 shell=True；PHP 中 escapeshellarg 仅作补强。",
    "auth": "统一鉴权入口，执行验签、过期时间和关键声明校验，保持原有 JSON/响应格式。",
    "proto_pollution": "限制可写键名，拒绝 __proto__/constructor/prototype 等危险键，优先做对象白名单映射。",
    "ssrf": "对目标地址做白名单或受控映射，限制协议和端口，避免直接请求用户提供的 URL。",
    "xss": "按输出上下文做编码或使用安全模板 API，避免原样拼接 HTML 或脚本片段。",
    "deserialization": "避免反序列化不可信输入，改用安全格式并对白名单字段做显式解析。",
    "xxe": "必须禁用外部实体解析并关闭危险 XML 特性，优先使用安全解析器配置，例如禁用 external entity / DTD。",
    "variable_overwrite": "避免从不可信输入直接覆盖当前上下文变量，改用白名单字段做显式赋值。",
    "jndi": "优先升级组件版本，限制反序列化类白名单并禁用 AutoType / 不安全的 JNDI 远程加载。",
    "path_traversal": "使用 realpath/commonpath 或白名单映射限制可访问路径，避免直接拼接用户路径。",
    "dynamic_include": "使用固定模板映射或白名单视图选择，避免直接拼接 include/require/template 路径。",
    "hardening": "优先使用框架安全 API，收敛动态执行和危险反射，不改变路由与返回结构。",
}

 


def normalize_vuln_family(raw_value):
    value = str(raw_value or "").strip().lower()
    if not value:
        return ""

    family_keywords = {
        "sqli": ["sql", "注入", "jdbc", "mysql", "mysqli", "pdo"],
        "upload": ["upload", "文件上传", "multipart"],
        "file_write": ["file write", "文件写入", "write file", "file_put_contents", "writefile", "overwrite"],
        "ssti": ["ssti", "template injection", "jinja", "twig", "freemarker", "render_template_string", "模板注入", "拼模板"],
        "command_exec": ["command", "rce", "exec", "shell", "eval", "命令执行", "代码执行"],
        "auth": ["jwt", "session", "auth", "鉴权", "认证", "越权", "权限"],
        "proto_pollution": ["prototype", "proto", "污染"],
        "ssrf": ["ssrf", "server-side request", "内网请求"],
        "xss": ["xss", "cross site", "脚本"],
        "deserialization": ["deserialize", "pickle", "unserialize", "反序列化"],
        "xxe": ["xxe", "simplexml", "domdocument", "loadxml", "external entity", "外部实体"],
        "variable_overwrite": ["变量覆盖", "extract", "parse_str", "variable overwrite"],
        "jndi": ["jndi", "lookup", "fastjson", "autotype"],
        "dynamic_include": ["dynamic include", "动态包含", "template path", "模板选择", "template include", "include path", "require_once", "require("],
        "path_traversal": ["path", "traversal", "lfi", "zip slip", "目录穿越", "文件读取", "文件访问"],
        "hardening": ["hardening", "unsafe api", "security config", "危险配置"],
    }

    for family, patterns in family_keywords.items():
        if any(pattern in value for pattern in patterns):
            return family
    return ""


def get_repair_mainline_hint(vuln_type):
    family = normalize_vuln_family(vuln_type)
    return REPAIR_MAINLINE_HINTS.get(family, "最小补丁、保服务、可验证、可回滚，不整文件重写。")


def _default_knowledge_result():
    return {
        "used": False,
        "stage": "未参与",
        "query": "",
        "files": [],
        "note": "",
        "context": "",
    }


def _default_repair_result():
    return {
        "minimal_fix": "",
        "report_fix_summary": "",
        "report_fix_code": "",
        "vuln_location": "",
        "original_code_snippet": "",
        "fixed_code_snippet": "",
    }


def _extract_json_object(raw_text):
    text = str(raw_text or "").strip()
    if not text:
        return {}

    try:
        loaded = json.loads(text)
        if isinstance(loaded, dict):
            return loaded
    except Exception:
        pass

    fenced_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced_match:
        try:
            loaded = json.loads(fenced_match.group(1))
            if isinstance(loaded, dict):
                return loaded
        except Exception:
            pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        try:
            loaded = json.loads(candidate)
            if isinstance(loaded, dict):
                return loaded
        except Exception:
            pass
    return {}


def build_knowledge_query(plan, detection_result=None):
    lang_ctx = plan.get("lang_ctx", {})
    family = normalize_vuln_family((detection_result or {}).get("vuln_type", ""))
    lang_name = lang_ctx.get("lang_name", "") or "未知"
    family_label = VULN_FAMILY_LABELS.get(family, "潜在风险")
    inputs = "、".join(lang_ctx.get("input_hits", [])[:3]) or "未明确输入源"
    patterns = "、".join(lang_ctx.get("pattern_hits", [])[:4]) or "未明确危险模式"
    keywords = "、".join(lang_ctx.get("keywords", [])[:4]) or "无额外关键词"
    return (
        f"寻找关于 {lang_name} 语言中 {family_label} 漏洞的修复约束，"
        f"涉及输入源 {inputs}，危险模式为 {patterns}，相关代码关键词包括 {keywords}。"
    )


def search_knowledge_base(vector_db, plan, detection_result=None, phase="repair"):
    result = _default_knowledge_result()
    if vector_db is None or RAG_MODE == "off":
        result["note"] = "知识库未启用。"
        return result

    detection_result = detection_result or {}
    verdict = detection_result.get("verdict", "")

    if phase == "repair":
        if verdict == "safe" and not normalize_vuln_family(detection_result.get("vuln_type", "")):
            result["note"] = "检测结果为安全，未触发修复约束检索。"
            return result

    query = build_knowledge_query(plan, detection_result)
    if not query.strip():
        result["note"] = "检索信息不足，已跳过知识库。"
        return result

    top_k = max(1, RAG_TOP_K)
    try:
        docs_with_scores = vector_db.similarity_search_with_score(query, k=top_k)
    except Exception as exc:
        result["note"] = f"知识库检索失败: {exc}"
        return result

    matched_docs = sorted(
        [
            (doc, score, os.path.basename(str((doc.metadata or {}).get("source", ""))))
            for doc, score in docs_with_scores
            if score <= RAG_SCORE_THRESHOLD
        ],
        key=lambda item: item[1],
    )[:top_k]

    if not matched_docs:
        result["note"] = "未检索到匹配的修复约束文档。"
        result["query"] = query
        return result

    snippets = []
    files = []
    for doc, score, source in matched_docs[:top_k]:
        if source and source not in files:
            files.append(source)
        page_content = _short_text(getattr(doc, "page_content", ""), limit=900)
        snippets.append(f"[{source or 'knowledge'} | score={score:.3f}]\n{page_content}")

    stage = "判定前实验" if phase == "prejudge" else "修复约束/修复复核"
    result.update(
        {
            "used": True,
            "stage": stage,
            "query": query,
            "files": files,
            "note": f"命中 {len(snippets)} 条知识库文档。",
            "context": (
                "【本地知识库只用于修复约束与修复复核，不可作为漏洞判定证据】\n"
                + "\n\n".join(snippets)
            ),
        }
    )
    return result


def build_detection_prompt(file_path, plan, prejudge_knowledge=None):
    lang_ctx = plan["lang_ctx"]
    knowledge_text = ""
    boundary_text = ""
    pollution_text = ""
    if prejudge_knowledge and prejudge_knowledge.get("used"):
        knowledge_text = (
            "\n[实验信息]\n"
            "以下内容仅可作为术语对齐和风险点提醒，不能直接作为漏洞证据。\n"
            f"{prejudge_knowledge.get('context', '')}\n"
        )
    if plan.get("boundary_case"):
        boundary_text = (
            "\n[边界场景提醒]\n"
            "该文件属于路径/编码/标准化边界场景，请关注“表面过滤”和“真实根路径约束”是否一致。\n"
        )
    if plan.get("is_source_highly_polluted"):
        pollution_text = (
            "\n[跨文件上下文提醒]\n"
            "该文件关联全局高危污染源，当前文件即使表面较干净，也要关注是否只是把不可信输入继续传递到后续路径/加载/写入逻辑。\n"
        )

    return f"""
你是 AWDP 防守场景中的本地代码审计助手。你的职责是做“检测层”判断，而不是给攻击建议。

[硬约束]
1. 漏洞是否存在，只能基于下面给出的真实代码上下文、输入源、风险 API 和控制流迹象判断。
2. 不要把知识库、模板经验、漏洞名字本身，当作“代码一定有洞”的证据。
3. 只输出一个 JSON 对象，不要输出 Markdown，不要输出解释性前后缀。
4. 不要输出修复代码，不要输出 Break，不要整文件重写。

[目标文件]
{file_path}

[语言]
{lang_ctx.get('lang_name', 'Unknown')}

[语言硬约束]
{lang_ctx.get('lang_hint', '')}

[预筛摘要]
{plan.get('reason', '')}

[代码片段模式]
{plan.get('snippet_mode', 'unknown')}

[代码片段]
```text
{plan.get('snippet', '')}
```
{boundary_text}
{pollution_text}
{knowledge_text}
[输出字段]
verdict: vulnerable | safe | needs_manual_review
vuln_type: 简短漏洞类型
reason: 2-4 句，说明为什么怀疑或为什么判定安全
code_evidence: 直接引用代码层证据摘要，如输入源、危险 API、拼接点、模板拼接点
confidence: 0~1
"""


def call_ollama(prompt, num_predict, retries=MODEL_RETRIES):
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "format": "json",
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": num_predict,
        },
    }

    last_error = ""
    for attempt in range(1, retries + 1):
        try:
            response = requests.post(OLLAMA_API_URL, json=payload, timeout=OLLAMA_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            text = str(data.get("response", "")).strip()
            if text:
                return {"ok": True, "text": text, "error": ""}
            last_error = "Ollama 返回空响应。"
        except requests.exceptions.Timeout:
            last_error = f"Ollama 请求超时（第 {attempt}/{retries} 次）。"
        except requests.RequestException as exc:
            last_error = f"Ollama 请求失败: {exc}"
        except ValueError:
            last_error = "Ollama 返回了无效 JSON。"
        time.sleep(min(attempt, 2))
    return {"ok": False, "text": "", "error": last_error or "Ollama 调用失败。"}


def parse_detection_output(raw_text):
    parsed = _extract_json_object(raw_text)
    if not parsed:
        return {
            "verdict": "needs_manual_review",
            "vuln_type": "",
            "reason": _short_text(raw_text or "模型输出无法解析为 JSON。", limit=260),
            "code_evidence": "模型输出格式异常，建议人工复核。",
            "confidence": 0.0,
        }

    cleaned_evidence = _clean_evidence_text(parsed.get("code_evidence", ""))
    return {
        "verdict": _normalize_verdict(parsed.get("verdict")),
        "vuln_type": _short_text(parsed.get("vuln_type", ""), limit=80),
        "reason": _short_text(parsed.get("reason", ""), limit=320),
        "code_evidence": _short_text(cleaned_evidence or parsed.get("code_evidence", ""), limit=260),
        "confidence": _normalize_confidence(parsed.get("confidence")),
    }


def _apply_hard_override(file_path, code_content, plan, detection_result, heuristic_meta=None):
    # 后置 hard override:
    # 仅在模型已经给出 safe 结论后再次执行。
    # 这里不替代前置启发式，而是用于兜住“模型已看过代码但仍误判 safe”的情况。
    if detection_result.get("verdict") != "safe":
        return detection_result, {"triggered": False, "reason": ""}

    ext = os.path.splitext(file_path)[1].lower()
    rules = HARD_OVERRIDE_RULES.get(ext, [])
    if not rules:
        return detection_result, {"triggered": False, "reason": ""}

    lang_ctx = plan.get("lang_ctx", {})
    if not (lang_ctx.get("has_input") or plan.get("is_source_highly_polluted")):
        return detection_result, {"triggered": False, "reason": ""}

    heuristic_meta = heuristic_meta or run_heuristic_prescreen(code_content, file_path=file_path)
    if heuristic_meta.get("hard_override"):
        lines = code_content.splitlines()
        actionable_hits = []
        for raw_hit in heuristic_meta.get("hits") or []:
            hit = dict(raw_hit or {})
            family = _normalize_override_family(hit.get("family", ""))
            line_no = int(hit.get("line_no", 0) or 0)
            if line_no <= 0:
                actionable_hits.append(hit)
                continue
            primary_radius, fallback_radius = _get_hard_override_context_radii(family)
            sampled = _collect_stable_local_context(
                lines,
                line_no,
                ext,
                probes={"constraint": lambda text, current_family=family: _has_family_constraint_signal(text, current_family)},
                primary_radius=primary_radius,
                fallback_radius=fallback_radius,
            )
            has_local_constraint = bool(sampled.get("signals", {}).get("constraint"))
            if has_local_constraint:
                continue
            local_context = sampled.get("context", {})
            hit["start_line"] = local_context.get("start_line", hit.get("start_line", line_no))
            hit["end_line"] = local_context.get("end_line", hit.get("end_line", line_no))
            hit["context_stage"] = sampled.get("stage", hit.get("context_stage", "primary"))
            hit["context_radius"] = sampled.get("used_radius", hit.get("context_radius", primary_radius))
            actionable_hits.append(hit)

        if not actionable_hits:
            return detection_result, {"triggered": False, "reason": ""}

        hit = actionable_hits[0]
        label_to_rule = {rule.get("label"): rule for rule in rules}
        matched_rule = label_to_rule.get(hit.get("label")) or {}
        family = _normalize_override_family(hit.get("family") or matched_rule.get("family", ""))
        family_label = VULN_FAMILY_LABELS.get(family, family or "unknown")
        overridden = dict(detection_result)
        overridden["verdict"] = "needs_manual_review"
        overridden["vuln_type"] = matched_rule.get("vuln_type") or detection_result.get("vuln_type") or family_label
        overridden["reason"] = _join_notes(
            "AI 判定为 safe，但硬规则命中极高危 Sink。",
            f"第 {hit.get('line_no', 0)} 行附近出现 `{hit.get('label', '')}`，家族为 {family_label}。",
            f"局部上下文内未识别到 {_get_hard_override_constraint_hint(family)}。",
            "为避免 AI 漏判，已强制提升为待人工复核。",
        )
        overridden["code_evidence"] = _join_notes(
            f"第 {hit.get('line_no', 0)} 行 `{_short_text(hit.get('line_text', ''), 120)}`",
            f"局部上下文范围: 第 {hit.get('start_line', 0)}-{hit.get('end_line', 0)} 行",
            f"上下文采样: {hit.get('context_stage', 'primary')} / radius={hit.get('context_radius', 0)}",
            "硬规则状态: suspicious_sink",
        )
        overridden["confidence"] = max(float(detection_result.get("confidence", 0.0) or 0.0), 0.45)
        overridden["heuristic_status"] = "suspicious_sink"
        overridden["hard_override_family"] = family
        overridden["hard_override_reason"] = hit.get("override_reason") or heuristic_meta.get("hard_override_reason", "")
        override_reason = _join_notes(
            f"硬规则兜底: 命中 {hit.get('label', '')}，已忽略 safe 判定。",
            hit.get("override_reason"),
        )
        return overridden, {"triggered": True, "reason": override_reason, "family": family, "detail": hit.get("override_reason", "")}

    return detection_result, {"triggered": False, "reason": ""}


# ==========================================
# 8. Repair stage
# ==========================================
def build_repair_prompt(file_path, plan, detection_result, knowledge_meta):
    lang_ctx = plan["lang_ctx"]
    repair_hint = get_repair_mainline_hint(detection_result.get("vuln_type", ""))
    knowledge_text = knowledge_meta.get("context", "") if knowledge_meta.get("used") else "未命中修复约束文档。"

    return f"""
你是 AWDP 防守场景中的本地修复建议助手。你的职责是输出“极其稳定的人类修复引导”，而不是自动打补丁。

[全局硬约束]
1. 只允许最小补丁，不允许整文件重写。
2. 不得改变返回值类型、路由结构、核心业务逻辑、原有 JSON/响应格式。
3. 优先参数化、白名单、上下文变量、安全 API。
4. 黑名单、关键字拦截、脆弱正则，最多只能作为临时缓解，不能作为主修法。
5. 优先输出“最小但完整”的局部代码，不要只给修复原则。
6. 不要输出与漏洞无关的大段条件逻辑、不要只给半截 if 分支、不要输出无意义 allowlist 示例数据。
7. 不要输出解释性前后缀，不要输出“请根据实际情况修改”，不要输出伪代码，不要输出省略号或省略实现。
8. 如果原接口是 API，尽量保持原响应格式、返回结构和错误处理风格。
9. vuln_location 只能写函数名、方法名、危险调用点名称或核心风险代码块标识，绝对不要写行号。
10. original_code_snippet 必须是原文件中的危险代码片段，fixed_code_snippet 必须是与之对应的完整、闭合、可直接替换的修复代码块。
11. original_code_snippet 和 fixed_code_snippet 都不要带行号，不要带 Markdown 代码块围栏。
12. 只输出一个 JSON 对象，不要输出 Markdown，不要输出额外说明。
13. fixed_code_snippet 必须是纯净、可直接执行的代码。严禁在代码块中添加任何多余的中文注释（如'// 移除 eval 函数...'），严禁输出解释性废话。

[目标文件]
{file_path}

[语言]
{lang_ctx.get('lang_name', 'Unknown')}

[语言硬约束]
{lang_ctx.get('lang_hint', '')}

[检测结果]
verdict={detection_result.get('verdict', '')}
vuln_type={detection_result.get('vuln_type', '')}
reason={detection_result.get('reason', '')}
code_evidence={detection_result.get('code_evidence', '')}
confidence={detection_result.get('confidence', 0)}

[建议修复主线]
{repair_hint}

[代码片段]
```text
{plan.get('snippet', '')}
```

[知识库修复约束]
{knowledge_text}

[输出字段]
report_fix_summary: 面向人工阅读的一句话修复摘要
vuln_location: 受影响的函数名、方法名或核心风险位置标识，不允许输出行号
original_code_snippet: 原始危险代码片段，不允许输出行号，必须是纯净代码
fixed_code_snippet: 推荐替换的完整闭合代码块，不允许输出行号，必须是纯净、无注释的代码
"""


def parse_repair_output(raw_text):
    parsed = _extract_json_object(raw_text) or _parse_mapping_literal(raw_text)
    if not parsed:
        result = _default_repair_result()
        result["minimal_fix"] = str(raw_text or "")
        result["report_fix_summary"] = "修复输出格式异常，已保留原始内容供人工复核。"
        return result

    report_fix_summary = parsed.get("report_fix_summary", "") or parsed.get("summary", "")
    original_code_snippet = (
        parsed.get("original_code_snippet", "")
        or parsed.get("match", "")
        or parsed.get("original_code", "")
        or ""
    )
    fixed_code_snippet = (
        parsed.get("fixed_code_snippet", "")
        or parsed.get("report_fix_code", "")
        or parsed.get("replace", "")
        or parsed.get("code", "")
        or ""
    )
    report_fix_code = (
        parsed.get("report_fix_code", "")
        or fixed_code_snippet
    )
    minimal_fix = _normalize_legacy_fix_payload(parsed, raw_text, fixed_code_snippet)
    return {
        "minimal_fix": minimal_fix,
        "report_fix_summary": _short_text(report_fix_summary, limit=220),
        "report_fix_code": str(report_fix_code or ""),
        "vuln_location": _sanitize_vuln_location(parsed.get("vuln_location", "") or parsed.get("location", "")),
        "original_code_snippet": str(original_code_snippet or ""),
        "fixed_code_snippet": str(fixed_code_snippet or ""),
    }


def _parse_mapping_literal(raw_value):
    text = str(raw_value or "").strip()
    if not text or not text.startswith(("{", "[")):
        return {}
    try:
        loaded = ast.literal_eval(text)
    except Exception:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _build_patch_protocol(summary="", match="", replace=""):
    parts = []
    if summary:
        parts.extend(["[summary]", str(summary).strip()])
    if match:
        parts.extend(["[match]", str(match).strip("\n")])
    if replace:
        parts.extend(["[replace]", str(replace).strip("\n")])
    return "\n".join(parts).strip()


def _extract_patch_sections(minimal_fix):
    text = str(minimal_fix or "").strip()
    summary_match = re.search(r"\[summary\]\s*(.*?)\s*(?=\[match\]|\[replace\]|$)", text, re.S | re.I)
    match_match = re.search(r"\[match\]\s*(.*?)\s*(?=\[replace\]|$)", text, re.S | re.I)
    replace_match = re.search(r"\[replace\]\s*(.*)$", text, re.S | re.I)
    return {
        "summary": summary_match.group(1).strip() if summary_match else "",
        "match": match_match.group(1).strip("\n") if match_match else "",
        "replace": replace_match.group(1).strip("\n") if replace_match else "",
    }


def _normalize_legacy_fix_payload(parsed, raw_text="", report_fix_code=""):
    minimal_fix = parsed.get("minimal_fix", "")
    if isinstance(minimal_fix, dict):
        summary = minimal_fix.get("summary", "")
        match = minimal_fix.get("match", "")
        replace = minimal_fix.get("replace", "")
        protocol = _build_patch_protocol(summary, match, replace)
        return protocol or json.dumps(minimal_fix, ensure_ascii=False)

    if any(key in parsed for key in ("summary", "match", "replace")):
        protocol = _build_patch_protocol(parsed.get("summary", ""), parsed.get("match", ""), parsed.get("replace", ""))
        if protocol:
            return protocol

    minimal_fix_text = str(minimal_fix or "")
    patch_sections = _extract_patch_sections(minimal_fix_text)
    if patch_sections["match"] or patch_sections["replace"]:
        return minimal_fix_text

    literal_fix = _parse_mapping_literal(minimal_fix_text)
    if literal_fix:
        protocol = _build_patch_protocol(
            literal_fix.get("summary", ""),
            literal_fix.get("match", ""),
            literal_fix.get("replace", ""),
        )
        if protocol:
            return protocol

    embedded_json = _extract_json_object(minimal_fix_text)
    if embedded_json:
        protocol = _build_patch_protocol(
            embedded_json.get("summary", ""),
            embedded_json.get("match", ""),
            embedded_json.get("replace", ""),
        )
        if protocol:
            return protocol

    if minimal_fix_text.strip():
        return minimal_fix_text
    if str(report_fix_code or "").strip():
        return str(report_fix_code or "").strip()
    return str(raw_text or "")


def _normalize_report_fix_language(raw_value, file_path=""):
    value = str(raw_value or "").strip().lower()
    language_map = {
        "php": "php",
        "python": "python",
        "py": "python",
        "javascript": "javascript",
        "js": "javascript",
        "java": "java",
        "go": "go",
        "text": "text",
    }
    if value in language_map:
        return language_map[value]

    ext_map = {
        ".php": "php",
        ".py": "python",
        ".js": "javascript",
        ".java": "java",
        ".go": "go",
    }
    return ext_map.get(os.path.splitext(file_path)[1].lower(), "text")


def _sanitize_vuln_location(raw_value):
    text = str(raw_value or "").strip()
    if not text:
        return ""
    text = re.sub(r"(?i)\bline\s*\d+\b", "", text)
    text = re.sub(r"第\s*\d+\s*行", "", text)
    text = re.sub(r"\s+", " ", text).strip(" :-")
    return _short_text(text, limit=120)


def _sanitize_code_snippet(raw_value):
    _, unfenced = _unwrap_fenced_code_block(raw_value)
    return str(unfenced or "").strip()


def _offset_to_line_number(code_content, offset):
    if offset < 0:
        return 0
    return code_content.count("\n", 0, offset) + 1


def locate_code_snippet(code_content, snippet):
    cleaned_snippet = _sanitize_code_snippet(snippet)
    if not code_content or not cleaned_snippet:
        return {"matched": False, "matched_snippet": cleaned_snippet, "start_line": 0, "end_line": 0}

    start = code_content.find(cleaned_snippet)
    if start != -1:
        end = start + len(cleaned_snippet)
        return {
            "matched": True,
            "matched_snippet": code_content[start:end].strip("\n"),
            "start_line": _offset_to_line_number(code_content, start),
            "end_line": _offset_to_line_number(code_content, max(start, end - 1)),
        }

    snippet_parts = [part for part in re.split(r"(\s+)", cleaned_snippet.strip()) if part]
    if len(cleaned_snippet) >= 12 and snippet_parts:
        pattern = "".join(r"\s+" if part.isspace() else re.escape(part) for part in snippet_parts)
        matched = re.search(pattern, code_content, re.S)
        if matched:
            start = matched.start()
            end = matched.end()
            return {
                "matched": True,
                "matched_snippet": code_content[start:end].strip("\n"),
                "start_line": _offset_to_line_number(code_content, start),
                "end_line": _offset_to_line_number(code_content, max(start, end - 1)),
            }

    return {"matched": False, "matched_snippet": cleaned_snippet, "start_line": 0, "end_line": 0}


def _extract_pattern_value(pattern_builders, text):
    source_text = str(text or "")
    for pattern, value_builder in pattern_builders:
        matched = pattern.search(source_text)
        if matched:
            return value_builder(matched)
    return ""


def _normalize_anchor_text(text, limit=4):
    tokens = re.findall(r"[a-zA-Z_][\w:-]{2,}", str(text or "").lower())
    stopwords = {
        "input",
        "source",
        "danger",
        "keyword",
        "risk",
        "pattern",
        "code",
        "evidence",
        "query",
        "request",
        "cookie",
        "header",
    }
    filtered = [token for token in tokens if token not in stopwords]
    return "-".join(filtered[:limit])


def extract_format_features(text):
    features = []
    source_text = str(text or "")
    for pattern, feature_name in ROOT_CAUSE_FORMAT_PATTERNS:
        if pattern.search(source_text) and feature_name not in features:
            features.append(feature_name)
    return features


def collect_state_accesses(text, lang_ctx=None):
    source_text = str(text or "")
    accesses = []
    for pattern, value_builder in ROOT_CAUSE_INPUT_PATTERNS:
        for matched in pattern.finditer(source_text):
            identifier = value_builder(matched)
            accesses.append(
                {
                    "role": "reader",
                    "identifier": identifier,
                    "container": _container_from_identifier(identifier),
                }
            )
    for pattern, container_name, value_builder in ROOT_CAUSE_STATE_WRITE_PATTERNS:
        for matched in pattern.finditer(source_text):
            identifier = value_builder(matched)
            accesses.append(
                {
                    "role": "writer",
                    "identifier": identifier,
                    "container": container_name or _container_from_identifier(identifier),
                }
            )

    if not accesses:
        input_identifier = _extract_pattern_value(ROOT_CAUSE_INPUT_PATTERNS, source_text)
        if not input_identifier:
            input_hits = list((lang_ctx or {}).get("input_hits") or [])
            if input_hits:
                input_identifier = str(input_hits[0]).lower()
        if input_identifier:
            accesses.append(
                {
                    "role": "reader",
                    "identifier": input_identifier,
                    "container": _container_from_identifier(input_identifier),
                }
            )

    deduped = []
    seen = set()
    for access in accesses:
        key = (
            access.get("role", ""),
            access.get("identifier", ""),
            access.get("container", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(access)
    return deduped


def extract_input_identifier(text, lang_ctx):
    accesses = collect_state_accesses(text, lang_ctx)
    prioritized = sorted(
        accesses,
        key=lambda item: (
            0 if item.get("container") in {"cookie", "session", "hidden_field", "session_storage", "local_storage"} else 1,
            0 if item.get("role") == "writer" else 1,
            len(item.get("identifier", "")),
        ),
    )
    for access in prioritized:
        identifier = str(access.get("identifier", "") or "").strip()
        if identifier:
            return identifier
    input_hits = list((lang_ctx or {}).get("input_hits") or [])
    if input_hits:
        return str(input_hits[0]).lower()
    return ""


def extract_danger_api(text, lang_ctx):
    source_text = str(text or "")
    for pattern, api_name in ROOT_CAUSE_API_PATTERNS:
        if pattern.search(source_text):
            return api_name
    pattern_hits = list((lang_ctx or {}).get("pattern_hits") or [])
    if pattern_hits:
        return _normalize_anchor_text(pattern_hits[0], limit=2) or pattern_hits[0]
    keywords = list((lang_ctx or {}).get("keywords") or [])
    if keywords:
        return str(keywords[0]).lower()
    return ""


def extract_chain_role(text, lang_ctx):
    accesses = collect_state_accesses(text, lang_ctx)
    roles = {access.get("role", "") for access in accesses if access.get("role")}
    if {"reader", "writer"}.issubset(roles):
        return "reader+writer"
    if "reader" in roles:
        return "reader"
    if "writer" in roles:
        return "writer"
    return "unknown"


def _build_root_cause_group_key(meta):
    family = meta.get("family") or "unknown"
    container = meta.get("state_container") or ""
    input_identifier = meta.get("input_identifier") or ""
    format_signature = meta.get("format_signature") or ""
    lang_name = meta.get("lang_name") or "unknown"
    danger_api = meta.get("danger_api") or "api:unknown"
    evidence_anchor = meta.get("evidence_anchor") or "generic"

    if container in {"cookie", "session", "hidden_field", "session_storage", "local_storage"} and input_identifier:
        key_parts = [
            family,
            container,
            input_identifier,
            format_signature or "format:unknown",
        ]
        if not format_signature:
            key_parts.append(evidence_anchor)
        return "|".join(key_parts)

    key_parts = [
        family,
        input_identifier or "input:unknown",
        danger_api,
        lang_name,
    ]
    if not input_identifier and not meta.get("danger_api"):
        key_parts.append(evidence_anchor)
    return "|".join(key_parts)


def build_root_cause_metadata(file_path, code_content, plan, detection_result, repair_result):
    lang_ctx = plan.get("lang_ctx", {})
    family = normalize_vuln_family(detection_result.get("vuln_type", ""))
    combined_text = "\n".join(
        [
            str(plan.get("snippet", "") or ""),
            str(_clean_evidence_text(detection_result.get("code_evidence", "")) or ""),
            str(detection_result.get("reason", "") or ""),
            str(repair_result.get("original_code_snippet", "") or ""),
        ]
    )
    source_text = combined_text or code_content
    state_accesses = collect_state_accesses(source_text, lang_ctx)
    input_identifier = extract_input_identifier(source_text, lang_ctx)
    danger_api = extract_danger_api(source_text, lang_ctx)
    evidence_anchor = _normalize_anchor_text(
        _clean_evidence_text(detection_result.get("code_evidence")) or plan.get("reason") or detection_result.get("vuln_type")
    )
    lang_name = str(lang_ctx.get("lang_name", "unknown") or "unknown").lower()
    chain_role = extract_chain_role(source_text, lang_ctx)
    container_values = [access.get("container", "") for access in state_accesses]
    state_container = _mode_nonempty(container_values, default=_container_from_identifier(input_identifier))
    format_features = extract_format_features(source_text)
    format_signature = ",".join(sorted(format_features))

    fingerprint_parts = [
        f"family={family or 'unknown'}",
        f"input={input_identifier or 'unknown'}",
        f"api={danger_api or 'unknown'}",
        f"container={state_container or 'unknown'}",
        f"formats={format_signature or 'unknown'}",
        f"role={chain_role}",
        f"evidence={evidence_anchor or 'generic'}",
        f"lang={lang_name}",
        f"location={repair_result.get('vuln_location', '') or 'unknown'}",
    ]
    metadata = {
        "family": family,
        "input_identifier": input_identifier,
        "danger_api": danger_api,
        "evidence_anchor": evidence_anchor,
        "type_label": detection_result.get("vuln_type", "") or VULN_FAMILY_LABELS.get(family, ""),
        "lang_name": lang_name,
        "file_path": _relative_path(file_path),
        "state_container": state_container,
        "format_features": format_signature,
        "chain_role": chain_role,
        "evidence_summary": _clean_evidence_text(detection_result.get("code_evidence") or detection_result.get("reason") or plan.get("reason")),
    }
    metadata["group_key"] = _build_root_cause_group_key(
        {
            **metadata,
            "format_signature": format_signature,
        }
    )
    return {
        **metadata,
        "fingerprint": " | ".join(fingerprint_parts),
    }


def _find_matching_line_samples(code_content, patterns, limit=2, ext=""):
    samples = []
    if not patterns:
        return samples
    for line_no, raw_line in enumerate(code_content.splitlines(), start=1):
        line = _strip_inline_comment(raw_line, ext) if ext else raw_line
        if any(pattern.search(line) for pattern in patterns):
            samples.append((line_no, line.strip()))
        if len(samples) >= limit:
            break
    return samples


def _evaluate_secondary_rule(code_content, rule, main_family):
    if rule.get("family") == main_family:
        return None
    ext = str(rule.get("ext", "") or "")
    if not _match_any_patterns(code_content, rule.get("input_patterns", []), ext):
        return None

    sink_samples = _find_matching_line_samples(
        code_content,
        rule.get("sink_patterns", []),
        limit=2,
        ext=ext,
    )
    if not sink_samples:
        return None

    has_context = _match_any_patterns(code_content, rule.get("context_patterns", []), ext)
    has_weak = _match_any_patterns(code_content, rule.get("weak_patterns", []), ext)
    notes = []
    note_text = rule.get("notes", {})
    if has_context and note_text.get("context"):
        notes.append(note_text["context"])
    if has_weak and note_text.get("weak"):
        notes.append(note_text["weak"])

    evidence_lines = [f"第 {line_no} 行 `{_short_text(line, 100)}`" for line_no, line in sink_samples]
    score = 35
    if has_context:
        score += 25
    if has_weak:
        score += 15
    if len(sink_samples) > 1:
        score += 10
    score = max(0, min(100, score))

    # 灰度分级:
    # - >=70: 正式次级风险，直接进入 secondary_findings
    # - 45~69: 低置信度疑似漏洞，进入 potential_secondary_risk
    # - <45: 仅保留人工复核备注，避免噪声淹没主问题
    risk_grade = "review_note"
    if score >= 70:
        risk_grade = "secondary_risk"
    elif score >= 45:
        risk_grade = "potential_secondary_risk"
    return {
        "family": rule.get("family", ""),
        "secondary_family_original": rule.get("name", ""),
        "related_families": list(rule.get("related_families", []) or []),
        "name": rule.get("name", ""),
        "summary": _join_notes(rule.get("summary", ""), "、".join(notes) if notes else ""),
        "evidence": "；".join(evidence_lines),
        "score": score,
        "risk_grade": risk_grade,
        "review_note": "" if risk_grade != "review_note" else _join_notes(rule.get("summary", ""), "仅命中加载/读取点，建议人工复核上下文约束"),
    }


def scan_secondary_risks(file_path, code_content, plan, main_family):
    ext = os.path.splitext(file_path)[1].lower()
    results = []
    for rule in SECONDARY_RISK_RULES.get(ext, []):
        matched = _evaluate_secondary_rule(code_content, {**rule, "ext": ext}, main_family)
        if matched:
            results.append(matched)
    return results


def collect_secondary_findings(file_path, code_content, plan, detection_result):
    main_family = normalize_vuln_family(detection_result.get("vuln_type", ""))
    if detection_result.get("verdict") not in {"vulnerable", "needs_manual_review"}:
        return {"findings": [], "potential_findings": [], "review_note": ""}

    ext = os.path.splitext(file_path)[1].lower()
    lang_ctx = plan.get("lang_ctx", {})
    pattern_line_map = dict(lang_ctx.get("pattern_line_map") or {})
    findings = []
    potential_findings = []
    seen_families = set()
    weak_notes = []
    code_lines = code_content.splitlines()

    for label, line_numbers in pattern_line_map.items():
        family = SECONDARY_LABEL_FAMILY_MAP.get(label)
        if not family or family == main_family or family in seen_families:
            continue
        evidence_lines = []
        for line_no in line_numbers[:2]:
            raw_line = code_lines[line_no - 1] if line_no - 1 < len(code_lines) else ""
            line_text = _strip_inline_comment(raw_line, ext).strip()
            evidence_lines.append(f"第 {line_no} 行 `{_short_text(line_text, 100)}`")
        summary = f"该文件除主问题外，仍存在疑似 {VULN_FAMILY_LABELS.get(family, family)} 风险"
        if label == "动态包含":
            summary = "该文件除主问题外，仍存在疑似动态包含或模板选择风险"
        findings.append(
            {
                "family": family,
                "secondary_family_original": label,
                "related_families": ["path_traversal"] if family == "dynamic_include" else [],
                "summary": summary,
                "evidence": "；".join(evidence_lines) or label,
            }
        )
        seen_families.add(family)
        if len(findings) >= 2:
            return {"findings": findings[:2], "potential_findings": potential_findings[:2], "review_note": ""}

    for matched in scan_secondary_risks(file_path, code_content, plan, main_family):
        family = matched.get("family", "")
        summary = matched.get("summary", "")
        evidence = matched.get("evidence", "")
        finding_payload = {
            "family": family,
            "secondary_family_original": matched.get("secondary_family_original") or matched.get("name", ""),
            "related_families": list(matched.get("related_families", []) or []),
            "summary": summary,
            "evidence": evidence,
            "score": matched.get("score", 0),
        }
        if matched.get("risk_grade") == "secondary_risk" and family not in seen_families and len(findings) < 2:
            findings.append(
                finding_payload
            )
            seen_families.add(family)
        elif matched.get("risk_grade") == "potential_secondary_risk" and len(potential_findings) < 2:
            potential_findings.append(finding_payload)
        elif matched.get("review_note"):
            weak_notes.append(matched["review_note"])

    return {
        "findings": findings[:2],
        "potential_findings": potential_findings[:2],
        "review_note": _join_notes(*weak_notes) if weak_notes else "",
    }


def format_secondary_findings(findings):
    if not findings:
        return ""
    parts = []
    for finding in findings:
        family_label = VULN_FAMILY_LABELS.get(finding.get("family", ""), finding.get("family", "未知风险"))
        original_label = str(finding.get("secondary_family_original", "") or "").strip()
        related_families = [VULN_FAMILY_LABELS.get(item, item) for item in finding.get("related_families", []) if item]
        family_text = family_label
        if original_label and original_label.lower() not in {family_label.lower(), finding.get("family", "").lower()}:
            family_text = f"{family_label} [{original_label}]"
        if related_families:
            family_text = f"{family_text} (关联: {', '.join(related_families)})"
        parts.append(
            f"{family_text}: {_clean_evidence_text(finding.get('summary', ''))}；证据: {_clean_evidence_text(finding.get('evidence', '无'))}"
        )
    return " | ".join(parts)


def format_potential_secondary_findings(findings):
    if not findings:
        return ""
    parts = []
    for finding in findings:
        family_label = VULN_FAMILY_LABELS.get(finding.get("family", ""), finding.get("family", "未知风险"))
        score = int(finding.get("score", 0) or 0)
        original_label = str(finding.get("secondary_family_original", "") or "").strip()
        related_families = [VULN_FAMILY_LABELS.get(item, item) for item in finding.get("related_families", []) if item]
        family_text = family_label
        if original_label and original_label.lower() not in {family_label.lower(), finding.get("family", "").lower()}:
            family_text = f"{family_label} [{original_label}]"
        if related_families:
            family_text = f"{family_text} (关联: {', '.join(related_families)})"
        parts.append(
            f"{family_text} [score={score}]: {_clean_evidence_text(finding.get('summary', ''))}；证据: {_clean_evidence_text(finding.get('evidence', '无'))}"
        )
    return " | ".join(parts)


def extract_repair_strategy_tags(family, entry):
    text = " ".join(
        [
            str(entry.get("repair_mainline", "")),
            str(entry.get("report_fix_summary", "")),
            str(entry.get("fixed_code_snippet", "")),
            str(entry.get("report_fix_code", "")),
        ]
    ).lower()
    tags = set()

    if any(token in text for token in ("json", "json_decode", "json.loads", "json.unmarshal")):
        tags.add("json_format")
    if any(token in text for token in ("unserialize", "pickle", "yaml.load", "xml", "readobject", "gob")):
        tags.add("legacy_serialization")
    if any(token in text for token in ("parameter", "prepare", "placeholder", "bind", "参数化", "预处理")):
        tags.add("parameterized")
    if any(token in text for token in ("realpath", "commonpath", "safe_join", "filepath.rel", "filepath.clean")):
        tags.add("root_constraint")
    if any(token in text for token in ("shell=false", "subprocess.run([", "exec.command(", "参数列表", "escapeshellarg")):
        tags.add("safe_exec")
    if any(token in text for token in ("shell=true", "system(", "exec(", "unserialize(", "pickle.loads", "parse_str(", "extract(")):
        tags.add("retains_dangerous_mechanism")
    if any(token in text for token in ("autotype", "allowed_classes", "白名单类", "白名单字段", "whitelist")):
        tags.add("whitelist_control")
    if any(token in text for token in ("allowed_classes", "白名单类", "禁止对象", "限制对象实例化", "autotype")):
        tags.add("mitigation_control")

    if family == "sqli" and "parameterized" not in tags:
        tags.add("non_parameterized")
    return tags


def _derive_group_advice_level(entries):
    statuses = {str(entry.get("repair_consistency_status", "") or "").strip() for entry in entries}
    if "mitigation_only" in statuses:
        return "临时缓解"
    if "warning" in statuses:
        return "局部修复"
    return "项目级根治建议"


def _group_chain_role(entries):
    roles = {str(entry.get("chain_role", "") or "").strip() for entry in entries}
    if "reader+writer" in roles or ("reader" in roles and "writer" in roles):
        return "reader+writer"
    if "reader" in roles:
        return "reader"
    if "writer" in roles:
        return "writer"
    return "unknown"


def _strip_secondary_noise_from_text(text, entry):
    cleaned = str(text or "")
    secondary_text = str(entry.get("secondary_findings", "") or "").strip()
    potential_text = str(entry.get("potential_secondary_findings", "") or "").strip()
    for noise in (secondary_text, potential_text):
        if noise and noise in cleaned:
            cleaned = cleaned.replace(noise, "")
    return _clean_evidence_text(cleaned)


def _refresh_root_cause_group(group):
    entries = list(group.get("entries") or [])
    group["family"] = _mode_nonempty([entry.get("root_cause_family", "") for entry in entries], default=group.get("family", ""))
    group["type_label"] = _mode_nonempty(
        [_strip_secondary_noise_from_text(entry.get("vuln_type", ""), entry) for entry in entries],
        default=VULN_FAMILY_LABELS.get(group.get("family", ""), group.get("type_label", "")),
    )
    group["input_identifier"] = _mode_nonempty([entry.get("root_cause_input", "") for entry in entries], default=group.get("input_identifier", ""))
    group["danger_api"] = _mode_nonempty(
        [_strip_secondary_noise_from_text(entry.get("root_cause_api", ""), entry) for entry in entries],
        default=group.get("danger_api", ""),
    )
    group["state_container"] = _mode_nonempty(
        [entry.get("root_cause_container", "") for entry in entries],
        default=group.get("state_container", ""),
    )
    group["chain_role"] = _group_chain_role(entries)
    format_features = set()
    for entry in entries:
        format_features.update(_split_csv_set(entry.get("root_cause_formats", "")))
    group["format_features"] = sorted(format_features)
    evidence_candidates = []
    for entry in entries:
        evidence_candidates.append(_strip_secondary_noise_from_text(entry.get("code_evidence", ""), entry))
        evidence_candidates.append(_strip_secondary_noise_from_text(entry.get("root_cause_api", ""), entry))
    group["evidence_summary"] = _mode_nonempty(evidence_candidates, default=group.get("evidence_summary", ""))
    return group


def _score_root_cause_group_match(group, entry):
    group_family = str(group.get("family", "") or "").strip()
    entry_family = str(entry.get("root_cause_family", "") or "").strip()
    if group_family and entry_family and group_family != entry_family:
        return -1

    score = 0
    group_input = str(group.get("input_identifier", "") or "").strip()
    entry_input = str(entry.get("root_cause_input", "") or "").strip()
    if group_input and entry_input:
        if group_input != entry_input:
            return -1
        score += 6

    group_container = str(group.get("state_container", "") or "").strip()
    entry_container = str(entry.get("root_cause_container", "") or "").strip()
    if group_container and entry_container:
        if group_container == entry_container:
            score += 6
        else:
            score -= 1

    group_api = str(group.get("danger_api", "") or "").strip()
    entry_api = str(entry.get("root_cause_api", "") or "").strip()
    if group_api and entry_api:
        if group_api == entry_api:
            score += 1
        else:
            score -= 1

    group_role = str(group.get("chain_role", "") or "").strip()
    entry_role = str(entry.get("chain_role", "") or "").strip()
    if (
        group_input
        and entry_input
        and group_input == entry_input
        and group_container
        and entry_container
        and group_container == entry_container
        and {group_role, entry_role} == {"reader", "writer"}
    ):
        score += 2

    group_formats = set(group.get("format_features") or [])
    entry_formats = _split_csv_set(entry.get("root_cause_formats", ""))
    if group_formats and entry_formats:
        if group_formats.intersection(entry_formats):
            score += 2
        else:
            score -= 1

    group_evidence_tokens = _tokenize_for_similarity(group.get("evidence_summary", "") or group.get("danger_api", ""))
    entry_evidence_tokens = _tokenize_for_similarity(
        entry.get("root_cause_evidence", "") or entry.get("code_evidence", "") or entry.get("root_cause_api", "")
    )
    if group_evidence_tokens and entry_evidence_tokens and group_evidence_tokens.intersection(entry_evidence_tokens):
        score += 1

    if group.get("state_container") in {"cookie", "session", "hidden_field", "session_storage", "local_storage"}:
        score += 1
    return score


def _build_fix_order(group):
    entries = list(group.get("entries") or [])
    format_features = set(group.get("format_features") or [])
    chain_role = group.get("chain_role", "unknown")
    if len(entries) < 2:
        return []
    if chain_role != "reader+writer":
        return []
    if not format_features.intersection({"serialized", "json", "base64", "yaml", "url_encoding"}):
        return []
    return [
        "1. 在写入端新增安全格式写入逻辑，并保留短期兼容开关。",
        "2. 在读取端先兼容解析新旧格式，确认业务链路稳定。",
        "3. 清理旧格式写入逻辑，统一状态结构与字段约束。",
        "4. 废弃原危险反序列化/旧解析分支并做回归验证。",
    ]


def evaluate_group_consistency(group):
    entries = list(group.get("entries") or [])
    family_hint = get_repair_mainline_hint(group.get("family", "") or group.get("type_label", ""))
    fallback_mainline = get_repair_mainline_hint("")
    has_family_mainline = normalize_vuln_family(group.get("family", "") or group.get("type_label", "")) and family_hint != fallback_mainline

    if len(entries) <= 1:
        chain_role = group.get("chain_role", "unknown")
        risk = chain_role == "reader+writer"
        partial_fix_risk = "若存在关联读写链路，仍建议联动确认。"
        if risk:
            partial_fix_risk = "同一根因同时覆盖读写两端，必须同步修改数据格式与解析逻辑。"
        unified_mainline = family_hint if has_family_mainline else (group.get("mainline_hint", "") or family_hint)
        current_level = _derive_group_advice_level(entries)
        if current_level == "临时缓解" and has_family_mainline:
            partial_fix_risk = _join_notes(partial_fix_risk, "当前方案仍属临时缓解，需按家族主线完成最终根治改造。")
        return {
            "risk": risk,
            "risk_summary": "是" if risk else "否",
            "unified_mainline": unified_mainline,
            "unified_suggestion": unified_mainline,
            "data_chain_hint": group.get("input_identifier", "") or "无",
            "partial_fix_risk": partial_fix_risk,
            "current_advice_level": current_level,
        }

    mainline_set = {str(entry.get("repair_mainline", "") or "").strip() for entry in entries if str(entry.get("repair_mainline", "") or "").strip()}
    tag_sets = [extract_repair_strategy_tags(group.get("family", ""), entry) for entry in entries]
    merged_tags = set().union(*tag_sets) if tag_sets else set()
    warnings = []
    chain_role = group.get("chain_role", "unknown")

    if len(mainline_set) > 1:
        warnings.append("同根因下修复主线不完全一致")
    if "json_format" in merged_tags and "legacy_serialization" in merged_tags:
        warnings.append("同一根因同时出现 JSON 迁移与保留原序列化，可能导致数据格式不一致")
    retains_count = sum(1 for tags in tag_sets if "retains_dangerous_mechanism" in tags)
    if 0 < retains_count < len(tag_sets):
        warnings.append("部分文件仍保留原危险机制，部分文件已迁移到新机制")
    if chain_role == "reader+writer":
        warnings.append("同一根因同时涉及读写两端，必须同步修改数据格式与解析逻辑")
    if _derive_group_advice_level(entries) == "临时缓解":
        warnings.append("当前建议仍以临时缓解为主，尚未体现项目级数据格式迁移")

    data_chain_hint = ""
    if group.get("input_identifier"):
        data_chain_hint = f"可能涉及同一输入/存储链路: {group['input_identifier']}"
    if "json_format" in merged_tags or "legacy_serialization" in merged_tags:
        data_chain_hint = _join_notes(data_chain_hint, "可能受影响的数据格式: JSON / 序列化对象")
    if group.get("state_container"):
        data_chain_hint = _join_notes(data_chain_hint, f"容器类型: {group['state_container']}")
    if group.get("format_features"):
        data_chain_hint = _join_notes(data_chain_hint, "格式特征: " + ", ".join(group.get("format_features", [])))

    non_generic_mainlines = [line for line in mainline_set if line != fallback_mainline]
    unified_mainline = family_hint if has_family_mainline else ""
    if not unified_mainline:
        if non_generic_mainlines:
            unified_mainline = sorted(non_generic_mainlines, key=len)[0]
        elif mainline_set:
            unified_mainline = sorted(mainline_set, key=len)[0]
        else:
            unified_mainline = group.get("mainline_hint") or family_hint

    current_advice_level = _derive_group_advice_level(entries)
    unified_suggestion = unified_mainline
    if group.get("input_identifier"):
        unified_suggestion = _join_notes(unified_mainline, f"建议围绕 `{group['input_identifier']}` 的全部读写位置联动修改。")
    if chain_role == "reader+writer":
        unified_suggestion = _join_notes(unified_suggestion, "读写两端需要同步切换到统一安全格式。")
    if current_advice_level == "临时缓解" and has_family_mainline:
        unified_suggestion = _join_notes(unified_suggestion, "当前补丁仍属临时缓解，最终仍需按上述家族主线完成根治改造。")

    partial_fix_risk = "若只修改部分文件，可能导致同一数据结构在不同页面/接口中的读写方式不一致。"
    if warnings:
        partial_fix_risk = _join_notes(*warnings)

    return {
        "risk": bool(warnings),
        "risk_summary": "是" if warnings else "否",
        "unified_mainline": unified_mainline,
        "unified_suggestion": unified_suggestion,
        "data_chain_hint": data_chain_hint or "无",
        "partial_fix_risk": partial_fix_risk,
        "current_advice_level": current_advice_level,
    }


def build_root_cause_summary(group):
    family_label = VULN_FAMILY_LABELS.get(group.get("family", ""), group.get("type_label", "") or "项目级根因")
    input_identifier = group.get("input_identifier", "") or "不可信输入"
    danger_api = group.get("danger_api", "") or group.get("type_label", "") or family_label
    chain_role = group.get("chain_role", "unknown")
    format_text = ", ".join(group.get("format_features", []))
    if chain_role == "reader+writer":
        return f"`{input_identifier}` 在多个文件中同时被读取与写入，并与 `{danger_api}` / `{format_text or '状态格式'}` 相关，疑似属于同一 {family_label} 根因。"
    return f"`{input_identifier}` 在多个位置进入 `{danger_api}`，疑似属于同一 {family_label} 根因。"


def aggregate_root_causes(entries):
    groups = []
    for entry in entries:
        if entry.get("suspected") not in {"是", "待人工复核"}:
            continue
        entry_group_key = str(entry.get("root_cause_key", "") or "").strip()
        if not entry_group_key:
            continue

        group = None
        for existing in groups:
            if existing.get("key") == entry_group_key:
                group = existing
                break
        if group is None:
            best_group = None
            best_score = 0
            for existing in groups:
                score = _score_root_cause_group_match(existing, entry)
                if score > best_score:
                    best_group = existing
                    best_score = score
            if best_group is not None and best_score >= 5:
                group = best_group

        if group is None:
            family_hint = get_repair_mainline_hint(entry.get("root_cause_family", "") or entry.get("vuln_type", ""))
            fallback_mainline = get_repair_mainline_hint("")
            has_family_hint = normalize_vuln_family(entry.get("root_cause_family", "") or entry.get("vuln_type", "")) and family_hint != fallback_mainline
            group = {
                "key": entry_group_key,
                "family": entry.get("root_cause_family", ""),
                "type_label": entry.get("vuln_type", ""),
                "input_identifier": entry.get("root_cause_input", ""),
                "danger_api": entry.get("root_cause_api", ""),
                "state_container": entry.get("root_cause_container", ""),
                "format_features": sorted(_split_csv_set(entry.get("root_cause_formats", ""))),
                "chain_role": entry.get("chain_role", "unknown"),
                "evidence_summary": _clean_evidence_text(entry.get("root_cause_evidence", "") or entry.get("code_evidence", "")),
                "mainline_hint": family_hint if has_family_hint else (entry.get("repair_mainline", "") or family_hint),
                "entries": [],
            }
            groups.append(group)

        group["entries"].append(entry)
        _refresh_root_cause_group(group)

    groups = sorted(groups, key=lambda item: (-len(item["entries"]), item.get("family", ""), item.get("danger_api", "")))
    for index, group in enumerate(groups, start=1):
        group_id = f"RC-{index:03d}"
        group["id"] = group_id
        group["summary"] = build_root_cause_summary(group)
        consistency = evaluate_group_consistency(group)
        group["consistency_risk"] = consistency["risk_summary"]
        group["consistency_risk_flag"] = bool(consistency["risk"])
        group["unified_mainline"] = consistency["unified_mainline"]
        group["unified_suggestion"] = consistency["unified_suggestion"]
        group["data_chain_hint"] = consistency["data_chain_hint"]
        group["partial_fix_risk"] = consistency["partial_fix_risk"]
        group["current_advice_level"] = consistency["current_advice_level"]
        group["fix_order"] = _build_fix_order(group)
        group["affected_files"] = sorted({entry["file_path"] for entry in group["entries"]})
        group["affected_locations"] = [
            f"{entry['file_path']}::{entry.get('vuln_location') or '未定位'}"
            + (f" ({entry['start_line']}-{entry['end_line']})" if entry.get("start_line") and entry.get("end_line") else "")
            for entry in group["entries"]
        ]
        for entry in group["entries"]:
            entry["root_cause_group_id"] = group_id
            entry["cross_file_consistency_risk"] = consistency["risk_summary"]
            if group.get("chain_role") != "unknown" and entry.get("chain_role") in {"", "unknown"}:
                entry["chain_role"] = group.get("chain_role", "unknown")
            if consistency["risk"]:
                entry["note"] = _join_notes(entry.get("note"), f"所属根因组 {group_id} 存在跨文件修复不一致风险")
            if group.get("chain_role") == "reader+writer":
                forced_warning = "同一根因覆盖读写两端，必须同步修改写入格式与读取解析逻辑。"
                entry["cross_file_consistency_risk"] = "是"
                entry["repair_consistency"] = _join_notes(entry.get("repair_consistency"), forced_warning)
                if entry.get("repair_consistency_status") in {"", "pass"}:
                    entry["repair_consistency_status"] = "warning"
                if not str(entry.get("repair_advice_level", "") or "").strip():
                    entry["repair_advice_level"] = consistency.get("current_advice_level") or "局部修复"
                entry["note"] = _join_notes(entry.get("note"), f"所属根因组 {group_id} 为读写联动链路，修复必须覆盖 reader 与 writer 两端")
    return groups


def _unwrap_fenced_code_block(text):
    stripped = str(text or "").strip()
    fenced_match = re.fullmatch(r"```([A-Za-z0-9_+-]*)\s*\n([\s\S]*?)\n?```", stripped)
    if not fenced_match:
        return "", stripped
    return fenced_match.group(1).strip().lower(), fenced_match.group(2).strip("\n")


def _looks_like_machine_blob(text):
    stripped = str(text or "").strip()
    if not stripped:
        return False

    lowered = stripped.lower()
    if any(marker in lowered for marker in ("[summary]", "[match]", "[replace]")):
        return True

    try:
        loaded = json.loads(stripped)
        if isinstance(loaded, (dict, list)):
            return True
    except Exception:
        pass

    literal_value = _parse_mapping_literal(stripped)
    if literal_value:
        return True
    return False


def _is_unusable_report_fix_code(text):
    stripped = str(text or "").strip()
    if not stripped or _looks_like_machine_blob(stripped):
        return True

    lowered = stripped.lower()
    bad_markers = [
        "请根据实际情况修改",
        "根据实际情况修改",
        "根据实际情况调整",
        "伪代码",
        "pseudo",
        "todo",
        "omitted",
        "省略实现",
        "example allowlist",
        "your_allowlist",
    ]
    if any(marker in lowered for marker in bad_markers):
        return True
    return bool(re.search(r"(^|\n)\s*\.\.\.\s*($|\n)", stripped))


def _looks_like_copyable_code(text):
    stripped = str(text or "").strip()
    if not stripped or _looks_like_machine_blob(stripped):
        return False
    code_markers = (
        "def ",
        "return ",
        "<?php",
        "$",
        "function ",
        "if (",
        "const ",
        "let ",
        "var ",
        "public ",
        "private ",
        "protected ",
        "import ",
        "from ",
        "exec.Command",
        "subprocess.",
    )
    if any(marker in stripped for marker in code_markers):
        return True
    return "\n" in stripped and any(char in stripped for char in "{}();[]=:")


def build_report_fix_payload(repair_result, file_path):
    repair_result = repair_result or {}
    minimal_fix = str(repair_result.get("minimal_fix", "") or "")
    summary = _short_text(repair_result.get("report_fix_summary", ""), limit=220)
    original_code = _sanitize_code_snippet(repair_result.get("original_code_snippet", ""))
    code = str(
        repair_result.get("fixed_code_snippet", "")
        or repair_result.get("report_fix_code", "")
        or ""
    ).strip()
    language = _normalize_report_fix_language("", file_path)

    fenced_language, unfenced_code = _unwrap_fenced_code_block(code)
    if fenced_language:
        language = _normalize_report_fix_language(fenced_language, file_path)
        code = unfenced_code
    if _is_unusable_report_fix_code(code):
        code = ""

    patch_sections = _extract_patch_sections(minimal_fix)
    if not summary and patch_sections["summary"]:
        summary = _short_text(patch_sections["summary"], limit=220)
    if not original_code and patch_sections["match"]:
        original_code = _sanitize_code_snippet(patch_sections["match"])
    if not code and patch_sections["replace"]:
        fenced_language, fallback_code = _unwrap_fenced_code_block(patch_sections["replace"])
        if fenced_language:
            language = _normalize_report_fix_language(fenced_language, file_path)
        if not _is_unusable_report_fix_code(fallback_code):
            code = fallback_code

    if not code and _looks_like_copyable_code(minimal_fix):
        fenced_language, fallback_code = _unwrap_fenced_code_block(minimal_fix)
        if fenced_language:
            language = _normalize_report_fix_language(fenced_language, file_path)
        if not _is_unusable_report_fix_code(fallback_code):
            code = fallback_code

    if not summary and minimal_fix and not _looks_like_machine_blob(minimal_fix):
        summary = _short_text(minimal_fix, limit=260)
    if not summary:
        summary = "需人工补全。"

    return {
        "summary": summary,
        "original_code": original_code.rstrip(),
        "code": code.rstrip(),
        "language": language,
    }


# ==========================================
# 9. Repair consistency checker
# ==========================================
class RepairConsistencyChecker:
    RULES = {
        "sqli": {
            "required": ["parameter", "prepare", "placeholder", "bind", "参数化", "预处理", "白名单"],
            "discouraged": ["blacklist", "denylist", "replace(\"'\"", "addslashes", "escape only", "过滤单引号"],
            "mainline": "参数化 / 预处理 / 白名单映射",
        },
        "upload": {
            "required": ["白名单", "pathinfo", "随机文件名", "random_bytes", "upload_root", "隔离目录", "mime"],
            "discouraged": ["原文件名", "basename(", "content-type only", "仅校验mime", "黑名单后缀"],
            "mainline": "扩展名白名单 + 隔离上传目录 + 随机文件名",
        },
        "file_write": {
            "required": ["白名单", "realpath", "commonpath", "safe_join", "固定目录", "file_map"],
            "discouraged": ["basename(", "str_replace", "仅过滤..", "直接拼接文件名", "原文件名"],
            "mainline": "固定根目录 / 白名单目标文件 / 禁止直接拼接写入路径",
        },
        "deserialization": {
            "required": ["json", "安全格式", "显式字段", "字段白名单", "schema", "map[string]", "array payload"],
            "discouraged": ["unserialize(", "pickle.loads", "yaml.load(", "readobject", "保留原序列化"],
            "mitigation": ["allowed_classes", "白名单类", "限制对象实例化", "禁止对象", "autotype", "仅允许数组"],
            "mainline": "迁移到 JSON / 安全格式 / 显式字段解析",
        },
        "ssti": {
            "required": ["fixed template", "context", "固定模板", "上下文变量", "render_template"],
            "discouraged": ["template string", "字符串拼模板", "denylist", "blacklist", "render_template_string"],
            "mainline": "固定模板 + context 变量",
        },
        "command_exec": {
            "required": ["shell=false", "参数列表", "白名单", "escapeshellarg", "subprocess.run(["],
            "discouraged": ["shell=true", "blacklist", "denylist", "eval(", "system("],
            "mainline": "参数白名单 + 参数列表化 + shell=False",
        },
        "path_traversal": {
            "required": ["realpath", "commonpath", "abspath", "白名单", "safe_join"],
            "discouraged": ["replace(\"../", "黑名单", "denylist", "startswith only"],
            "mainline": "realpath/commonpath 或白名单映射",
        },
        "dynamic_include": {
            "required": ["fixed template", "template_map", "view_map", "白名单", "固定模板", "固定视图", "映射"],
            "discouraged": ["basename(", "str_replace", "blacklist", "denylist", "拼接 include", "拼接模板"],
            "mainline": "固定模板映射 / 白名单视图选择 / 禁止直接拼接 include 路径",
        },
        "auth": {
            "required": ["verify", "signature", "claims", "统一鉴权", "验签", "过期时间"],
            "discouraged": ["decode only", "不验签", "if admin", "本地特判"],
            "mainline": "验签 + 声明校验 + 统一鉴权入口",
        },
    }

    @classmethod
    def evaluate(cls, vuln_type, repair_result):
        family = normalize_vuln_family(vuln_type)
        rule = cls.RULES.get(family)
        if not rule:
            return {"status": "pass", "mainline": "", "warning": "", "triggered": "否", "level": "局部修复"}

        repair_text = " ".join(
            [
                str(repair_result.get("report_fix_summary", "")),
                str(repair_result.get("report_fix_code", "")),
                str(repair_result.get("minimal_fix", "")),
            ]
        ).lower()

        has_required = any(token.lower() in repair_text for token in rule["required"])
        has_discouraged = any(token.lower() in repair_text for token in rule["discouraged"])
        mitigation_tokens = [token for token in rule.get("mitigation", []) if token.lower() in repair_text]
        warning_parts = []

        if mitigation_tokens and not has_required:
            warning_parts.append(f"当前修复仅为临时缓解，不符合该类型项目级主线: {rule['mainline']}")
            warning_parts.append("仍存在残留风险，后续仍需迁移到统一安全格式或显式字段解析")
            return {
                "status": "mitigation_only",
                "mainline": rule["mainline"],
                "warning": _join_notes(*warning_parts),
                "triggered": "是",
                "level": "临时缓解",
            }
        if not has_required:
            warning_parts.append(f"未体现该类型推荐主线: {rule['mainline']}")
        if has_discouraged:
            warning_parts.append("修复建议包含不推荐做法或危险模式")
        if warning_parts:
            return {
                "status": "warning",
                "mainline": rule["mainline"],
                "warning": _join_notes(*warning_parts),
                "triggered": "是",
                "level": "局部修复",
            }

        return {
            "status": "pass",
            "mainline": rule["mainline"],
            "warning": "",
            "triggered": "否",
            "level": "项目级根治建议",
        }


# ==========================================
# 10. Report generation
# ==========================================
def make_report_entry(**kwargs):
    entry = {
        "file_path": "",
        "suspected": "未分析",
        "vuln_type": "",
        "root_cause_group_id": "",
        "root_cause_fingerprint": "",
        "root_cause_key": "",
        "root_cause_family": "",
        "root_cause_input": "",
        "root_cause_api": "",
        "root_cause_container": "",
        "root_cause_formats": "",
        "root_cause_evidence": "",
        "chain_role": "unknown",
        "reason": "",
        "code_evidence": "",
        "minimal_fix": "",
        "report_fix_summary": "",
        "report_fix_code": "",
        "report_fix_language": "text",
        "vuln_location": "",
        "original_code_snippet": "",
        "fixed_code_snippet": "",
        "hard_override_family": "",
        "hard_override_reason": "",
        "polluted_source_flag": "否",
        "start_line": 0,
        "end_line": 0,
        "confidence": 0.0,
        "prescreen": "",
        "detection_basis": "",
        "knowledge_used": "否",
        "knowledge_stage": "未参与",
        "repair_mainline": "",
        "repair_consistency": "",
        "repair_consistency_status": "",
        "repair_advice_level": "",
        "kb_warning": "否",
        "cross_file_consistency_risk": "否",
        "secondary_findings": "",
        "secondary_findings_data": [],
        "potential_secondary_findings": "",
        "potential_secondary_findings_data": [],
        "syntax_check": "未执行",
        "note": "",
    }
    entry.update(kwargs)
    return entry


def evaluate_suspected(detection_result):
    verdict = detection_result.get("verdict")
    confidence = detection_result.get("confidence", 0.0)
    if verdict == "vulnerable" and confidence >= MIN_VULN_CONFIDENCE:
        return "是"
    if verdict in {"vulnerable", "needs_manual_review"}:
        return "待人工复核"
    if verdict == "safe":
        return "否"
    return "未分析"


def render_report(target_dir, entries, db_meta=None, root_cause_groups=None):
    db_meta = db_meta or {}
    root_cause_groups = root_cause_groups or []
    report_path = os.path.join(SCRIPT_DIR, "awdp_pro_report.md")

    total_count = len(entries)
    suspected_count = sum(1 for item in entries if item["suspected"] == "是")
    review_count = sum(1 for item in entries if item["suspected"] == "待人工复核")
    safe_count = sum(1 for item in entries if item["suspected"] == "否")
    other_count = total_count - suspected_count - review_count - safe_count
    risk_entries = [item for item in entries if item.get("suspected") in {"是", "待人工复核"}]
    safe_entries = [item for item in entries if item.get("suspected") == "否"]
    other_entries = [item for item in entries if item.get("suspected") not in {"是", "待人工复核", "否"}]

    def _render_location_detail(entry):
        if entry.get("start_line") and entry.get("end_line"):
            return f"{entry.get('vuln_location') or '未定'} (第 {entry['start_line']} 行 - 第 {entry['end_line']} 行)"
        return str(entry.get("vuln_location") or "未定")

    def _merge_report_text(*parts, limit=320):
        merged = []
        seen = set()
        for part in parts:
            text = str(part or "").strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            merged.append(text)
            seen.add(key)
        if not merged:
            return ""
        return _short_text("；".join(merged), limit=limit)

    def _should_show_syntax_detail(text):
        normalized = str(text or "").strip()
        if not normalized:
            return False
        if normalized.startswith("通过:") and "跳过" not in normalized:
            return False
        return True

    lines = [
        "# AWDP 审计报告",
        "",
        f"> 目标目录: `{target_dir}`",
        f"> 扫描时间(UTC): `{_utc_timestamp()}`",
        f"> 模型: `{MODEL_NAME}` | RAG: `{RAG_MODE}` | 知识库: `{db_meta.get('knowledge_role', 'unknown') or 'unknown'}` | 格式: `{REPORT_FORMAT_VERSION}`",
        "",
        "## 概览",
        "",
        f"- 文件总数: `{total_count}` | 明确疑似: `{suspected_count}` | 待人工复核: `{review_count}` | 安全: `{safe_count}`",
        "",
    ]
    if other_count:
        lines.extend([f"- 其他状态: `{other_count}`", ""])

    lines.extend(["## 项目级联动风险", ""])
    if not root_cause_groups:
        lines.extend(["- 未形成稳定的项目级联动问题。", ""])
    else:
        for group in root_cause_groups:
            family_label = group.get("type_label") or VULN_FAMILY_LABELS.get(group.get("family", ""), group.get("family", "") or "未知")
            unified_mainline = group.get("unified_mainline", "") or group.get("unified_suggestion", "")
            affected_locations = "；".join(group.get("affected_locations", [])) or "无"
            affected_files = ", ".join(group.get("affected_files", [])) or "无"
            lines.extend(
                [
                    f"### {family_label}",
                    "",
                    f"- 摘要: {group.get('summary') or '无'}",
                    f"- 影响: {affected_locations}",
                    f"- 联动文件: {affected_files}",
                    f"- 主线: {unified_mainline or '无'}",
                    f"- 建议级别: {group.get('current_advice_level') or '局部修复'}",
                ]
            )
            if group.get("chain_role") and group.get("chain_role") != "unknown":
                lines.append(f"- 链路: {group.get('chain_role')}")
            if group.get("consistency_risk") == "是":
                lines.append("- 风险: 存在跨文件修复不一致风险")
            if group.get("data_chain_hint") and group.get("data_chain_hint") != "无":
                lines.append(f"- 数据链: {group.get('data_chain_hint')}")
            if _meaningful_text(group.get("partial_fix_risk")):
                lines.append(f"- 提醒: {group.get('partial_fix_risk')}")
            if group.get("fix_order"):
                lines.append("- 顺序:")
                lines.extend(group.get("fix_order", []))
            lines.append("")

    lines.extend(["## 风险文件", ""])
    if not risk_entries:
        lines.extend(["- 未发现明确风险或待复核文件。", ""])
    else:
        for entry in risk_entries:
            lines.extend([f"### `{entry['file_path']}`", ""])
            verdict_text = "明确疑似" if entry.get("suspected") == "是" else "待人工复核"
            confidence_text = f"{float(entry.get('confidence', 0.0) or 0.0):.2f}"
            lines.append(
                f"- 结论: {verdict_text} | 类型: {entry.get('vuln_type') or '未定'} | 置信度: {confidence_text}"
            )
            if entry.get("root_cause_group_id"):
                lines.append(f"- 归属: {entry.get('root_cause_group_id')}")
            lines.append(f"- 位置: `{_render_location_detail(entry)}`")

            evidence_text = _merge_report_text(
                entry.get("reason", ""),
                _clean_evidence_text(entry.get("code_evidence", "")),
            )
            if _meaningful_text(evidence_text):
                lines.append(f"- 证据: {evidence_text}")

            repair_mainline = _short_text(entry.get("repair_mainline", ""), limit=180)
            repair_summary = _short_text(entry.get("report_fix_summary", ""), limit=260)
            if _meaningful_text(repair_mainline):
                lines.append(f"- 修复主线: {repair_mainline}")
            if _meaningful_text(repair_summary) and repair_summary != repair_mainline:
                lines.append(f"- 修复说明: {repair_summary}")

            if entry.get("cross_file_consistency_risk") == "是":
                lines.append("- 联动风险: 存在跨文件修复不一致风险")
            if _meaningful_text(entry.get("secondary_findings")):
                lines.append(f"- 次级风险: {entry.get('secondary_findings')}")
            if _meaningful_text(entry.get("potential_secondary_findings")):
                lines.append(f"- 低置信疑点: {entry.get('potential_secondary_findings')}")
            if entry.get("repair_consistency_status") in {"warning", "mitigation_only"} and _meaningful_text(entry.get("repair_consistency")):
                lines.append(f"- 一致性警告: {entry.get('repair_consistency')}")
            if entry.get("repair_consistency_status") == "mitigation_only":
                lines.append(f"- 建议级别: {entry.get('repair_advice_level') or '临时缓解'}")
            if _should_show_syntax_detail(entry.get("syntax_check", "")):
                lines.append(f"- 语法: {entry.get('syntax_check')}")

            note_text = _short_text(entry.get("note", ""), limit=220)
            if _meaningful_text(note_text) and note_text not in {evidence_text, repair_summary}:
                lines.append(f"- 备注: {note_text}")

            lines.extend(
                [
                    "",
                    "- 原始代码:",
                    f"```{entry.get('report_fix_language') or 'text'}",
                    (entry.get("original_code_snippet") or "未提供稳定原始代码片段。").rstrip(),
                    "```",
                    "",
                    "- 建议修复:",
                    f"```{entry.get('report_fix_language') or 'text'}",
                    (entry.get("fixed_code_snippet") or entry.get("report_fix_code") or "需人工补全").rstrip(),
                    "```",
                    "",
                ]
            )

    lines.extend(["## 安全文件", ""])
    if not safe_entries:
        lines.extend(["- 无。", ""])
    else:
        for entry in safe_entries:
            detail_parts = [_short_text(entry.get("prescreen") or "未命中高危候选", limit=140)]
            if _should_show_syntax_detail(entry.get("syntax_check", "")):
                detail_parts.append(f"语法: {entry.get('syntax_check')}")
            lines.append(f"- `{entry['file_path']}`: " + "；".join(part for part in detail_parts if _meaningful_text(part)))
        lines.append("")

    if other_entries:
        lines.extend(["## 其他状态", ""])
        for entry in other_entries:
            detail_text = _merge_report_text(entry.get("note", ""), entry.get("prescreen", ""), limit=180) or "未完成稳定分析。"
            extra_parts = [detail_text]
            if _should_show_syntax_detail(entry.get("syntax_check", "")):
                extra_parts.append(f"语法: {entry.get('syntax_check')}")
            lines.append(f"- `{entry['file_path']}`: {entry.get('suspected') or '未分析'}；" + "；".join(extra_parts))
        lines.append("")

    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write("\n".join(lines))
    return report_path


# ==========================================
# 11. Scan directory / main
# ==========================================
def audit_single_file(file_path, code_content, vector_db, project_context=None):
    rel_path = _relative_path(file_path)
    ext = os.path.splitext(file_path)[1].lower()
    syntax_check = validate_file(file_path, code_content, ext)
    heuristic_meta = run_heuristic_prescreen(code_content, file_path=file_path, project_context=project_context)
    plan = build_scan_plan(file_path, code_content, project_context=project_context, heuristic_meta=heuristic_meta)
    detection_result = {}
    repair_result = _default_repair_result()
    knowledge_meta = _default_knowledge_result()
    detection_basis = "规则预筛 + LLM 代码上下文判定"
    if heuristic_meta.get("force_deep_scan"):
        detection_basis += "（启发式强制送检）"

    if plan["status"] == "prescreen_only":
        detection_result = {
            "verdict": "safe",
            "vuln_type": "",
            "reason": plan["reason"],
            "code_evidence": plan["reason"],
            "confidence": 0.0,
        }
        entry = make_report_entry(
            file_path=rel_path,
            suspected="否",
            vuln_type=detection_result.get("vuln_type", ""),
            reason=detection_result.get("reason", ""),
            code_evidence=detection_result.get("code_evidence", ""),
            polluted_source_flag=plan.get("polluted_source_flag", "否"),
            minimal_fix="未触发深度分析。",
            confidence=detection_result.get("confidence", 0.0),
            prescreen=plan["note"],
            detection_basis="仅预筛",
            knowledge_used="否",
            knowledge_stage="未参与",
            repair_mainline="",
            repair_consistency="未进入修复阶段",
            kb_warning="否",
            syntax_check=format_check_result(syntax_check),
            note=plan["note"],
        )
        return {"entry": entry, "rel_path": rel_path}

    prejudge_meta = _default_knowledge_result()
    if RAG_MODE == "prejudge":
        prejudge_meta = search_knowledge_base(vector_db, plan, {}, phase="prejudge")
        if prejudge_meta.get("used"):
            detection_basis += "（实验：判定前知识库参与）"
    detection_prompt = build_detection_prompt(file_path, plan, prejudge_meta)
    detection_call = call_ollama(detection_prompt, DETECTION_NUM_PREDICT)
    if not detection_call["ok"]:
        detection_result = {
            "verdict": "needs_manual_review",
            "vuln_type": "",
            "reason": detection_call["error"],
            "code_evidence": plan["reason"],
            "confidence": 0.0,
        }
    else:
        detection_result = parse_detection_output(detection_call["text"])

    detection_result, override_meta = _apply_hard_override(file_path, code_content, plan, detection_result, heuristic_meta=heuristic_meta)
    if override_meta.get("triggered"):
        detection_basis += " + 硬规则兜底"

    if detection_result.get("verdict") in {"vulnerable", "needs_manual_review"}:
        if RAG_MODE in {"repair_only", "prejudge"}:
            knowledge_meta = search_knowledge_base(vector_db, plan, detection_result, phase="repair")
        repair_prompt = build_repair_prompt(file_path, plan, detection_result, knowledge_meta)
        repair_call = call_ollama(repair_prompt, REPAIR_NUM_PREDICT)
        if repair_call["ok"]:
            repair_result = parse_repair_output(repair_call["text"])
        else:
            repair_result = _default_repair_result()
            repair_result["minimal_fix"] = repair_call["error"]
            repair_result["report_fix_summary"] = "模型未返回稳定修复建议，请人工复核。"
    else:
        repair_result = _default_repair_result()
        if not knowledge_meta.get("used"):
            knowledge_meta = _default_knowledge_result()

    consistency_result = RepairConsistencyChecker.evaluate(detection_result.get("vuln_type", ""), repair_result)
    if detection_result.get("verdict") in {"vulnerable", "needs_manual_review"}:
        report_fix = build_report_fix_payload(repair_result, file_path)
    else:
        report_fix = {"summary": "", "original_code": "", "code": "", "language": _normalize_report_fix_language("", file_path)}

    location_result = locate_code_snippet(code_content, report_fix.get("original_code", ""))
    original_display = report_fix.get("original_code", "")
    if location_result.get("matched_snippet"):
        original_display = location_result["matched_snippet"]
    secondary_meta = collect_secondary_findings(file_path, code_content, plan, detection_result)
    secondary_findings_list = secondary_meta.get("findings", [])
    potential_secondary_findings_list = secondary_meta.get("potential_findings", [])
    secondary_findings = format_secondary_findings(secondary_findings_list)
    potential_secondary_findings = format_potential_secondary_findings(potential_secondary_findings_list)
    root_cause_meta = build_root_cause_metadata(file_path, code_content, plan, detection_result, repair_result)

    entry = make_report_entry(
        file_path=rel_path,
        suspected=evaluate_suspected(detection_result),
        vuln_type=detection_result.get("vuln_type", ""),
        root_cause_group_id="",
        root_cause_fingerprint=root_cause_meta.get("fingerprint", ""),
        root_cause_key=root_cause_meta.get("group_key", ""),
        root_cause_family=root_cause_meta.get("family", ""),
        root_cause_input=root_cause_meta.get("input_identifier", ""),
        root_cause_api=root_cause_meta.get("danger_api", ""),
        root_cause_container=root_cause_meta.get("state_container", ""),
        root_cause_formats=root_cause_meta.get("format_features", ""),
        root_cause_evidence=root_cause_meta.get("evidence_summary", ""),
        chain_role=root_cause_meta.get("chain_role", "unknown"),
        hard_override_family=override_meta.get("family") or detection_result.get("hard_override_family", "") or heuristic_meta.get("hard_override_family", ""),
        hard_override_reason=override_meta.get("detail") or detection_result.get("hard_override_reason", "") or heuristic_meta.get("hard_override_reason", ""),
        polluted_source_flag="是" if heuristic_meta.get("is_source_highly_polluted") else "否",
        reason=detection_result.get("reason", ""),
        code_evidence=_clean_evidence_text(detection_result.get("code_evidence", "")),
        minimal_fix=repair_result.get("minimal_fix", ""),
        report_fix_summary=report_fix.get("summary", ""),
        report_fix_code=report_fix.get("code", ""),
        report_fix_language=report_fix.get("language", "text"),
        vuln_location=repair_result.get("vuln_location", ""),
        original_code_snippet=original_display,
        fixed_code_snippet=report_fix.get("code", ""),
        start_line=location_result.get("start_line", 0),
        end_line=location_result.get("end_line", 0),
        confidence=detection_result.get("confidence", 0.0),
        prescreen=plan["note"],
        detection_basis=detection_basis,
        knowledge_used="是" if knowledge_meta.get("used") else "否",
        knowledge_stage=knowledge_meta.get("stage", "未参与"),
        repair_mainline=repair_result.get("repair_mainline")
        or consistency_result.get("mainline")
        or get_repair_mainline_hint(detection_result.get("vuln_type", "")),
        repair_consistency="通过" if consistency_result.get("status") == "pass" else consistency_result.get("warning", ""),
        repair_consistency_status=consistency_result.get("status", ""),
        repair_advice_level=consistency_result.get("level", ""),
        kb_warning=consistency_result.get("triggered", "否"),
        cross_file_consistency_risk="否",
        secondary_findings=secondary_findings,
        secondary_findings_data=secondary_findings_list,
        potential_secondary_findings=potential_secondary_findings,
        potential_secondary_findings_data=potential_secondary_findings_list,
        syntax_check=format_check_result(syntax_check),
        note=_join_notes(
            plan.get("focus"),
            knowledge_meta.get("note"),
            secondary_findings if secondary_findings else "",
            potential_secondary_findings if potential_secondary_findings else "",
            secondary_meta.get("review_note", ""),
            override_meta.get("reason", ""),
            "输入源被标记为高污染上下文" if heuristic_meta.get("is_source_highly_polluted") else "",
            "未能本地反算行号" if report_fix.get("original_code") and not location_result.get("matched") else "",
        ),
    )
    return {"entry": entry, "rel_path": rel_path}


def scan_directory(target_dir, vector_db=None):
    print(f"{Colors.BLUE}开始扫描目录: {target_dir}{Colors.RESET}")
    print(
        f"{Colors.BLUE}当前策略: 规则预筛 -> LLM 判定 -> 修复约束 -> 人工修复建议 | "
        f"RAG_MODE={RAG_MODE}{Colors.RESET}"
    )
    print(
        f"{Colors.BLUE}目录策略: AWDP_SCAN_UPLOADS={'on' if SCAN_UPLOADS else 'off'} | "
        f"忽略目录={','.join(sorted(IGNORE_DIRS)) or '无'}{Colors.RESET}"
    )

    db_meta = load_db_metadata()
    entries = []
    tasks = []

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [directory for directory in dirs if directory.lower() not in IGNORE_DIRS]
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                continue

            file_path = os.path.join(root, filename)
            rel_path = _relative_path(file_path)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as code_file:
                    code_content = code_file.read()
            except Exception as exc:
                entries.append(
                    make_report_entry(
                        file_path=rel_path,
                        suspected="未分析",
                        prescreen="读取失败",
                        detection_basis="未执行",
                        syntax_check="未执行",
                        note=f"文件读取失败: {exc}",
                    )
                )
                continue

            if not code_content.strip():
                entries.append(
                    make_report_entry(
                        file_path=rel_path,
                        suspected="否",
                        prescreen="空文件",
                        detection_basis="未执行",
                        reason="文件为空。",
                        syntax_check="未执行",
                        note="空文件未进入审计流程。",
                    )
                )
                continue

            tasks.append((file_path, code_content))

    project_context = build_project_context(tasks)
    effective_workers = max(1, MAX_WORKERS)
    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        future_map = {
            executor.submit(
                audit_single_file,
                file_path,
                code_content,
                vector_db,
                project_context,
            ): _relative_path(file_path)
            for file_path, code_content in tasks
        }

        for future in as_completed(future_map):
            rel_path = future_map[future]
            try:
                result = future.result()
                entry = result["entry"]
                entries.append(entry)

                if entry["suspected"] == "是":
                    status_icon = "🚨 VULN"
                    vuln_info = f"  ->  {entry['vuln_type'] or '未定'}"
                elif entry["suspected"] == "待人工复核":
                    status_icon = "⚠️ WARN"
                    vuln_info = f"  ->  {entry['vuln_type'] or '未定'} (需人工复核)"
                else:
                    status_icon = "✅ SAFE"
                    vuln_info = ""
                
                output_path = entry['file_path'].ljust(60)
                print(f"[{status_icon}]  {output_path}{vuln_info}")
            except Exception as exc:
                entries.append(
                    make_report_entry(
                        file_path=rel_path,
                        suspected="未分析",
                        prescreen="执行失败",
                        detection_basis="异常",
                        syntax_check="未执行",
                        note=f"单文件处理异常: {exc}",
                    )
                )

    entries.sort(key=lambda item: item["file_path"])
    root_cause_groups = aggregate_root_causes(entries)
    report_path = render_report(target_dir, entries, db_meta=db_meta, root_cause_groups=root_cause_groups)
    print(f"{Colors.GREEN}审计完成，报告已写入: {report_path}{Colors.RESET}")
    return report_path


if __name__ == "__main__":
    if not check_ollama_status():
        raise SystemExit(1)

    vector_db = init_vector_db(DB_DIRECTORY)
    if not os.path.isdir(TARGET_DIRECTORY):
        print(f"{Colors.RED}目标目录不存在: {TARGET_DIRECTORY}{Colors.RESET}")
        raise SystemExit(1)

    scan_directory(TARGET_DIRECTORY, vector_db=vector_db)
