import hashlib
import json
import os
import re
import shutil
import sys
import time
import uuid
import warnings

from awdp_scanner.rag import directory_content_digest, enrich_knowledge_chunks

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


def _load_local_dotenv():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dotenv_candidates = [os.path.join(script_dir, ".env"), os.path.join(os.getcwd(), ".env")]
    dotenv_path = next((path for path in dotenv_candidates if os.path.isfile(path)), "")
    if not dotenv_path:
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
    from langchain_community.document_loaders import DirectoryLoader, TextLoader
    from langchain_text_splitters import MarkdownTextSplitter
    from langchain_huggingface import HuggingFaceEmbeddings
    from langchain_chroma import Chroma
except ImportError as exc:
    DirectoryLoader = TextLoader = MarkdownTextSplitter = HuggingFaceEmbeddings = Chroma = None
    BUILD_DEPENDENCY_ERROR = str(exc)
else:
    BUILD_DEPENDENCY_ERROR = ""


def _resolve_local_path(path_value):
    if os.path.isabs(path_value):
        return path_value
    script_dir = os.path.dirname(os.path.abspath(__file__))
    configured_workspace = os.getenv("AWDP_WORKSPACE_DIRECTORY", "").strip()
    source_checkout = os.path.isdir(os.path.join(script_dir, "wp_knowledge"))
    workspace = configured_workspace or (script_dir if source_checkout else os.getcwd())
    return os.path.abspath(os.path.join(workspace, path_value))


def _get_env_int(name, default, minimum=1):
    raw_value = os.getenv(name, str(default)).strip()
    try:
        value = int(raw_value)
    except ValueError:
        return default
    return max(minimum, value)


# ==========================================
# 配置区域
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_KNOWLEDGE_DIR = os.path.join(SCRIPT_DIR, "wp_knowledge")
INSTALLED_KNOWLEDGE_DIR = os.path.join(sys.prefix, "share", "awdp-scanner", "wp_knowledge")
KNOWLEDGE_DIR = _resolve_local_path(os.getenv("AWDP_KNOWLEDGE_DIRECTORY", "wp_knowledge"))
if not os.path.isdir(KNOWLEDGE_DIR) and os.path.isdir(INSTALLED_KNOWLEDGE_DIR):
    KNOWLEDGE_DIR = INSTALLED_KNOWLEDGE_DIR
DB_DIR = _resolve_local_path(os.getenv("AWDP_DB_DIRECTORY", "chroma_db").strip() or "chroma_db")
MODELS_DIR = _resolve_local_path("models")
DB_META_PATH = os.path.join(DB_DIR, ".awdp_db_meta.json")

EMBED_MODEL_NAME = os.getenv("AWDP_EMBED_MODEL_NAME", "all-MiniLM-L6-v2").strip() or "all-MiniLM-L6-v2"
EMBED_MODEL_PATH = _resolve_local_path(
    os.getenv("AWDP_EMBED_MODEL_PATH", os.path.join("models", EMBED_MODEL_NAME)).strip()
)

CHUNK_SIZE = _get_env_int("AWDP_RAG_CHUNK_SIZE", 2500)
CHUNK_OVERLAP = _get_env_int("AWDP_RAG_CHUNK_OVERLAP", 200, minimum=0)
KNOWLEDGE_GLOB = os.getenv("AWDP_KNOWLEDGE_GLOB", "**/*.md").strip() or "**/*.md"
RAG_ROLE = "repair_constraints_only"
RAG_STRATEGY_VERSION = "awdp-repair-only-v3-hybrid"
KNOWLEDGE_LABEL_SCHEMA_VERSION = "awdp-kb-labels-v1"


def parse_knowledge_metadata(content, source=""):
    text = str(content or "")
    title_match = re.search(r"^#\s+(.+?)\s*$", text, re.M)
    label_section = re.search(r"^##\s+机器可读标签\s*$([\s\S]*?)(?=^##\s+|\Z)", text, re.M)
    raw_labels = {}
    if label_section:
        for key, value in re.findall(r"^-\s*([^:：]+)\s*[:：]\s*(.*?)\s*$", label_section.group(1), re.M):
            raw_labels[key.strip()] = value.strip()

    def boolean_label(*names):
        return any(raw_labels.get(name, "").lower() in {"是", "true", "yes", "1"} for name in names)

    return {
        "doc_id": os.path.basename(str(source or "")),
        "title": title_match.group(1).strip() if title_match else "",
        "families": raw_labels.get("适用family", ""),
        "languages": raw_labels.get("适用语言", ""),
        "document_role": raw_labels.get("文档角色", ""),
        "supports_mitigation_only": boolean_label("支持mitigation_only", "支持mitigation_only信号"),
        "supports_cross_file_risk": boolean_label("支持cross_file_risk", "支持cross_file_risk信号"),
        "supports_chain_role": boolean_label("支持chain_role信号"),
        "label_schema_version": KNOWLEDGE_LABEL_SCHEMA_VERSION,
        "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def annotate_knowledge_documents(documents):
    for document in documents:
        existing = dict(getattr(document, "metadata", {}) or {})
        existing.update(parse_knowledge_metadata(document.page_content, existing.get("source", "")))
        document.metadata = existing
    return documents


def knowledge_corpus_digest(documents):
    digest = hashlib.sha256()
    ordered = sorted(
        documents,
        key=lambda document: str((getattr(document, "metadata", {}) or {}).get("source", "")),
    )
    for document in ordered:
        metadata = getattr(document, "metadata", {}) or {}
        digest.update(str(metadata.get("source", "")).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(document.page_content).encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def get_embedding_model_path(required=False):
    if os.path.isdir(EMBED_MODEL_PATH):
        return EMBED_MODEL_PATH

    message = (
        f"本地 embedding 模型目录不存在: {EMBED_MODEL_PATH}。"
        f"请将 `{EMBED_MODEL_NAME}` 放到脚本目录下的 models 目录，或设置 AWDP_EMBED_MODEL_PATH。"
    )
    if required:
        raise FileNotFoundError(message)
    print(f"注意: {message}")
    return None


def build_local_embeddings():
    model_path = get_embedding_model_path(required=True)
    try:
        return HuggingFaceEmbeddings(
            model_name=model_path,
            model_kwargs={"local_files_only": True},
        )
    except Exception as exc:
        raise RuntimeError(
            "本地 embedding 模型加载失败；为保证离线性，不会回退到可能联网下载的加载方式。"
        ) from exc


def write_db_metadata(
    document_count,
    source_file_count,
    rebuild_info=None,
    db_dir=DB_DIR,
    corpus_digest="",
):
    os.makedirs(db_dir, exist_ok=True)
    rebuild_info = rebuild_info or {}
    metadata = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "last_build_time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "embedding_model_name": EMBED_MODEL_NAME,
        "embedding_model_path": EMBED_MODEL_PATH,
        "embedding_model_sha256": directory_content_digest(EMBED_MODEL_PATH),
        "chunk_size": CHUNK_SIZE,
        "chunk_overlap": CHUNK_OVERLAP,
        "knowledge_glob": KNOWLEDGE_GLOB,
        "document_count": document_count,
        "knowledge_file_count": source_file_count,
        "knowledge_role": RAG_ROLE,
        "strategy_version": RAG_STRATEGY_VERSION,
        "label_schema_version": KNOWLEDGE_LABEL_SCHEMA_VERSION,
        "knowledge_corpus_sha256": corpus_digest,
        "rebuild_requested": bool(rebuild_info.get("requested")),
        "full_rebuild": bool(rebuild_info.get("full_rebuild")),
        "backup_path": rebuild_info.get("backup_path", ""),
    }
    meta_path = os.path.join(db_dir, ".awdp_db_meta.json")
    temp_path = meta_path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as meta_file:
        json.dump(metadata, meta_file, ensure_ascii=False, indent=2)
        meta_file.flush()
        os.fsync(meta_file.fileno())
    os.replace(temp_path, meta_path)


def _install_staged_database(staging_dir, destination_dir):
    backup_dir = f"{destination_dir}.backup-{uuid.uuid4().hex[:8]}"
    had_previous = os.path.exists(destination_dir)
    if had_previous:
        os.replace(destination_dir, backup_dir)
    try:
        os.replace(staging_dir, destination_dir)
    except Exception:
        if had_previous and os.path.exists(backup_dir) and not os.path.exists(destination_dir):
            os.replace(backup_dir, destination_dir)
        raise
    if had_previous and os.path.exists(backup_dir):
        shutil.rmtree(backup_dir)
    return had_previous


def build_database(knowledge_dir=KNOWLEDGE_DIR, db_dir=DB_DIR):
    if BUILD_DEPENDENCY_ERROR:
        raise RuntimeError(f"缺少向量库构建依赖: {BUILD_DEPENDENCY_ERROR}；请安装 `awdp-scanner[rag]`。")
    print(f"正在读取知识库目录: {knowledge_dir}")
    print(f"Embedding 模型路径: {EMBED_MODEL_PATH}")
    print("知识库角色: 仅用于修复约束 / 修复复核，不作为漏洞判定依据。")
    staging_dir = f"{db_dir}.building-{uuid.uuid4().hex[:8]}"

    try:
        if not os.path.exists(knowledge_dir):
            os.makedirs(knowledge_dir)
            print(f"已创建知识库目录: {knowledge_dir}")
            print("当前目录为空，请先放入本地知识文档后再运行。")
            return False

        loader = DirectoryLoader(
            knowledge_dir,
            glob=KNOWLEDGE_GLOB,
            loader_cls=TextLoader,
            loader_kwargs={"autodetect_encoding": True},
        )
        documents = loader.load()

        if not documents:
            print(f"知识库目录为空或未匹配到文档: {knowledge_dir}")
            return False

        annotate_knowledge_documents(documents)
        corpus_digest = knowledge_corpus_digest(documents)

        print("正在按 Markdown 结构切分文档...")
        text_splitter = MarkdownTextSplitter(chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP)
        texts = text_splitter.split_documents(documents)

        if not texts:
            print("文档切分结果为空，未构建向量库。")
            return False
        texts = enrich_knowledge_chunks(texts)

        print("正在加载本地 embedding 模型...")
        embeddings = build_local_embeddings()

        print(f"正在临时目录构建向量库: {staging_dir}")
        Chroma.from_documents(texts, embeddings, persist_directory=staging_dir)
        rebuild_info = {
            "requested": True,
            "full_rebuild": True,
            "backup_path": "transactional-swap",
        }
        write_db_metadata(
            len(texts),
            len(documents),
            rebuild_info=rebuild_info,
            db_dir=staging_dir,
            corpus_digest=corpus_digest,
        )
        replaced_previous = _install_staged_database(staging_dir, db_dir)

        print(f"知识库构建完成，共读取 {len(documents)} 个 Markdown 文件，生成 {len(texts)} 个片段。")
        print(f"向量库已原子替换到: {db_dir}（替换旧库: {'是' if replaced_previous else '否'}）")
        print(f"向量库元数据已保存到: {os.path.join(db_dir, '.awdp_db_meta.json')}")
        return True
    except Exception:
        if os.path.exists(staging_dir):
            shutil.rmtree(staging_dir, ignore_errors=True)
        raise


if __name__ == "__main__":
    try:
        build_database()
    except Exception as exc:
        print(f"构建失败: {exc}")
        raise SystemExit(1)
