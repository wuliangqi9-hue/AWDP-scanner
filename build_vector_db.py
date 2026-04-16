import json
import os
import shutil
import time
import warnings

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
    from langchain_community.document_loaders import DirectoryLoader, TextLoader
    from langchain_text_splitters import MarkdownTextSplitter
    from langchain_huggingface import HuggingFaceEmbeddings
    from langchain_chroma import Chroma
except ImportError as exc:
    print(f"缺少向量库构建依赖: {exc}")
    raise SystemExit(1)


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


def _get_env_bool(name, default=False):
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


# ==========================================
# 配置区域
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE_DIR = os.path.join(SCRIPT_DIR, "wp_knowledge")
DB_DIR = os.path.join(SCRIPT_DIR, "chroma_db")
MODELS_DIR = os.path.join(SCRIPT_DIR, "models")
DB_META_PATH = os.path.join(DB_DIR, ".awdp_db_meta.json")

EMBED_MODEL_NAME = os.getenv("AWDP_EMBED_MODEL_NAME", "all-MiniLM-L6-v2").strip() or "all-MiniLM-L6-v2"
EMBED_MODEL_PATH = _resolve_local_path(
    os.getenv("AWDP_EMBED_MODEL_PATH", os.path.join("models", EMBED_MODEL_NAME)).strip()
)

CHUNK_SIZE = _get_env_int("AWDP_RAG_CHUNK_SIZE", 2500)
CHUNK_OVERLAP = _get_env_int("AWDP_RAG_CHUNK_OVERLAP", 200, minimum=0)
KNOWLEDGE_GLOB = os.getenv("AWDP_KNOWLEDGE_GLOB", "**/*.md").strip() or "**/*.md"
RAG_ROLE = "repair_constraints_only"
RAG_STRATEGY_VERSION = "awdp-repair-only-v2"
REBUILD_DB = _get_env_bool("AWDP_REBUILD_DB", False)


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
    except TypeError:
        return HuggingFaceEmbeddings(model_name=model_path)


def write_db_metadata(document_count, source_file_count, rebuild_info=None):
    os.makedirs(DB_DIR, exist_ok=True)
    rebuild_info = rebuild_info or {}
    metadata = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "last_build_time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "embedding_model_name": EMBED_MODEL_NAME,
        "embedding_model_path": EMBED_MODEL_PATH,
        "chunk_size": CHUNK_SIZE,
        "chunk_overlap": CHUNK_OVERLAP,
        "knowledge_glob": KNOWLEDGE_GLOB,
        "document_count": document_count,
        "knowledge_file_count": source_file_count,
        "knowledge_role": RAG_ROLE,
        "strategy_version": RAG_STRATEGY_VERSION,
        "rebuild_requested": bool(rebuild_info.get("requested")),
        "full_rebuild": bool(rebuild_info.get("full_rebuild")),
        "backup_path": rebuild_info.get("backup_path", ""),
    }
    temp_path = DB_META_PATH + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as meta_file:
        json.dump(metadata, meta_file, ensure_ascii=False, indent=2)
    os.replace(temp_path, DB_META_PATH)


def prepare_db_directory():
    info = {"requested": REBUILD_DB, "full_rebuild": False, "backup_path": ""}
    if not os.path.exists(DB_DIR):
        return info

    if not REBUILD_DB:
        print("\033[93m检测到已有向量库，默认执行干净重建，将在写入前清理旧库目录。\033[0m")
        return info

    backup_path = f"{DB_DIR}_bak_{int(time.time())}"
    suffix = 1
    while os.path.exists(backup_path):
        backup_path = f"{DB_DIR}_bak_{int(time.time())}_{suffix}"
        suffix += 1

    os.rename(DB_DIR, backup_path)
    info["full_rebuild"] = True
    info["backup_path"] = backup_path
    print(f"已将旧向量库重命名为备份目录: {backup_path}")
    print(f"正在按 AWDP_REBUILD_DB=1 全量重建: {DB_DIR}")
    return info


def finalize_rebuild_backup(rebuild_info, success):
    backup_path = str((rebuild_info or {}).get("backup_path") or "").strip()
    if not backup_path or not os.path.exists(backup_path):
        return
    if success:
        shutil.rmtree(backup_path, ignore_errors=True)
        print(f"新向量库构建成功，已删除旧库备份目录: {backup_path}")
    else:
        print(f"构建失败，旧向量库备份仍保留: {backup_path}")


def build_database():
    print(f"正在读取知识库目录: {KNOWLEDGE_DIR}")
    print(f"Embedding 模型路径: {EMBED_MODEL_PATH}")
    print("知识库角色: 仅用于修复约束 / 修复复核，不作为漏洞判定依据。")
    rebuild_info = prepare_db_directory()

    try:
        if not os.path.exists(KNOWLEDGE_DIR):
            os.makedirs(KNOWLEDGE_DIR)
            print(f"已创建知识库目录: {KNOWLEDGE_DIR}")
            print("当前目录为空，请先放入本地知识文档后再运行。")
            return

        loader = DirectoryLoader(
            KNOWLEDGE_DIR,
            glob=KNOWLEDGE_GLOB,
            loader_cls=TextLoader,
            loader_kwargs={"autodetect_encoding": True},
        )
        documents = loader.load()

        if not documents:
            print(f"知识库目录为空或未匹配到文档: {KNOWLEDGE_DIR}")
            return

        print("正在按 Markdown 结构切分文档...")
        text_splitter = MarkdownTextSplitter(chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP)
        texts = text_splitter.split_documents(documents)

        if not texts:
            print("文档切分结果为空，未构建向量库。")
            return

        print("正在加载本地 embedding 模型...")
        embeddings = build_local_embeddings()

        if os.path.exists(DB_DIR):
            print(f"检测到旧向量库目录，正在彻底清理: {DB_DIR}")
            shutil.rmtree(DB_DIR)

        print(f"正在构建并持久化向量库: {DB_DIR}")
        Chroma.from_documents(texts, embeddings, persist_directory=DB_DIR)
        write_db_metadata(len(texts), len(documents), rebuild_info=rebuild_info)
        finalize_rebuild_backup(rebuild_info, success=True)

        print(f"知识库构建完成，共读取 {len(documents)} 个 Markdown 文件，生成 {len(texts)} 个片段。")
        print(f"向量库已保存到: {DB_DIR}")
        print(f"向量库元数据已保存到: {DB_META_PATH}")
    except Exception:
        finalize_rebuild_backup(rebuild_info, success=False)
        raise


if __name__ == "__main__":
    try:
        build_database()
    except Exception as exc:
        print(f"构建失败: {exc}")
        raise SystemExit(1)
