"""
Microsoft-Email-Manager 邮件管理系统 - 主应用模块

基于FastAPI和IMAP协议的高性能邮件管理系统
支持多账户管理、邮件查看、搜索过滤等功能

Author: Microsoft-Email-Manager Team
Version: 1.0.0
"""

import asyncio
import email
import html as html_lib
import hashlib
import hmac
import imaplib
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from itertools import groupby
from pathlib import Path
from queue import Empty, Queue
from typing import Any, AsyncGenerator, List, Optional
from urllib.parse import quote, urlparse

import httpx
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field



# ============================================================================
# 配置常量
# ============================================================================

# 文件路径配置
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
ACCOUNTS_FILE = Path(os.getenv("ACCOUNTS_FILE", str(DATA_DIR / "accounts.json")))
AUTH_FILE = Path(os.getenv("AUTH_FILE", str(DATA_DIR / "auth.json")))
SESSIONS_FILE = Path(os.getenv("SESSIONS_FILE", str(DATA_DIR / "sessions.json")))
API_KEYS_FILE = Path(os.getenv("API_KEYS_FILE", str(DATA_DIR / "api_keys.json")))
PUBLIC_SHARES_FILE = Path(os.getenv("PUBLIC_SHARES_FILE", str(DATA_DIR / "public_shares.json")))
OPEN_ACCESS_SESSIONS_FILE = Path(os.getenv("OPEN_ACCESS_SESSIONS_FILE", str(DATA_DIR / "open_access_sessions.json")))
ADMIN_LOGIN_ATTEMPTS_FILE = Path(os.getenv("ADMIN_LOGIN_ATTEMPTS_FILE", str(DATA_DIR / "admin_login_attempts.json")))
ACCOUNT_HEALTH_FILE = Path(os.getenv("ACCOUNT_HEALTH_FILE", str(DATA_DIR / "account_health.json")))
ACCOUNT_CLASSIFICATIONS_FILE = Path(os.getenv("ACCOUNT_CLASSIFICATIONS_FILE", str(DATA_DIR / "account_classifications.json")))
EMAIL_TAGS_FILE = Path(os.getenv("EMAIL_TAGS_FILE", str(DATA_DIR / "email_tags.json")))
SITE_SETTINGS_FILE = Path(os.getenv("SITE_SETTINGS_FILE", str(DATA_DIR / "site_settings.json")))
STATIC_DIR = BASE_DIR / "static"
ICON_CACHE_DIR = DATA_DIR / "icon_cache"
ICON_ASSET_DIR = STATIC_DIR / "assets" / "icons"
SESSION_COOKIE = "outlookmanager_session"
SESSION_TTL_HOURS = max(1, int(os.getenv("SESSION_TTL_HOURS", "24")))
API_KEY_PREFIX = "om_"
API_KEY_USAGE_LOG_LIMIT = 500
OPEN_ACCESS_SESSION_TTL_HOURS = max(1, int(os.getenv("OPEN_ACCESS_SESSION_TTL_HOURS", "12")))
OPEN_ACCESS_FAILURE_LIMIT = max(1, int(os.getenv("OPEN_ACCESS_FAILURE_LIMIT", "5")))
OPEN_ACCESS_FAILURE_WINDOW_MINUTES = max(1, int(os.getenv("OPEN_ACCESS_FAILURE_WINDOW_MINUTES", "15")))
OPEN_ACCESS_LOCKOUT_MINUTES = max(1, int(os.getenv("OPEN_ACCESS_LOCKOUT_MINUTES", "15")))
ADMIN_LOGIN_FAILURE_LIMIT = max(1, int(os.getenv("ADMIN_LOGIN_FAILURE_LIMIT", "5")))
ADMIN_LOGIN_FAILURE_WINDOW_MINUTES = max(1, int(os.getenv("ADMIN_LOGIN_FAILURE_WINDOW_MINUTES", "15")))
ADMIN_LOGIN_LOCKOUT_MINUTES = max(1, int(os.getenv("ADMIN_LOGIN_LOCKOUT_MINUTES", "15")))
TRUST_PROXY_HEADERS = str(os.getenv("TRUST_PROXY_HEADERS", "")).strip().lower() in {"1", "true", "yes", "on"}
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
DEFAULT_ADMIN_LOGIN_PATH = "/admin"
DEFAULT_HOME_TITLE = "Microsoft-Email-Manager"
DEFAULT_HOME_INTRO = "批量管理 微软邮箱账户\n邮件与 API 自动化中枢"

# OAuth2配置
TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
IMAP_OAUTH_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
GRAPH_OAUTH_SCOPE = "https://graph.microsoft.com/Mail.Read offline_access"
GRAPH_API_BASE_URL = "https://graph.microsoft.com/v1.0"
COMMON_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
DEFAULT_ACCOUNT_AUTH_METHOD = "imap"
SUPPORTED_ACCOUNT_AUTH_METHODS = {"imap", "graph"}

# IMAP服务器配置
IMAP_SERVER = "outlook.live.com"
IMAP_PORT = 993

# 连接池配置
MAX_CONNECTIONS = 5
CONNECTION_TIMEOUT = 30
SOCKET_TIMEOUT = 15

# 缓存配置
CACHE_EXPIRE_TIME = 60  # 缓存过期时间（秒）
CLASSIFICATION_KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
BUILTIN_CLASSIFICATION_REMARK = "此分类此标签为适配MREGISTER开源项目"
SUPPORTED_SETUP_MODES = {"mregister", "normal", "commercial"}
BUILTIN_ACCOUNT_CLASSIFICATIONS: dict[str, dict[str, dict[str, Any]]] = {
    "categories": {
        "mregister": {
            "name_zh": "MREGISTER",
            "name_en": "mregister",
            "remark": BUILTIN_CLASSIFICATION_REMARK,
        }
    },
    "tags": {
        "chatgpt_registered": {
            "name_zh": "已注册CHATGPT",
            "name_en": "chatgpt_registered",
            "remark": BUILTIN_CLASSIFICATION_REMARK,
        }
    },
}
ADMIN_LOGIN_PATH_PATTERN = re.compile(r"^/[a-zA-Z0-9/_-]{2,120}$")
HOSTNAME_PATTERN = re.compile(r"^[a-z0-9.-]+(?::\d{1,5})?$")
SAFE_BROWSER_METHODS = {"GET", "HEAD", "OPTIONS"}
LOCAL_DOMAIN_ICON_RULES: list[tuple[str, tuple[str, ...]]] = [
    (
        "microsoft.svg",
        (
            "microsoft.com",
            "microsoftonline.com",
            "outlook.com",
            "live.com",
            "hotmail.com",
            "office.com",
            "office365.com",
            "msn.com",
        ),
    ),
]

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# 数据模型 (Pydantic Models)
# ============================================================================

class AccountCredentials(BaseModel):
    """账户凭证模型"""
    email: EmailStr
    refresh_token: str
    client_id: str
    auth_method: str = Field(default=DEFAULT_ACCOUNT_AUTH_METHOD)
    category_key: Optional[str] = None
    tag_keys: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    class Config:
        schema_extra = {
            "example": {
                "email": "user@outlook.com",
                "refresh_token": "0.AXoA...",
                "client_id": "your-client-id",
                "auth_method": "imap",
                "category_key": "sales",
                "tag_keys": ["registered_openai", "vip"],
                "tags": ["registered_openai", "vip"]
            }
        }


class ClassificationOption(BaseModel):
    """分类或标签定义"""
    key: str
    name_zh: str
    name_en: str
    remark: Optional[str] = None
    created_at: Optional[str] = None


class ClassificationCatalogResponse(BaseModel):
    """分类与标签配置列表"""
    categories: List[ClassificationOption] = Field(default_factory=list)
    tags: List[ClassificationOption] = Field(default_factory=list)


class ClassificationCreateRequest(BaseModel):
    """创建分类或标签"""
    name_zh: str = Field(min_length=1, max_length=80)
    name_en: str = Field(min_length=1, max_length=80)
    remark: Optional[str] = Field(default=None, max_length=200)


class EmailItem(BaseModel):
    """邮件项目模型"""
    message_id: str
    folder: str
    subject: str
    from_email: str
    date: str
    is_read: bool = False
    has_attachments: bool = False
    sender_initial: str = "?"
    sender_avatar_url: Optional[str] = None
    tag_keys: List[str] = Field(default_factory=list)
    tag_details: List[ClassificationOption] = Field(default_factory=list)

    class Config:
        schema_extra = {
            "example": {
                "message_id": "INBOX-123",
                "folder": "INBOX",
                "subject": "Welcome to Augment Code",
                "from_email": "noreply@augmentcode.com",
                "date": "2024-01-01T12:00:00",
                "is_read": False,
                "has_attachments": False,
                "sender_initial": "A",
                "sender_avatar_url": "https://www.gravatar.com/avatar/...",
                "tag_keys": ["registered_openai"],
                "tag_details": [
                    {
                        "key": "registered_openai",
                        "name_zh": "已注册 OpenAI",
                        "name_en": "Registered OpenAI"
                    }
                ]
            }
        }


class EmailListResponse(BaseModel):
    """邮件列表响应模型"""
    email_id: str
    folder_view: str
    page: int
    page_size: int
    total_emails: int
    emails: List[EmailItem]


class DualViewEmailResponse(BaseModel):
    """双栏视图邮件响应模型"""
    email_id: str
    inbox_emails: List[EmailItem]
    junk_emails: List[EmailItem]
    inbox_total: int
    junk_total: int


class EmailDetailsResponse(BaseModel):
    """邮件详情响应模型"""
    message_id: str
    subject: str
    from_email: str
    to_email: str
    date: str
    sender_avatar_url: Optional[str] = None
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    tag_keys: List[str] = Field(default_factory=list)
    tag_details: List[ClassificationOption] = Field(default_factory=list)


class AccountResponse(BaseModel):
    """账户操作响应模型"""
    email_id: str
    message: str


class AccountInfo(BaseModel):
    """账户信息模型"""
    email_id: str
    client_id: str
    auth_method: str = DEFAULT_ACCOUNT_AUTH_METHOD
    status: str = "active"
    category_key: Optional[str] = None
    category: Optional[ClassificationOption] = None
    tag_keys: List[str] = Field(default_factory=list)
    tag_details: List[ClassificationOption] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    health_score: int = 0
    health_summary: str = "未检查"
    health_checked_at: Optional[str] = None


class AccountListResponse(BaseModel):
    """账户列表响应模型"""
    total_accounts: int
    page: int
    page_size: int
    total_pages: int
    accounts: List[AccountInfo]
    available_email_domains: List[str] = Field(default_factory=list)


class UpdateAccountClassificationRequest(BaseModel):
    """更新账户分类和标签请求模型"""
    category_key: Optional[str] = None
    tag_keys: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class UpdateEmailTagsRequest(BaseModel):
    """更新邮件标签请求模型"""
    tag_keys: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class EmailTagUpdateResponse(BaseModel):
    """邮件标签更新响应"""
    email_id: str
    message_id: str
    message: str
    tag_keys: List[str] = Field(default_factory=list)
    tag_details: List[ClassificationOption] = Field(default_factory=list)


class ActionResponse(BaseModel):
    """通用操作响应"""
    message: str
    key: Optional[str] = None


class PasswordPayload(BaseModel):
    password: str = Field(min_length=8, max_length=256)
    turnstile_token: Optional[str] = Field(default=None, max_length=2048)


class SetupPayload(PasswordPayload):
    agreed_terms: bool = Field(default=False)
    admin_login_path: str = Field(default=DEFAULT_ADMIN_LOGIN_PATH, min_length=2, max_length=120)
    setup_mode: str = Field(default="normal", pattern="^(mregister|normal|commercial)$")


class ApiKeyCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    expires_mode: str = Field(default="never")
    expires_at: Optional[datetime] = None
    request_mode: str = Field(default="unlimited")
    max_requests: Optional[int] = Field(default=None, ge=1)


class PublicShareConfigPayload(BaseModel):
    enabled: bool = Field(default=False)
    expires_mode: str = Field(default="never")
    expires_at: Optional[datetime] = None
    access_password: Optional[str] = Field(default=None, max_length=256)
    clear_password: bool = Field(default=False)


class PublicShareAccessPayload(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    turnstile_token: Optional[str] = Field(default=None, max_length=2048)


class SiteSettingsPayload(BaseModel):
    home_title: str = Field(default=DEFAULT_HOME_TITLE, min_length=1, max_length=80)
    home_intro: str = Field(default=DEFAULT_HOME_INTRO, min_length=1, max_length=1200)
    admin_login_path: str = Field(default=DEFAULT_ADMIN_LOGIN_PATH, min_length=2, max_length=120)
    share_domain_enabled: bool = Field(default=False)
    share_domain: Optional[str] = Field(default=None, max_length=255)
    turnstile_site_key: Optional[str] = Field(default=None, max_length=512)
    turnstile_secret_key: Optional[str] = Field(default=None, max_length=512)
    turnstile_enabled_for_admin_login: bool = Field(default=False)
    turnstile_enabled_for_public_access: bool = Field(default=False)

# ============================================================================
# IMAP连接池管理
# ============================================================================

class IMAPConnectionPool:
    """
    IMAP连接池管理器

    提供连接复用、自动重连、连接状态监控等功能
    优化IMAP连接性能，减少连接建立开销
    """

    def __init__(self, max_connections: int = MAX_CONNECTIONS):
        """
        初始化连接池

        Args:
            max_connections: 每个邮箱的最大连接数
        """
        self.max_connections = max_connections
        self.connections = {}  # {email: Queue of connections}
        self.connection_count = {}  # {email: active connection count}
        self.lock = threading.Lock()
        logger.info(f"Initialized IMAP connection pool with max_connections={max_connections}")

    def _create_connection(self, email: str, access_token: str) -> imaplib.IMAP4_SSL:
        """
        创建新的IMAP连接

        Args:
            email: 邮箱地址
            access_token: OAuth2访问令牌

        Returns:
            IMAP4_SSL: 已认证的IMAP连接

        Raises:
            Exception: 连接创建失败
        """
        try:
            # 设置全局socket超时
            socket.setdefaulttimeout(SOCKET_TIMEOUT)

            # 创建SSL IMAP连接
            imap_client = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)

            # 设置连接超时
            imap_client.sock.settimeout(CONNECTION_TIMEOUT)

            # XOAUTH2认证
            auth_string = f"user={email}\x01auth=Bearer {access_token}\x01\x01".encode('utf-8')
            imap_client.authenticate('XOAUTH2', lambda _: auth_string)

            logger.info(f"Successfully created IMAP connection for {email}")
            return imap_client

        except Exception as e:
            logger.error(f"Failed to create IMAP connection for {email}: {e}")
            raise

    def get_connection(self, email: str, access_token: str) -> imaplib.IMAP4_SSL:
        """
        获取IMAP连接（从池中复用或创建新连接）

        Args:
            email: 邮箱地址
            access_token: OAuth2访问令牌

        Returns:
            IMAP4_SSL: 可用的IMAP连接

        Raises:
            Exception: 无法获取连接
        """
        with self.lock:
            # 初始化邮箱的连接池
            if email not in self.connections:
                self.connections[email] = Queue(maxsize=self.max_connections)
                self.connection_count[email] = 0

            connection_queue = self.connections[email]

            # 尝试从池中获取现有连接
            try:
                connection = connection_queue.get_nowait()
                # 测试连接有效性
                try:
                    connection.noop()
                    logger.debug(f"Reused existing IMAP connection for {email}")
                    return connection
                except Exception:
                    # 连接已失效，需要创建新连接
                    logger.debug(f"Existing connection invalid for {email}, creating new one")
                    self.connection_count[email] -= 1
            except Empty:
                # 池中没有可用连接
                pass

            # 检查是否可以创建新连接
            if self.connection_count[email] < self.max_connections:
                connection = self._create_connection(email, access_token)
                self.connection_count[email] += 1
                return connection
            else:
                # 达到最大连接数，等待可用连接
                logger.warning(f"Max connections ({self.max_connections}) reached for {email}, waiting...")
                try:
                    return connection_queue.get(timeout=30)
                except Exception as e:
                    logger.error(f"Timeout waiting for connection for {email}: {e}")
                    raise

    def return_connection(self, email: str, connection: imaplib.IMAP4_SSL) -> None:
        """
        归还连接到池中

        Args:
            email: 邮箱地址
            connection: 要归还的IMAP连接
        """
        if email not in self.connections:
            logger.warning(f"Attempting to return connection for unknown email: {email}")
            return

        try:
            # 测试连接状态
            connection.noop()
            # 连接有效，归还到池中
            self.connections[email].put_nowait(connection)
            logger.debug(f"Successfully returned IMAP connection for {email}")
        except Exception as e:
            # 连接已失效，减少计数并丢弃
            with self.lock:
                if email in self.connection_count:
                    self.connection_count[email] = max(0, self.connection_count[email] - 1)
            logger.debug(f"Discarded invalid connection for {email}: {e}")

    def close_all_connections(self, email: str = None) -> None:
        """
        关闭所有连接

        Args:
            email: 指定邮箱地址，如果为None则关闭所有邮箱的连接
        """
        with self.lock:
            if email:
                # 关闭指定邮箱的所有连接
                if email in self.connections:
                    closed_count = 0
                    while not self.connections[email].empty():
                        try:
                            conn = self.connections[email].get_nowait()
                            conn.logout()
                            closed_count += 1
                        except Exception as e:
                            logger.debug(f"Error closing connection: {e}")

                    self.connection_count[email] = 0
                    logger.info(f"Closed {closed_count} connections for {email}")
            else:
                # 关闭所有邮箱的连接
                total_closed = 0
                for email_key in list(self.connections.keys()):
                    count_before = self.connection_count.get(email_key, 0)
                    self.close_all_connections(email_key)
                    total_closed += count_before
                logger.info(f"Closed total {total_closed} connections for all accounts")

# ============================================================================
# 全局实例和缓存管理
# ============================================================================

# 全局连接池实例
imap_pool = IMAPConnectionPool()

# 内存缓存存储
email_cache = {}  # 邮件列表缓存
email_count_cache = {}  # 邮件总数缓存，用于检测新邮件


def get_cache_key(email: str, folder: str, page: int, page_size: int) -> str:
    """
    生成缓存键

    Args:
        email: 邮箱地址
        folder: 文件夹名称
        page: 页码
        page_size: 每页大小

    Returns:
        str: 缓存键
    """
    return f"{email}:{folder}:{page}:{page_size}"


def get_cached_emails(cache_key: str, force_refresh: bool = False):
    """
    获取缓存的邮件列表

    Args:
        cache_key: 缓存键
        force_refresh: 是否强制刷新缓存

    Returns:
        缓存的数据或None
    """
    if force_refresh:
        # 强制刷新，删除现有缓存
        if cache_key in email_cache:
            del email_cache[cache_key]
            logger.debug(f"Force refresh: removed cache for {cache_key}")
        return None

    if cache_key in email_cache:
        cached_data, timestamp = email_cache[cache_key]
        if time.time() - timestamp < CACHE_EXPIRE_TIME:
            logger.debug(f"Cache hit for {cache_key}")
            return cached_data
        else:
            # 缓存已过期，删除
            del email_cache[cache_key]
            logger.debug(f"Cache expired for {cache_key}")

    return None


def set_cached_emails(cache_key: str, data) -> None:
    """
    设置邮件列表缓存

    Args:
        cache_key: 缓存键
        data: 要缓存的数据
    """
    email_cache[cache_key] = (data, time.time())
    logger.debug(f"Cache set for {cache_key}")


def clear_email_cache(email: str = None) -> None:
    """
    清除邮件缓存

    Args:
        email: 指定邮箱地址，如果为None则清除所有缓存
    """
    if email:
        # 清除特定邮箱的缓存
        keys_to_delete = [key for key in email_cache.keys() if key.startswith(f"{email}:")]
        for key in keys_to_delete:
            del email_cache[key]
        logger.info(f"Cleared cache for {email} ({len(keys_to_delete)} entries)")
    else:
        # 清除所有缓存
        cache_count = len(email_cache)
        email_cache.clear()
        email_count_cache.clear()
        logger.info(f"Cleared all email cache ({cache_count} entries)")


def normalize_account_auth_method(auth_method: str | None) -> str:
    method = (auth_method or DEFAULT_ACCOUNT_AUTH_METHOD).strip().lower()
    return method if method in SUPPORTED_ACCOUNT_AUTH_METHODS else DEFAULT_ACCOUNT_AUTH_METHOD


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    normalized_values: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        normalized_values.append(value)
    return normalized_values


def normalize_reference_key(value: Any) -> str:
    raw_value = str(value or "").strip()
    if not raw_value:
        return ""

    ascii_key = re.sub(r"[^a-z0-9_-]+", "_", raw_value.lower()).strip("_")
    return ascii_key or raw_value


def build_classification_key(name_en: Any) -> str:
    key = normalize_reference_key(name_en)
    if not key or not CLASSIFICATION_KEY_PATTERN.fullmatch(key):
        raise HTTPException(
            status_code=400,
            detail="English name must generate a valid API key using lowercase letters, numbers, hyphen or underscore.",
        )
    return key


def normalize_account_category_key(category_key: Any) -> Optional[str]:
    normalized = normalize_reference_key(category_key)
    return normalized or None


def normalize_account_tags(tags: Any) -> List[str]:
    if not isinstance(tags, list):
        return []
    normalized_tags = [normalize_reference_key(tag) for tag in tags]
    return _dedupe_preserve_order([tag for tag in normalized_tags if tag])


def normalize_account_tag_keys(tag_keys: Any, legacy_tags: Any = None) -> List[str]:
    primary_values = tag_keys if isinstance(tag_keys, list) and tag_keys else legacy_tags
    return normalize_account_tags(primary_values)


def normalize_classification_record(key: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "key": key,
        "name_zh": str(payload.get("name_zh") or "").strip(),
        "name_en": str(payload.get("name_en") or "").strip(),
        "remark": str(payload.get("remark") or "").strip(),
        "created_at": payload.get("created_at"),
    }


def normalize_setup_mode(value: Any, fallback: str | None = None) -> str | None:
    raw = str(value or "").strip().lower()
    if raw in SUPPORTED_SETUP_MODES:
        return raw
    return fallback


def get_effective_setup_mode(settings: dict[str, Any] | None = None) -> str | None:
    current_settings = settings or load_auth_settings()
    normalized_mode = normalize_setup_mode(current_settings.get("setup_mode"))
    if normalized_mode:
        return normalized_mode
    if current_settings.get("admin_password_hash") or current_settings.get("agreement_accepted"):
        return "mregister"
    return None


def get_builtin_account_classifications(setup_mode: str | None = None) -> dict[str, dict[str, dict[str, Any]]]:
    if normalize_setup_mode(setup_mode) == "mregister":
        return BUILTIN_ACCOUNT_CLASSIFICATIONS
    return {"categories": {}, "tags": {}}


def ensure_builtin_classifications(data: dict[str, Any], setup_mode: str | None = None) -> tuple[dict[str, Any], bool]:
    categories = data.get("categories")
    tags = data.get("tags")
    normalized_data = {
        "categories": categories if isinstance(categories, dict) else {},
        "tags": tags if isinstance(tags, dict) else {},
    }
    changed = not isinstance(categories, dict) or not isinstance(tags, dict)

    for collection_name, builtin_collection in get_builtin_account_classifications(setup_mode).items():
        collection = normalized_data[collection_name]
        for key, builtin_payload in builtin_collection.items():
            existing_payload = collection.get(key) if isinstance(collection.get(key), dict) else {}
            next_payload = {
                "name_zh": builtin_payload["name_zh"],
                "name_en": builtin_payload["name_en"],
                "remark": builtin_payload.get("remark"),
                "created_at": existing_payload.get("created_at"),
            }
            if normalize_classification_record(key, existing_payload) != normalize_classification_record(key, next_payload):
                collection[key] = next_payload
                changed = True

    return normalized_data, changed


def build_classification_option(key: str, payload: dict[str, Any] | None) -> ClassificationOption:
    if not payload:
        fallback_name_en = re.sub(r"[_-]+", " ", key).title() if CLASSIFICATION_KEY_PATTERN.fullmatch(key) else key
        return ClassificationOption(key=key, name_zh=key, name_en=fallback_name_en)
    normalized = normalize_classification_record(key, payload)
    return ClassificationOption(
        key=key,
        name_zh=normalized["name_zh"] or key,
        name_en=normalized["name_en"] or key,
        remark=normalized["remark"] or None,
        created_at=normalized["created_at"],
    )


def sorted_classification_options(collection: dict[str, dict[str, Any]]) -> list[ClassificationOption]:
    options = [build_classification_option(key, payload) for key, payload in collection.items()]
    return sorted(options, key=lambda item: ((item.name_zh or item.name_en or item.key).lower(), item.key))


def resolve_category_option(category_key: str | None, catalog: dict[str, Any]) -> Optional[ClassificationOption]:
    if not category_key:
        return None
    categories = catalog.get("categories", {})
    payload = categories.get(category_key)
    return build_classification_option(category_key, payload)


def resolve_tag_options(tag_keys: list[str], catalog: dict[str, Any]) -> list[ClassificationOption]:
    tags_collection = catalog.get("tags", {})
    return [build_classification_option(tag_key, tags_collection.get(tag_key)) for tag_key in tag_keys]


def validate_catalog_references(category_key: str | None, tag_keys: list[str], catalog: dict[str, Any]) -> None:
    categories = catalog.get("categories", {})
    tags = catalog.get("tags", {})

    if category_key and category_key not in categories:
        raise HTTPException(status_code=400, detail=f"Unknown category_key: {category_key}")

    invalid_tag_keys = [tag_key for tag_key in tag_keys if tag_key not in tags]
    if invalid_tag_keys:
        raise HTTPException(status_code=400, detail=f"Unknown tag_keys: {', '.join(invalid_tag_keys)}")


def build_account_credentials_from_data(email_id: str, account_data: dict[str, Any]) -> AccountCredentials:
    return AccountCredentials(
        email=email_id,
        refresh_token=str(account_data["refresh_token"]),
        client_id=str(account_data["client_id"]),
        auth_method=normalize_account_auth_method(account_data.get("auth_method")),
        category_key=normalize_account_category_key(account_data.get("category_key")),
        tag_keys=normalize_account_tag_keys(account_data.get("tag_keys"), account_data.get("tags", [])),
        tags=normalize_account_tag_keys(account_data.get("tag_keys"), account_data.get("tags", [])),
    )


def get_account_cache_key(credentials: AccountCredentials, folder: str, page: int, page_size: int) -> str:
    return get_cache_key(
        f"{credentials.email}:{normalize_account_auth_method(credentials.auth_method)}",
        folder,
        page,
        page_size,
    )


def get_classification_catalog_response() -> ClassificationCatalogResponse:
    catalog = load_account_classifications_data()
    return ClassificationCatalogResponse(
        categories=sorted_classification_options(catalog.get("categories", {})),
        tags=sorted_classification_options(catalog.get("tags", {})),
    )


def upsert_classification_item(collection_name: str, payload: ClassificationCreateRequest) -> ClassificationOption:
    key = build_classification_key(payload.name_en)
    data = load_account_classifications_data()
    collection = data.get(collection_name, {})
    if key in collection:
        raise HTTPException(status_code=409, detail=f"{collection_name[:-1].capitalize()} already exists: {key}")

    duplicate_name_zh = next(
        (
            existing_key
            for existing_key, item in collection.items()
            if str(item.get("name_zh") or "").strip() == payload.name_zh.strip()
        ),
        None,
    )
    if duplicate_name_zh:
        raise HTTPException(status_code=409, detail=f"Chinese name already exists: {payload.name_zh}")

    collection[key] = {
        "name_zh": payload.name_zh.strip(),
        "name_en": payload.name_en.strip(),
        "remark": str(payload.remark or "").strip(),
        "created_at": datetime.utcnow().isoformat(),
    }
    data[collection_name] = collection
    save_account_classifications_data(data)
    return build_classification_option(key, collection[key])


def remove_classification_item(collection_name: str, key: str) -> None:
    if key in BUILTIN_ACCOUNT_CLASSIFICATIONS.get(collection_name, {}):
        raise HTTPException(status_code=400, detail=f"Built-in {collection_name[:-1]} cannot be deleted: {key}")
    data = load_account_classifications_data()
    collection = data.get(collection_name, {})
    if key not in collection:
        raise HTTPException(status_code=404, detail=f"{collection_name[:-1].capitalize()} not found: {key}")
    del collection[key]
    data[collection_name] = collection
    save_account_classifications_data(data)


def get_email_tag_keys(email_id: str, message_id: str) -> list[str]:
    data = load_email_tags_data()
    email_entries = data.get("emails", {}).get(email_id, {})
    if not isinstance(email_entries, dict):
        return []
    return normalize_account_tag_keys(email_entries.get(message_id, []))


def set_email_tag_keys(email_id: str, message_id: str, tag_keys: list[str]) -> None:
    data = load_email_tags_data()
    emails = data.setdefault("emails", {})
    email_entries = emails.get(email_id)
    if not isinstance(email_entries, dict):
        email_entries = {}

    normalized_tag_keys = normalize_account_tag_keys(tag_keys)
    if normalized_tag_keys:
        email_entries[message_id] = normalized_tag_keys
        emails[email_id] = email_entries
    else:
        email_entries.pop(message_id, None)
        if email_entries:
            emails[email_id] = email_entries
        else:
            emails.pop(email_id, None)

    data["emails"] = emails
    save_email_tags_data(data)


def remove_account_category_references(category_key: str) -> None:
    with auth_lock:
        accounts = _read_json_file(ACCOUNTS_FILE, {})
        accounts = accounts if isinstance(accounts, dict) else {}
        if not accounts:
            return

        changed = False
        for account_data in accounts.values():
            if not isinstance(account_data, dict):
                continue
            if normalize_account_category_key(account_data.get("category_key")) == category_key:
                account_data["category_key"] = None
                changed = True

        if changed:
            _write_json_file(ACCOUNTS_FILE, accounts)


def remove_tag_references(tag_key: str) -> None:
    with auth_lock:
        accounts = _read_json_file(ACCOUNTS_FILE, {})
        accounts = accounts if isinstance(accounts, dict) else {}
        if accounts:
            accounts_changed = False
            for account_data in accounts.values():
                if not isinstance(account_data, dict):
                    continue
                normalized_tag_keys = normalize_account_tag_keys(account_data.get("tag_keys"), account_data.get("tags", []))
                updated_tag_keys = [item for item in normalized_tag_keys if item != tag_key]
                if updated_tag_keys != normalized_tag_keys:
                    account_data["tag_keys"] = updated_tag_keys
                    account_data.pop("tags", None)
                    accounts_changed = True

            if accounts_changed:
                _write_json_file(ACCOUNTS_FILE, accounts)

    email_tags_data = load_email_tags_data()
    emails = email_tags_data.get("emails", {})
    email_tags_changed = False

    for email_id in list(emails.keys()):
        message_map = emails.get(email_id)
        if not isinstance(message_map, dict):
            continue
        for message_id in list(message_map.keys()):
            normalized_tag_keys = normalize_account_tag_keys(message_map.get(message_id, []))
            updated_tag_keys = [item for item in normalized_tag_keys if item != tag_key]
            if updated_tag_keys != normalized_tag_keys:
                email_tags_changed = True
                if updated_tag_keys:
                    message_map[message_id] = updated_tag_keys
                else:
                    del message_map[message_id]
        if not message_map:
            del emails[email_id]

    if email_tags_changed:
        email_tags_data["emails"] = emails
        save_email_tags_data(email_tags_data)


def apply_email_tag_details(
    email_id: str,
    email_obj: EmailItem | EmailDetailsResponse,
    catalog: dict[str, Any] | None = None,
    email_tag_map: dict[str, Any] | None = None,
) -> EmailItem | EmailDetailsResponse:
    if isinstance(email_tag_map, dict):
        tag_keys = normalize_account_tag_keys(email_tag_map.get(email_obj.message_id, []))
    else:
        tag_keys = get_email_tag_keys(email_id, email_obj.message_id)
    catalog = catalog or load_account_classifications_data()
    email_obj.tag_keys = tag_keys
    email_obj.tag_details = resolve_tag_options(tag_keys, catalog)
    return email_obj

# ============================================================================
# 邮件处理辅助函数
# ============================================================================

def decode_header_value(header_value: str) -> str:
    """
    解码邮件头字段

    处理各种编码格式的邮件头部信息，如Subject、From等

    Args:
        header_value: 原始头部值

    Returns:
        str: 解码后的字符串
    """
    if not header_value:
        return ""

    try:
        decoded_parts = decode_header(str(header_value))
        decoded_string = ""

        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                try:
                    # 使用指定编码或默认UTF-8解码
                    encoding = charset if charset else 'utf-8'
                    decoded_string += part.decode(encoding, errors='replace')
                except (LookupError, UnicodeDecodeError):
                    # 编码失败时使用UTF-8强制解码
                    decoded_string += part.decode('utf-8', errors='replace')
            else:
                decoded_string += str(part)

        return decoded_string.strip()
    except Exception as e:
        logger.warning(f"Failed to decode header value '{header_value}': {e}")
        return str(header_value) if header_value else ""


def extract_sender_email_address(from_value: str) -> str:
    """从发件人字段中提取邮箱地址"""
    _display_name, email_address = parseaddr(from_value or "")
    return (email_address or "").strip().lower()


def build_sender_avatar_url(from_value: str, size: int = 128) -> Optional[str]:
    """构建发件人头像 URL，优先使用 Gravatar 的公开头像"""
    email_address = extract_sender_email_address(from_value)
    if not email_address:
        return None
    email_hash = hashlib.md5(email_address.encode("utf-8")).hexdigest()
    return f"https://www.gravatar.com/avatar/{email_hash}?d=404&s={size}"


def extract_email_content(email_message: email.message.EmailMessage) -> tuple[str, str]:
    """
    提取邮件的纯文本和HTML内容

    Args:
        email_message: 邮件消息对象

    Returns:
        tuple[str, str]: (纯文本内容, HTML内容)
    """
    body_plain = ""
    body_html = ""

    try:
        if email_message.is_multipart():
            # 处理多部分邮件
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # 跳过附件
                if 'attachment' not in content_disposition.lower():
                    try:
                        charset = part.get_content_charset() or 'utf-8'
                        payload = part.get_payload(decode=True)

                        if payload:
                            decoded_content = payload.decode(charset, errors='replace')

                            if content_type == 'text/plain' and not body_plain:
                                body_plain = decoded_content
                            elif content_type == 'text/html' and not body_html:
                                body_html = decoded_content

                    except Exception as e:
                        logger.warning(f"Failed to decode email part ({content_type}): {e}")
        else:
            # 处理单部分邮件
            try:
                charset = email_message.get_content_charset() or 'utf-8'
                payload = email_message.get_payload(decode=True)

                if payload:
                    content = payload.decode(charset, errors='replace')
                    content_type = email_message.get_content_type()

                    if content_type == 'text/plain':
                        body_plain = content
                    elif content_type == 'text/html':
                        body_html = content
                    else:
                        # 默认当作纯文本处理
                        body_plain = content

            except Exception as e:
                logger.warning(f"Failed to decode single-part email body: {e}")

    except Exception as e:
        logger.error(f"Error extracting email content: {e}")

    return body_plain.strip(), body_html.strip()


# ============================================================================
# 账户凭证管理模块
# ============================================================================

async def get_account_credentials(email_id: str) -> AccountCredentials:
    """
    从accounts.json文件获取指定邮箱的账户凭证

    Args:
        email_id: 邮箱地址

    Returns:
        AccountCredentials: 账户凭证对象

    Raises:
        HTTPException: 账户不存在或文件读取失败
    """
    try:
        accounts = load_accounts_data()
        if not accounts:
            logger.warning(f"Accounts file {ACCOUNTS_FILE} not found")
            raise HTTPException(status_code=404, detail="No accounts configured")

        # 检查指定邮箱是否存在
        if email_id not in accounts:
            logger.warning(f"Account {email_id} not found in accounts file")
            raise HTTPException(status_code=404, detail=f"Account {email_id} not found")

        # 验证账户数据完整性
        account_data = accounts[email_id]
        required_fields = ['refresh_token', 'client_id']
        missing_fields = [field for field in required_fields if not account_data.get(field)]

        if missing_fields:
            logger.error(f"Account {email_id} missing required fields: {missing_fields}")
            raise HTTPException(status_code=500, detail="Account configuration incomplete")

        return build_account_credentials_from_data(email_id, account_data)

    except HTTPException:
        # 重新抛出HTTP异常
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in accounts file: {e}")
        raise HTTPException(status_code=500, detail="Accounts file format error")
    except Exception as e:
        logger.error(f"Unexpected error getting account credentials for {email_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


async def save_account_credentials(email_id: str, credentials: AccountCredentials) -> None:
    """保存账户凭证到accounts.json"""
    try:
        with auth_lock:
            accounts = _read_json_file(ACCOUNTS_FILE, {})
            accounts = accounts if isinstance(accounts, dict) else {}
            accounts[email_id] = {
                'refresh_token': credentials.refresh_token,
                'client_id': credentials.client_id,
                'auth_method': normalize_account_auth_method(getattr(credentials, 'auth_method', DEFAULT_ACCOUNT_AUTH_METHOD)),
                'category_key': normalize_account_category_key(getattr(credentials, 'category_key', None)),
                'tag_keys': normalize_account_tag_keys(
                    getattr(credentials, 'tag_keys', []),
                    getattr(credentials, 'tags', []),
                ),
            }
            _write_json_file(ACCOUNTS_FILE, accounts)
        logger.info(f"Account credentials saved for {email_id}")
    except Exception as e:
        logger.error(f"Error saving account credentials: {e}")
        raise HTTPException(status_code=500, detail="Failed to save account")


async def get_all_accounts(
    page: int = 1, 
    page_size: int = 10, 
    email_search: Optional[str] = None,
    email_domain: Optional[str] = None,
    tag_search: Optional[str] = None,
    category_search: Optional[str] = None,
    category_key: Optional[str] = None,
    tag_key: Optional[str] = None,
) -> AccountListResponse:
    """获取所有已加载的邮箱账户列表，支持分页和搜索"""
    try:
        accounts_data = load_accounts_data()
        if not accounts_data:
            return AccountListResponse(
                total_accounts=0, 
                page=page, 
                page_size=page_size, 
                total_pages=0, 
                accounts=[],
                available_email_domains=[],
            )
        health_data = load_account_health_data().get("accounts", {})
        catalog = load_account_classifications_data()
        available_email_domains: set[str] = set()

        all_accounts = []
        for email_id, account_info in accounts_data.items():
            email_id_normalized = str(email_id or "").strip()
            email_domain_value = ""
            if "@" in email_id_normalized:
                email_domain_value = email_id_normalized.rsplit("@", 1)[-1].strip().lower()
            if email_domain_value:
                available_email_domains.add(email_domain_value)

            health_record = health_data.get(email_id, {})
            if not isinstance(health_record, dict):
                health_record = build_account_health_record("unchecked", 0, "未检查")

            normalized_category_key = normalize_account_category_key(account_info.get("category_key"))
            normalized_tag_keys = normalize_account_tag_keys(account_info.get("tag_keys"), account_info.get("tags", []))
            category_option = resolve_category_option(normalized_category_key, catalog)
            tag_options = resolve_tag_options(normalized_tag_keys, catalog)

            account = AccountInfo(
                email_id=email_id,
                client_id=account_info.get('client_id', ''),
                auth_method=normalize_account_auth_method(account_info.get('auth_method')),
                status=str(health_record.get("status") or "unchecked"),
                category_key=normalized_category_key,
                category=category_option,
                tag_keys=normalized_tag_keys,
                tag_details=tag_options,
                tags=[option.name_zh or option.name_en or option.key for option in tag_options],
                health_score=max(0, min(int(health_record.get("score", 0) or 0), 100)),
                health_summary=str(health_record.get("summary") or "未检查"),
                health_checked_at=health_record.get("checked_at"),
            )
            all_accounts.append(account)

        # 应用搜索过滤
        filtered_accounts = all_accounts
        
        # 邮箱账号模糊搜索
        if email_search:
            email_search_lower = email_search.lower()
            filtered_accounts = [
                acc for acc in filtered_accounts 
                if email_search_lower in acc.email_id.lower()
            ]

        if email_domain:
            email_domain_lower = str(email_domain or "").strip().lower()
            filtered_accounts = [
                acc for acc in filtered_accounts
                if acc.email_id.lower().endswith("@" + email_domain_lower)
            ]

        if category_key:
            normalized_category_filter = normalize_account_category_key(category_key)
            filtered_accounts = [
                acc for acc in filtered_accounts
                if normalize_account_category_key(acc.category_key) == normalized_category_filter
            ]

        if category_search:
            category_search_lower = category_search.lower()
            filtered_accounts = [
                acc for acc in filtered_accounts
                if (
                    (acc.category_key and category_search_lower in acc.category_key.lower())
                    or (acc.category and category_search_lower in acc.category.name_zh.lower())
                    or (acc.category and category_search_lower in acc.category.name_en.lower())
                )
            ]

        if tag_key:
            normalized_tag_key = normalize_reference_key(tag_key)
            filtered_accounts = [
                acc for acc in filtered_accounts
                if normalized_tag_key in acc.tag_keys
            ]
        
        # 标签模糊搜索
        if tag_search:
            tag_search_lower = tag_search.lower()
            filtered_accounts = [
                acc for acc in filtered_accounts 
                if any(
                    tag_search_lower in value.lower()
                    for tag in acc.tag_details
                    for value in [tag.key, tag.name_zh, tag.name_en]
                    if value
                )
            ]

        # 计算分页信息
        total_accounts = len(filtered_accounts)
        total_pages = (total_accounts + page_size - 1) // page_size if total_accounts > 0 else 0
        
        # 应用分页
        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        paginated_accounts = filtered_accounts[start_index:end_index]

        return AccountListResponse(
            total_accounts=total_accounts,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            accounts=paginated_accounts,
            available_email_domains=sorted(available_email_domains),
        )

    except json.JSONDecodeError:
        logger.error("Failed to parse accounts.json")
        raise HTTPException(status_code=500, detail="Failed to read accounts file")
    except Exception as e:
        logger.error(f"Error getting accounts list: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# OAuth2令牌管理模块
# ============================================================================

# Auth/file helpers can call each other while operating on the same on-disk state.
# Use a re-entrant lock so nested reads/writes do not deadlock the request thread.
auth_lock = threading.RLock()


def _read_json_file(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return json.loads(json.dumps(default))
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON detected in {path}, using default structure")
        return json.loads(json.dumps(default))


def _write_json_file(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def load_auth_settings() -> dict[str, Any]:
    with auth_lock:
        return _read_json_file(
            AUTH_FILE,
            {
                "admin_password_hash": "",
                "agreement_accepted": False,
                "agreement_accepted_at": None,
                "setup_mode": None,
                "updated_at": None,
            },
        )


def save_auth_settings(settings: dict[str, Any]) -> None:
    with auth_lock:
        payload = {
            "admin_password_hash": settings.get("admin_password_hash", ""),
            "agreement_accepted": bool(settings.get("agreement_accepted", False)),
            "agreement_accepted_at": settings.get("agreement_accepted_at"),
            "setup_mode": normalize_setup_mode(settings.get("setup_mode")),
            "updated_at": datetime.utcnow().isoformat(),
        }
        _write_json_file(AUTH_FILE, payload)


def load_sessions() -> dict[str, Any]:
    with auth_lock:
        data = _read_json_file(SESSIONS_FILE, {"sessions": {}})
        sessions = data.get("sessions")
        if not isinstance(sessions, dict):
            return {"sessions": {}}
        return {"sessions": sessions}


def save_sessions(data: dict[str, Any]) -> None:
    with auth_lock:
        _write_json_file(SESSIONS_FILE, {"sessions": data.get("sessions", {})})


def load_api_keys_data() -> dict[str, Any]:
    with auth_lock:
        data = _read_json_file(API_KEYS_FILE, {"keys": {}, "usage_logs": []})
        keys = data.get("keys")
        usage_logs = data.get("usage_logs")
        return {
            "keys": keys if isinstance(keys, dict) else {},
            "usage_logs": usage_logs if isinstance(usage_logs, list) else [],
        }


def save_api_keys_data(data: dict[str, Any]) -> None:
    with auth_lock:
        _write_json_file(
            API_KEYS_FILE,
            {
                "keys": data.get("keys", {}),
                "usage_logs": data.get("usage_logs", [])[-API_KEY_USAGE_LOG_LIMIT:],
            },
        )


def load_accounts_data() -> dict[str, Any]:
    with auth_lock:
        data = _read_json_file(ACCOUNTS_FILE, {})
        return data if isinstance(data, dict) else {}


def save_accounts_data(data: dict[str, Any]) -> None:
    with auth_lock:
        _write_json_file(ACCOUNTS_FILE, data if isinstance(data, dict) else {})


def load_account_health_data() -> dict[str, Any]:
    with auth_lock:
        data = _read_json_file(ACCOUNT_HEALTH_FILE, {"accounts": {}})
        accounts = data.get("accounts")
        return {"accounts": accounts if isinstance(accounts, dict) else {}}


def save_account_health_data(data: dict[str, Any]) -> None:
    with auth_lock:
        _write_json_file(ACCOUNT_HEALTH_FILE, {"accounts": data.get("accounts", {})})


def reset_account_classifications_for_mode(setup_mode: str | None = None) -> None:
    with auth_lock:
        normalized_data, _ = ensure_builtin_classifications({"categories": {}, "tags": {}}, setup_mode)
        _write_json_file(ACCOUNT_CLASSIFICATIONS_FILE, normalized_data)


def load_account_classifications_data() -> dict[str, Any]:
    with auth_lock:
        data = _read_json_file(ACCOUNT_CLASSIFICATIONS_FILE, {"categories": {}, "tags": {}})
        normalized_data, changed = ensure_builtin_classifications(data, get_effective_setup_mode())
        if changed:
            _write_json_file(ACCOUNT_CLASSIFICATIONS_FILE, normalized_data)
        return normalized_data


def save_account_classifications_data(data: dict[str, Any]) -> None:
    with auth_lock:
        normalized_data, _ = ensure_builtin_classifications(data, get_effective_setup_mode())
        _write_json_file(
            ACCOUNT_CLASSIFICATIONS_FILE,
            normalized_data,
        )


def load_email_tags_data() -> dict[str, Any]:
    with auth_lock:
        data = _read_json_file(EMAIL_TAGS_FILE, {"emails": {}})
        emails = data.get("emails")
        return {"emails": emails if isinstance(emails, dict) else {}}


def save_email_tags_data(data: dict[str, Any]) -> None:
    with auth_lock:
        _write_json_file(EMAIL_TAGS_FILE, {"emails": data.get("emails", {})})


def load_public_shares_data() -> dict[str, Any]:
    with auth_lock:
        data = _read_json_file(PUBLIC_SHARES_FILE, {"shares": {}})
        shares = data.get("shares")
        return {"shares": shares if isinstance(shares, dict) else {}}


def save_public_shares_data(data: dict[str, Any]) -> None:
    with auth_lock:
        _write_json_file(PUBLIC_SHARES_FILE, {"shares": data.get("shares", {})})


def load_open_access_data() -> dict[str, Any]:
    with auth_lock:
        data = _read_json_file(OPEN_ACCESS_SESSIONS_FILE, {"sessions": {}, "failed_attempts": {}})
        sessions = data.get("sessions")
        failed_attempts = data.get("failed_attempts")
        return {
            "sessions": sessions if isinstance(sessions, dict) else {},
            "failed_attempts": failed_attempts if isinstance(failed_attempts, dict) else {},
        }


def save_open_access_data(data: dict[str, Any]) -> None:
    with auth_lock:
        _write_json_file(
            OPEN_ACCESS_SESSIONS_FILE,
            {
                "sessions": data.get("sessions", {}),
                "failed_attempts": data.get("failed_attempts", {}),
            },
        )


def load_admin_login_attempts_data() -> dict[str, Any]:
    with auth_lock:
        data = _read_json_file(ADMIN_LOGIN_ATTEMPTS_FILE, {"attempts": {}})
        attempts = data.get("attempts")
        return {"attempts": attempts if isinstance(attempts, dict) else {}}


def save_admin_login_attempts_data(data: dict[str, Any]) -> None:
    with auth_lock:
        _write_json_file(ADMIN_LOGIN_ATTEMPTS_FILE, {"attempts": data.get("attempts", {})})


def get_default_site_settings() -> dict[str, Any]:
    return {
        "home_title": DEFAULT_HOME_TITLE,
        "home_intro": DEFAULT_HOME_INTRO,
        "admin_login_path": DEFAULT_ADMIN_LOGIN_PATH,
        "share_domain_enabled": False,
        "share_domain": "",
        "turnstile_site_key": "",
        "turnstile_secret_key": "",
        "turnstile_enabled_for_admin_login": False,
        "turnstile_enabled_for_public_access": False,
        "updated_at": None,
    }


def normalize_admin_login_path(value: str | None) -> str:
    raw_value = str(value or DEFAULT_ADMIN_LOGIN_PATH).strip()
    if "://" in raw_value:
        raise HTTPException(status_code=400, detail="管理员登录地址只支持站内路径")

    stripped = raw_value.strip("/")
    path = f"/{stripped}" if stripped else "/"
    path = re.sub(r"/{2,}", "/", path)

    if path == "/":
        raise HTTPException(status_code=400, detail="管理员登录地址不能设置为根路径 /")
    if not ADMIN_LOGIN_PATH_PATTERN.fullmatch(path):
        raise HTTPException(status_code=400, detail="管理员登录地址仅支持字母、数字、-、_ 和 /")

    reserved_prefixes = [
        "/api",
        "/open",
        "/static",
        "/docs",
        "/redoc",
        "/favicon.ico",
        "/icons",
    ]
    if any(path == prefix or path.startswith(prefix + "/") for prefix in reserved_prefixes):
        raise HTTPException(status_code=400, detail="管理员登录地址与系统保留路径冲突，请更换")

    return path


def normalize_hostname(value: str | None) -> str:
    raw_value = str(value or "").strip().lower()
    if not raw_value:
        return ""

    parsed = urlparse(raw_value if "://" in raw_value else f"https://{raw_value}")
    host = (parsed.netloc or parsed.path or "").strip().strip("/")
    if "/" in host:
        host = host.split("/", 1)[0].strip()

    if not host or not HOSTNAME_PATTERN.fullmatch(host) or ".." in host:
        raise HTTPException(status_code=400, detail="分享页面域名格式不正确")

    return host


def normalize_icon_domain(value: str | None) -> str:
    normalized = normalize_hostname(value)
    host = normalized.split(":", 1)[0].strip().lower()
    if not host:
        return ""
    if host != normalized:
        raise HTTPException(status_code=400, detail="图标域名不支持自定义端口")
    if host == "localhost" or "." not in host:
        raise HTTPException(status_code=400, detail="图标域名必须是公开域名")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise HTTPException(status_code=400, detail="图标域名不能直接使用 IP 地址")


def normalize_turnstile_value(value: str | None) -> str:
    return str(value or "").strip()[:512]


def build_turnstile_client_config(settings: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    source = settings or load_site_settings()
    site_key = normalize_turnstile_value(source.get("turnstile_site_key"))
    secret_key = normalize_turnstile_value(source.get("turnstile_secret_key"))
    configured = bool(site_key) and bool(secret_key)
    return {
        "enabled": configured,
        "site_key": site_key if configured else "",
        "admin_login_enabled": configured and bool(source.get("turnstile_enabled_for_admin_login", False)),
        "public_access_enabled": configured and bool(source.get("turnstile_enabled_for_public_access", False)),
    }


def load_site_settings() -> dict[str, Any]:
    with auth_lock:
        data = _read_json_file(SITE_SETTINGS_FILE, get_default_site_settings())
        defaults = get_default_site_settings()
        normalized = {
            "home_title": str(data.get("home_title") or defaults["home_title"]).strip()[:80] or defaults["home_title"],
            "home_intro": str(data.get("home_intro") or defaults["home_intro"]).strip()[:1200] or defaults["home_intro"],
            "share_domain_enabled": bool(data.get("share_domain_enabled", False)),
            "share_domain": "",
            "turnstile_site_key": normalize_turnstile_value(data.get("turnstile_site_key")),
            "turnstile_secret_key": normalize_turnstile_value(data.get("turnstile_secret_key")),
            "turnstile_enabled_for_admin_login": bool(data.get("turnstile_enabled_for_admin_login", False)),
            "turnstile_enabled_for_public_access": bool(data.get("turnstile_enabled_for_public_access", False)),
            "updated_at": data.get("updated_at"),
        }

        try:
            normalized["admin_login_path"] = normalize_admin_login_path(data.get("admin_login_path"))
        except HTTPException:
            normalized["admin_login_path"] = defaults["admin_login_path"]

        try:
            normalized["share_domain"] = normalize_hostname(data.get("share_domain"))
        except HTTPException:
            normalized["share_domain"] = ""

        if not normalized["share_domain"]:
            normalized["share_domain_enabled"] = False
        if not normalized["turnstile_site_key"] or not normalized["turnstile_secret_key"]:
            normalized["turnstile_enabled_for_admin_login"] = False
            normalized["turnstile_enabled_for_public_access"] = False

        return normalized


def save_site_settings(settings: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "home_title": str(settings.get("home_title") or DEFAULT_HOME_TITLE).strip()[:80] or DEFAULT_HOME_TITLE,
        "home_intro": str(settings.get("home_intro") or DEFAULT_HOME_INTRO).strip()[:1200] or DEFAULT_HOME_INTRO,
        "admin_login_path": normalize_admin_login_path(settings.get("admin_login_path")),
        "share_domain_enabled": bool(settings.get("share_domain_enabled", False)),
        "share_domain": normalize_hostname(settings.get("share_domain")),
        "turnstile_site_key": normalize_turnstile_value(settings.get("turnstile_site_key")),
        "turnstile_secret_key": normalize_turnstile_value(settings.get("turnstile_secret_key")),
        "turnstile_enabled_for_admin_login": bool(settings.get("turnstile_enabled_for_admin_login", False)),
        "turnstile_enabled_for_public_access": bool(settings.get("turnstile_enabled_for_public_access", False)),
        "updated_at": datetime.utcnow().isoformat(),
    }
    if not payload["share_domain"]:
        payload["share_domain_enabled"] = False
    if not payload["turnstile_site_key"] or not payload["turnstile_secret_key"]:
        payload["turnstile_enabled_for_admin_login"] = False
        payload["turnstile_enabled_for_public_access"] = False

    with auth_lock:
        _write_json_file(SITE_SETTINGS_FILE, payload)
    return payload


def get_admin_login_path(settings: Optional[dict[str, Any]] = None) -> str:
    source = settings or load_site_settings()
    return normalize_admin_login_path(source.get("admin_login_path"))


def hash_password(password: str, salt_hex: str | None = None) -> str:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored or "$" not in stored:
        return False
    salt_hex, expected = stored.split("$", 1)
    actual = hash_password(password, salt_hex).split("$", 1)[1]
    return hmac.compare_digest(actual, expected)


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def normalize_utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def parse_stored_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return normalize_utc_datetime(parsed) if parsed.tzinfo else parsed


def get_request_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "") if TRUST_PROXY_HEADERS else ""
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return ""


def get_request_host(request: Request) -> str:
    forwarded_host = request.headers.get("X-Forwarded-Host", "") if TRUST_PROXY_HEADERS else ""
    if forwarded_host:
        return forwarded_host.split(",")[0].strip().lower()
    host = request.headers.get("host", "")
    if host:
        return host.strip().lower()
    return request.url.netloc.strip().lower()


def hosts_match(request_host: str, configured_host: str) -> bool:
    request_host = (request_host or "").strip().lower()
    configured_host = (configured_host or "").strip().lower()
    if not request_host or not configured_host:
        return False
    if ":" in configured_host:
        return request_host == configured_host
    return request_host.split(":", 1)[0] == configured_host


def is_share_domain_allowed_path(path: str) -> bool:
    if path in {"/", "/api/public/site-info", "/favicon.ico"}:
        return True
    return any(
        path == prefix or path.startswith(prefix + "/")
        for prefix in ("/open", "/api/open", "/static", "/icons")
    )


def get_request_origin(request: Request) -> str:
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "") if TRUST_PROXY_HEADERS else ""
    scheme = request.url.scheme
    if forwarded_proto:
        scheme = forwarded_proto.split(",")[0].strip().lower() or scheme
    return f"{scheme}://{get_request_host(request)}"


def normalize_origin_value(value: str | None) -> str:
    if not value:
        return ""
    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return ""
    scheme = (parsed.scheme or "").strip().lower()
    netloc = (parsed.netloc or "").strip().lower()
    if scheme not in {"http", "https"} or not netloc:
        return ""
    return f"{scheme}://{netloc}"


def get_browser_supplied_origin(request: Request) -> tuple[bool, str]:
    raw_origin = (request.headers.get("Origin") or "").strip()
    if raw_origin:
        if raw_origin.lower() == "null":
            return True, "null"
        return True, normalize_origin_value(raw_origin)

    raw_referer = (request.headers.get("Referer") or "").strip()
    if raw_referer:
        return True, normalize_origin_value(raw_referer)

    return False, ""


def validate_browser_origin(request: Request) -> JSONResponse | None:
    if extract_api_key_from_request(request):
        return None
    has_browser_origin, supplied_origin = get_browser_supplied_origin(request)
    if not has_browser_origin:
        return None
    if supplied_origin == get_request_origin(request).lower():
        return None
    return JSONResponse({"detail": "Cross-site browser requests are not allowed."}, status_code=403)


async def enforce_turnstile(request: Request, token: str | None, audience: str) -> None:
    site_settings = load_site_settings()
    turnstile_config = build_turnstile_client_config(site_settings)
    audience_enabled = (
        turnstile_config.get("admin_login_enabled")
        if audience == "admin_login"
        else turnstile_config.get("public_access_enabled")
    )
    if not audience_enabled:
        return

    token_value = str(token or "").strip()
    if not token_value:
        raise HTTPException(status_code=400, detail="请先完成 Cloudflare Turnstile 验证")

    payload = {
        "secret": site_settings.get("turnstile_secret_key", ""),
        "response": token_value,
    }
    remote_ip = get_request_ip(request)
    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(TURNSTILE_VERIFY_URL, data=payload)
            response.raise_for_status()
            verification = response.json()
    except httpx.HTTPError as exc:
        logger.warning("Turnstile verification request failed for %s: %s", audience, exc)
        raise HTTPException(status_code=502, detail="Cloudflare Turnstile 验证服务暂时不可用，请稍后重试")

    if not verification.get("success"):
        logger.info(
            "Turnstile verification rejected for %s: %s",
            audience,
            verification.get("error-codes") or [],
        )
        raise HTTPException(status_code=400, detail="Cloudflare Turnstile 验证失败，请刷新后重试")


def request_uses_https(request: Request | None) -> bool:
    if request is None:
        return False
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "") if TRUST_PROXY_HEADERS else ""
    if forwarded_proto:
        return forwarded_proto.split(",")[0].strip().lower() == "https"
    return request.url.scheme == "https"


def get_request_public_base_url(request: Request) -> str:
    site_settings = load_site_settings()
    share_domain = site_settings.get("share_domain", "")
    if site_settings.get("share_domain_enabled") and share_domain:
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "") if TRUST_PROXY_HEADERS else ""
        scheme = request.url.scheme
        if forwarded_proto:
            scheme = forwarded_proto.split(",")[0].strip().lower() or scheme
        return f"{scheme}://{share_domain}"

    forwarded_proto = request.headers.get("X-Forwarded-Proto", "") if TRUST_PROXY_HEADERS else ""
    forwarded_host = request.headers.get("X-Forwarded-Host", "") if TRUST_PROXY_HEADERS else ""
    forwarded_prefix = request.headers.get("X-Forwarded-Prefix", "") if TRUST_PROXY_HEADERS else ""
    host = ""

    if forwarded_host:
        host = forwarded_host.split(",")[0].strip()
    elif request.headers.get("host"):
        host = request.headers["host"].strip()
    else:
        host = request.url.netloc

    scheme = request.url.scheme
    if forwarded_proto:
        scheme = forwarded_proto.split(",")[0].strip().lower() or scheme

    prefix = ""
    if forwarded_prefix:
        prefix = "/" + forwarded_prefix.split(",")[0].strip().strip("/")
        if prefix == "/":
            prefix = ""

    return f"{scheme}://{host}{prefix}".rstrip("/")


def build_public_share_url(request: Request, email_id: str) -> str:
    base_url = get_request_public_base_url(request)
    return f"{base_url}/open/emails/{quote(email_id, safe='')}"


def get_public_share_cookie_name(email_id: str) -> str:
    email_hash = hashlib.sha256(email_id.lower().encode("utf-8")).hexdigest()[:16]
    return f"om_open_{email_hash}"


def build_public_share_record(email_id: str, meta: dict[str, Any], request: Request) -> dict[str, Any]:
    now = datetime.utcnow()
    expires_at = parse_stored_datetime(meta.get("expires_at"))
    status = "disabled"
    if bool(meta.get("enabled", False)):
        status = "expired" if expires_at and expires_at <= now else "active"

    return {
        "email_id": email_id,
        "enabled": bool(meta.get("enabled", False)),
        "status": status,
        "expires_mode": "fixed" if meta.get("expires_at") else "never",
        "expires_at": meta.get("expires_at"),
        "requires_password": bool(meta.get("password_hash")),
        "password_updated_at": meta.get("password_updated_at"),
        "updated_at": meta.get("updated_at"),
        "public_url": build_public_share_url(request, email_id),
    }


def get_public_share_meta(email_id: str) -> dict[str, Any]:
    data = load_public_shares_data()
    meta = data.get("shares", {}).get(email_id, {})
    return meta if isinstance(meta, dict) else {}


def is_public_share_active(meta: dict[str, Any]) -> bool:
    if not bool(meta.get("enabled", False)):
        return False
    expires_at = parse_stored_datetime(meta.get("expires_at"))
    return not expires_at or expires_at > datetime.utcnow()


def cleanup_expired_open_access() -> None:
    data = load_open_access_data()
    now = datetime.utcnow()
    now_ts = time.time()
    sessions = data.get("sessions", {})
    failed_attempts = data.get("failed_attempts", {})

    active_sessions = {
        token_hash: meta
        for token_hash, meta in sessions.items()
        if isinstance(meta, dict) and float(meta.get("expires_at_ts", 0)) > now_ts
    }

    active_failures = {}
    failure_window = timedelta(minutes=OPEN_ACCESS_FAILURE_WINDOW_MINUTES)
    for key, meta in failed_attempts.items():
        if not isinstance(meta, dict):
            continue
        blocked_until = parse_stored_datetime(meta.get("blocked_until"))
        last_failed_at = parse_stored_datetime(meta.get("last_failed_at"))
        if blocked_until and blocked_until > now:
            active_failures[key] = meta
            continue
        if last_failed_at and last_failed_at >= now - failure_window:
            active_failures[key] = meta

    if active_sessions != sessions or active_failures != failed_attempts:
        save_open_access_data({"sessions": active_sessions, "failed_attempts": active_failures})


def cleanup_expired_admin_login_attempts() -> None:
    data = load_admin_login_attempts_data()
    attempts = data.get("attempts", {})
    now_ts = time.time()
    failure_window_seconds = ADMIN_LOGIN_FAILURE_WINDOW_MINUTES * 60
    active_attempts = {
        attempt_key: meta
        for attempt_key, meta in attempts.items()
        if isinstance(meta, dict)
        and (
            float(meta.get("blocked_until_ts", 0) or 0) > now_ts
            or float(meta.get("last_failed_at_ts", 0) or 0) > (now_ts - failure_window_seconds)
        )
    }
    if active_attempts != attempts:
        save_admin_login_attempts_data({"attempts": active_attempts})


def get_admin_login_attempt_key(request: Request) -> str:
    return get_request_ip(request) or "unknown"


def clear_admin_login_failures(request: Request) -> None:
    data = load_admin_login_attempts_data()
    attempt_key = get_admin_login_attempt_key(request)
    if attempt_key in data.get("attempts", {}):
        del data["attempts"][attempt_key]
        save_admin_login_attempts_data(data)


def get_admin_login_block_state(request: Request) -> dict[str, Any] | None:
    cleanup_expired_admin_login_attempts()
    attempt_key = get_admin_login_attempt_key(request)
    meta = load_admin_login_attempts_data().get("attempts", {}).get(attempt_key)
    if not isinstance(meta, dict):
        return None
    if float(meta.get("blocked_until_ts", 0) or 0) <= time.time():
        return None
    return meta


def record_admin_login_failure(request: Request) -> dict[str, Any]:
    cleanup_expired_admin_login_attempts()
    data = load_admin_login_attempts_data()
    attempts = data.get("attempts", {})
    attempt_key = get_admin_login_attempt_key(request)
    now = datetime.utcnow()
    now_ts = time.time()
    failure_window_seconds = ADMIN_LOGIN_FAILURE_WINDOW_MINUTES * 60
    meta = attempts.get(attempt_key)
    meta = meta if isinstance(meta, dict) else {}

    count = int(meta.get("count", 0) or 0)
    if float(meta.get("last_failed_at_ts", 0) or 0) <= now_ts - failure_window_seconds:
        count = 0
    count += 1

    blocked_until_ts = 0.0
    blocked_until = None
    if count >= ADMIN_LOGIN_FAILURE_LIMIT:
        blocked_until_ts = now_ts + ADMIN_LOGIN_LOCKOUT_MINUTES * 60
        blocked_until = datetime.utcfromtimestamp(blocked_until_ts).isoformat()

    updated_meta = {
        "count": count,
        "ip": get_request_ip(request),
        "last_failed_at": now.isoformat(),
        "last_failed_at_ts": now_ts,
        "blocked_until": blocked_until,
        "blocked_until_ts": blocked_until_ts,
    }
    attempts[attempt_key] = updated_meta
    data["attempts"] = attempts
    save_admin_login_attempts_data(data)
    return updated_meta


def revoke_open_access_sessions(email_id: str) -> None:
    data = load_open_access_data()
    sessions = {
        token_hash: meta
        for token_hash, meta in data.get("sessions", {}).items()
        if not (isinstance(meta, dict) and meta.get("email_id") == email_id)
    }
    failed_attempts = {
        key: meta
        for key, meta in data.get("failed_attempts", {}).items()
        if not (isinstance(meta, dict) and meta.get("email_id") == email_id)
    }
    save_open_access_data({"sessions": sessions, "failed_attempts": failed_attempts})


def create_open_access_session(email_id: str, meta: dict[str, Any]) -> tuple[str, str]:
    cleanup_expired_open_access()
    now = datetime.utcnow()
    expires_at = now + timedelta(hours=OPEN_ACCESS_SESSION_TTL_HOURS)
    share_expires_at = parse_stored_datetime(meta.get("expires_at"))
    if share_expires_at and share_expires_at < expires_at:
        expires_at = share_expires_at

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    data = load_open_access_data()
    data.setdefault("sessions", {})[token_hash] = {
        "email_id": email_id,
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "expires_at_ts": expires_at.timestamp(),
    }
    save_open_access_data(data)
    return raw_token, expires_at.isoformat()


def get_open_access_attempt_key(email_id: str, request: Request) -> str:
    ip = get_request_ip(request) or "unknown"
    return hashlib.sha256(f"{email_id.lower()}|{ip}".encode("utf-8")).hexdigest()


def clear_open_access_failures(email_id: str, request: Request) -> None:
    data = load_open_access_data()
    attempt_key = get_open_access_attempt_key(email_id, request)
    if attempt_key in data.get("failed_attempts", {}):
        del data["failed_attempts"][attempt_key]
        save_open_access_data(data)


def get_open_access_block_state(email_id: str, request: Request) -> dict[str, Any] | None:
    cleanup_expired_open_access()
    data = load_open_access_data()
    attempt_key = get_open_access_attempt_key(email_id, request)
    meta = data.get("failed_attempts", {}).get(attempt_key)
    if not isinstance(meta, dict):
        return None
    blocked_until = parse_stored_datetime(meta.get("blocked_until"))
    if blocked_until and blocked_until > datetime.utcnow():
        return meta
    return None


def record_open_access_failure(email_id: str, request: Request) -> dict[str, Any]:
    cleanup_expired_open_access()
    now = datetime.utcnow()
    data = load_open_access_data()
    attempt_key = get_open_access_attempt_key(email_id, request)
    attempts = data.setdefault("failed_attempts", {})
    existing = attempts.get(attempt_key)
    failure_window = timedelta(minutes=OPEN_ACCESS_FAILURE_WINDOW_MINUTES)

    if not isinstance(existing, dict):
        count = 0
        first_failed_at = now
    else:
        first_failed_at = parse_stored_datetime(existing.get("first_failed_at")) or now
        if first_failed_at < now - failure_window:
            count = 0
            first_failed_at = now
        else:
            count = int(existing.get("count", 0) or 0)

    count += 1
    blocked_until = now + timedelta(minutes=OPEN_ACCESS_LOCKOUT_MINUTES) if count >= OPEN_ACCESS_FAILURE_LIMIT else None
    attempts[attempt_key] = {
        "email_id": email_id,
        "ip": get_request_ip(request),
        "count": count,
        "first_failed_at": first_failed_at.isoformat(),
        "last_failed_at": now.isoformat(),
        "blocked_until": blocked_until.isoformat() if blocked_until else None,
    }
    save_open_access_data(data)
    return attempts[attempt_key]


def get_open_access_session(request: Request, email_id: str) -> dict[str, Any] | None:
    cleanup_expired_open_access()
    raw_token = request.cookies.get(get_public_share_cookie_name(email_id))
    if not raw_token:
        return None

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    sessions = load_open_access_data().get("sessions", {})
    meta = sessions.get(token_hash)
    if not isinstance(meta, dict):
        return None
    if meta.get("email_id") != email_id:
        return None
    if float(meta.get("expires_at_ts", 0)) <= time.time():
        return None
    return meta


def require_public_share_access(request: Request, email_id: str) -> dict[str, Any]:
    meta = get_public_share_meta(email_id)
    if not is_public_share_active(meta):
        raise HTTPException(status_code=404, detail="Public page unavailable")
    if meta.get("password_hash") and not get_open_access_session(request, email_id):
        raise HTTPException(status_code=401, detail="Access password required")
    return meta


def build_account_health_record(status: str, score: int, summary: str, detail: str = "", checked_at: str | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "score": max(0, min(int(score), 100)),
        "summary": summary,
        "detail": detail,
        "checked_at": checked_at or datetime.utcnow().isoformat(),
    }


def get_account_health_record(email_id: str) -> dict[str, Any]:
    data = load_account_health_data()
    record = data.get("accounts", {}).get(email_id, {})
    if not isinstance(record, dict):
        return build_account_health_record("unchecked", 0, "未检查")
    return {
        "status": str(record.get("status") or "unchecked"),
        "score": max(0, min(int(record.get("score", 0) or 0), 100)),
        "summary": str(record.get("summary") or "未检查"),
        "detail": str(record.get("detail") or ""),
        "checked_at": record.get("checked_at"),
    }


def save_account_health_record(email_id: str, record: dict[str, Any]) -> None:
    data = load_account_health_data()
    data.setdefault("accounts", {})[email_id] = record
    save_account_health_data(data)


def remove_account_health_record(email_id: str) -> None:
    data = load_account_health_data()
    if email_id in data.get("accounts", {}):
        del data["accounts"][email_id]
        save_account_health_data(data)


def extract_api_key_from_request(request: Request) -> str | None:
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        if token:
            return token
    header_token = request.headers.get("X-API-Key", "").strip()
    return header_token or None


def build_api_key_public_record(key_id: str, meta: dict[str, Any]) -> dict[str, Any]:
    now = datetime.utcnow()
    expires_at = parse_stored_datetime(meta.get("expires_at"))
    max_requests = meta.get("max_requests")
    used_requests = int(meta.get("used_requests", 0) or 0)
    unlimited_requests = bool(meta.get("unlimited_requests", False))
    revoked_at = meta.get("revoked_at")
    remaining_requests = None
    if not unlimited_requests and max_requests is not None:
        remaining_requests = max(int(max_requests) - used_requests, 0)

    status = "active"
    if revoked_at:
        status = "revoked"
    elif expires_at and expires_at <= now:
        status = "expired"
    elif remaining_requests == 0 and not unlimited_requests:
        status = "exhausted"

    return {
        "id": key_id,
        "name": meta.get("name", ""),
        "prefix": meta.get("prefix", ""),
        "created_at": meta.get("created_at"),
        "expires_at": meta.get("expires_at"),
        "never_expires": bool(meta.get("never_expires", False)),
        "request_mode": "unlimited" if unlimited_requests else "fixed",
        "max_requests": max_requests,
        "used_requests": used_requests,
        "remaining_requests": remaining_requests,
        "last_used_at": meta.get("last_used_at"),
        "status": status,
        "revoked_at": revoked_at,
    }


def authenticate_api_key(request: Request, consume: bool = True) -> dict[str, Any]:
    raw_key = extract_api_key_from_request(request)
    if not raw_key:
        raise HTTPException(status_code=401, detail="API key required")

    key_hash = hash_api_key(raw_key)
    now = datetime.utcnow()
    data = load_api_keys_data()
    keys = data.get("keys", {})

    for key_id, meta in keys.items():
        if not isinstance(meta, dict) or meta.get("key_hash") != key_hash:
            continue

        public_record = build_api_key_public_record(key_id, meta)
        if public_record["status"] == "revoked":
            raise HTTPException(status_code=401, detail="API key has been revoked")
        if public_record["status"] == "expired":
            raise HTTPException(status_code=401, detail="API key has expired")
        if public_record["status"] == "exhausted":
            raise HTTPException(status_code=429, detail="API key request limit reached")

        if consume:
            meta["used_requests"] = int(meta.get("used_requests", 0) or 0) + 1
            meta["last_used_at"] = now.isoformat()
            keys[key_id] = meta
            usage_logs = data.get("usage_logs", [])
            usage_logs.append(
                {
                    "id": secrets.token_hex(8),
                    "key_id": key_id,
                    "key_name": meta.get("name", ""),
                    "path": request.url.path,
                    "method": request.method,
                    "used_at": now.isoformat(),
                    "ip": get_request_ip(request),
                    "remaining_requests": None
                    if bool(meta.get("unlimited_requests", False))
                    else max(int(meta.get("max_requests", 0) or 0) - int(meta.get("used_requests", 0) or 0), 0),
                }
            )
            data["keys"] = keys
            data["usage_logs"] = usage_logs
            save_api_keys_data(data)

        return {
            "auth_type": "api_key",
            "key_id": key_id,
            "key_name": meta.get("name", ""),
        }

    raise HTTPException(status_code=401, detail="Invalid API key")


def auth_is_configured() -> bool:
    settings = load_auth_settings()
    return bool(settings.get("admin_password_hash")) and bool(settings.get("agreement_accepted"))


def cleanup_expired_sessions() -> None:
    sessions = load_sessions()
    now_ts = time.time()
    active_sessions = {
        token_hash: meta
        for token_hash, meta in sessions.get("sessions", {}).items()
        if isinstance(meta, dict) and float(meta.get("expires_at_ts", 0)) > now_ts
    }
    if active_sessions != sessions.get("sessions", {}):
        save_sessions({"sessions": active_sessions})


def create_session_token() -> tuple[str, str]:
    cleanup_expired_sessions()
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS)
    sessions = load_sessions()
    sessions.setdefault("sessions", {})[token_hash] = {
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": expires_at.isoformat(),
        "expires_at_ts": expires_at.timestamp(),
    }
    save_sessions(sessions)
    return raw_token, expires_at.isoformat()


def delete_session(raw_token: str | None) -> None:
    if not raw_token:
        return
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    sessions = load_sessions()
    if token_hash in sessions.get("sessions", {}):
        del sessions["sessions"][token_hash]
        save_sessions(sessions)


def is_authenticated_request(request: Request) -> bool:
    cleanup_expired_sessions()
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not raw_token:
        return False
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    sessions = load_sessions().get("sessions", {})
    meta = sessions.get(token_hash)
    if not isinstance(meta, dict):
        return False
    return float(meta.get("expires_at_ts", 0)) > time.time()


def require_authenticated(request: Request, allow_api_key: bool = False) -> dict[str, Any]:
    if not auth_is_configured():
        raise HTTPException(status_code=403, detail="Admin password is not configured yet")
    if not is_authenticated_request(request):
        if allow_api_key and extract_api_key_from_request(request):
            return authenticate_api_key(request, consume=True)
        if allow_api_key:
            raise HTTPException(status_code=401, detail="Login required or use API key")
        raise HTTPException(status_code=401, detail="Login required")
    return {"auth_type": "session"}


def make_session_response(
    payload: dict[str, Any],
    raw_token: str | None = None,
    expires_at: str | None = None,
    request: Request | None = None,
) -> JSONResponse:
    response = JSONResponse(payload)
    if raw_token and expires_at:
        max_age = SESSION_TTL_HOURS * 60 * 60
        response.set_cookie(
            SESSION_COOKIE,
            raw_token,
            max_age=max_age,
            expires=max_age,
            httponly=True,
            samesite="lax",
            secure=request_uses_https(request),
            path="/",
        )
    return response


async def get_access_token(credentials: AccountCredentials) -> str:
    auth_method = normalize_account_auth_method(credentials.auth_method)
    base_request_data = {
        "client_id": credentials.client_id,
        "grant_type": "refresh_token",
        "refresh_token": credentials.refresh_token,
    }

    if auth_method == "graph":
        token_urls = [TOKEN_URL, COMMON_TOKEN_URL]
        request_attempts = [
            {**base_request_data, "scope": GRAPH_OAUTH_SCOPE},
            {**base_request_data, "scope": "offline_access openid profile email https://graph.microsoft.com/Mail.Read"},
            {**base_request_data, "scope": "offline_access https://graph.microsoft.com/.default"},
            dict(base_request_data),
        ]
    else:
        token_urls = [TOKEN_URL]
        request_attempts = [
            {**base_request_data, "scope": IMAP_OAUTH_SCOPE},
            dict(base_request_data),
        ]

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            last_error_response: httpx.Response | None = None

            for token_url in token_urls:
                for token_request_data in request_attempts:
                    response = await client.post(token_url, data=token_request_data)
                    if response.is_success:
                        token_data = response.json()
                        access_token = token_data.get("access_token")
                        if not access_token:
                            logger.error(f"No access token in response for {credentials.email}")
                            raise HTTPException(
                                status_code=401,
                                detail="Failed to obtain access token from response",
                            )

                        logger.info(
                            "Successfully obtained %s access token for %s via %s",
                            auth_method,
                            credentials.email,
                            token_url,
                        )
                        return access_token

                    last_error_response = response
                    detail = extract_graph_error_detail(response)
                    logger.warning(
                        "Token attempt failed for %s via %s: HTTP %s %s",
                        credentials.email,
                        token_url,
                        response.status_code,
                        detail,
                    )

            if last_error_response is not None:
                detail = extract_graph_error_detail(last_error_response)
                if last_error_response.status_code == 400:
                    raise HTTPException(status_code=401, detail=detail or "Invalid refresh token or client credentials")
                raise HTTPException(status_code=401, detail=detail or "Authentication failed")

            raise HTTPException(status_code=401, detail="Authentication failed")

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP {e.response.status_code} error getting access token for {credentials.email}: {e}")
        if e.response.status_code == 400:
            raise HTTPException(status_code=401, detail="Invalid refresh token or client credentials")
        raise HTTPException(status_code=401, detail="Authentication failed")
    except httpx.RequestError as e:
        logger.error(f"Request error getting access token for {credentials.email}: {e}")
        raise HTTPException(status_code=500, detail="Network error during token acquisition")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error getting access token for {credentials.email}: {e}")
        raise HTTPException(status_code=500, detail="Token acquisition failed")


def build_graph_headers(access_token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }


def extract_graph_error_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text or "Graph API request failed"

    error = payload.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or error.get("code") or "Graph API request failed")
    return str(payload.get("message") or response.text or "Graph API request failed")


async def graph_api_get(access_token: str, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{GRAPH_API_BASE_URL}{path}",
                headers=build_graph_headers(access_token),
                params=params,
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        detail = extract_graph_error_detail(e.response)
        logger.error("Graph API HTTP %s error for %s: %s", e.response.status_code, path, detail)
        if e.response.status_code in {401, 403}:
            raise HTTPException(status_code=401, detail=detail)
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail=detail)
        raise HTTPException(status_code=500, detail=detail)
    except httpx.RequestError as e:
        logger.error(f"Graph API request error for {path}: {e}")
        raise HTTPException(status_code=500, detail="Network error during Graph API request")


def format_graph_email_address(address_payload: dict[str, Any] | None) -> str:
    if not isinstance(address_payload, dict):
        return ""
    email_address = address_payload.get("emailAddress")
    if not isinstance(email_address, dict):
        return ""
    address = str(email_address.get("address") or "").strip()
    name = str(email_address.get("name") or "").strip()
    if name and address:
        return f"{name} <{address}>"
    return address or name


def format_graph_recipients(recipients: list[dict[str, Any]] | None) -> str:
    if not isinstance(recipients, list):
        return ""
    values = [format_graph_email_address(recipient) for recipient in recipients]
    return ", ".join(value for value in values if value)


def build_graph_message_id(folder: str, graph_message_id: str) -> str:
    return f"graph:{folder}:{graph_message_id}"


def parse_graph_message_id(message_id: str) -> tuple[str, str] | None:
    if not message_id.startswith("graph:"):
        return None
    parts = message_id.split(":", 2)
    if len(parts) != 3 or not parts[2]:
        raise HTTPException(status_code=400, detail="Invalid Graph message_id format")
    return parts[1], parts[2]


def normalize_graph_folder_name(folder: str) -> tuple[str, str]:
    if folder == "junk":
        return "junkemail", "Junk"
    return "inbox", "INBOX"


def graph_message_to_email_item(message: dict[str, Any], folder_key: str) -> EmailItem:
    graph_message_id = str(message.get("id") or "").strip()
    if not graph_message_id:
        raise HTTPException(status_code=500, detail="Graph message is missing id")

    graph_folder_key, display_folder = normalize_graph_folder_name(folder_key)
    from_email = format_graph_email_address(message.get("from"))
    subject = str(message.get("subject") or "(No Subject)")
    received_at = str(message.get("receivedDateTime") or datetime.utcnow().isoformat())
    sender_initial = "?"
    match = re.search(r"([A-Za-z])", from_email)
    if match:
        sender_initial = match.group(1).upper()

    return EmailItem(
        message_id=build_graph_message_id(graph_folder_key, graph_message_id),
        folder=display_folder,
        subject=subject,
        from_email=from_email or "(Unknown Sender)",
        date=received_at,
        is_read=bool(message.get("isRead", False)),
        has_attachments=bool(message.get("hasAttachments", False)),
        sender_initial=sender_initial,
        sender_avatar_url=build_sender_avatar_url(from_email)
    )


def strip_html_tags(content: str) -> str:
    if not content:
        return ""
    return html_lib.unescape(re.sub(r"<[^>]+>", " ", content)).strip()


async def evaluate_account_health(credentials: AccountCredentials) -> dict[str, Any]:
    missing_fields = [
        field_name
        for field_name, field_value in {
            "refresh_token": credentials.refresh_token,
            "client_id": credentials.client_id,
        }.items()
        if not field_value
    ]
    if missing_fields:
        return build_account_health_record(
            "config_error",
            0,
            "账户配置不完整",
            f"缺少字段: {', '.join(missing_fields)}",
        )

    try:
        access_token = await get_access_token(credentials)
    except HTTPException as exc:
        return build_account_health_record(
            "auth_error",
            20,
            "OAuth 刷新失败",
            str(exc.detail),
        )
    except Exception as exc:
        return build_account_health_record(
            "auth_error",
            20,
            "OAuth 刷新失败",
            str(exc),
        )

    if normalize_account_auth_method(credentials.auth_method) == "graph":
        try:
            await graph_api_get(
                access_token,
                "/me/mailFolders/inbox",
                params={"$select": "id,displayName,totalItemCount"},
            )
            return build_account_health_record(
                "healthy",
                100,
                "OAuth 与 Graph 均正常",
            )
        except HTTPException as exc:
            logger.warning(f"Graph health probe failed for {credentials.email}: {exc.detail}")
            return build_account_health_record(
                "graph_error",
                60,
                "OAuth 正常，但 Graph API 请求失败",
                str(exc.detail),
            )
        except Exception as exc:
            logger.warning(f"Graph health probe failed for {credentials.email}: {exc}")
            return build_account_health_record(
                "graph_error",
                60,
                "OAuth 正常，但 Graph API 请求失败",
                str(exc),
            )

    def _probe_imap() -> dict[str, Any]:
        connection = None
        try:
            connection = imap_pool.get_connection(credentials.email, access_token)
            connection.noop()
            return build_account_health_record(
                "healthy",
                100,
                "OAuth 与 IMAP 均正常",
            )
        except Exception as exc:
            logger.warning(f"IMAP health probe failed for {credentials.email}: {exc}")
            return build_account_health_record(
                "imap_error",
                60,
                "OAuth 正常，但 IMAP 连接失败",
                str(exc),
            )
        finally:
            if connection is not None:
                try:
                    imap_pool.return_connection(credentials.email, connection)
                except Exception:
                    try:
                        connection.logout()
                    except Exception:
                        pass

    return await asyncio.to_thread(_probe_imap)


async def validate_account_credentials(credentials: AccountCredentials) -> dict[str, Any]:
    credentials.auth_method = normalize_account_auth_method(credentials.auth_method)
    credentials.category_key = normalize_account_category_key(credentials.category_key)
    credentials.tag_keys = normalize_account_tag_keys(credentials.tag_keys, credentials.tags)
    credentials.tags = list(credentials.tag_keys)
    record = await evaluate_account_health(credentials)
    if record.get("status") != "healthy":
        detail = str(record.get("detail") or record.get("summary") or "Account validation failed")
        status_code = 401 if record.get("status") == "auth_error" else 400
        raise HTTPException(status_code=status_code, detail=detail)
    return record


async def refresh_account_health(email_id: str) -> dict[str, Any]:
    credentials = await get_account_credentials(email_id)
    record = await evaluate_account_health(credentials)
    save_account_health_record(email_id, record)
    return record


async def refresh_all_account_health() -> dict[str, Any]:
    accounts_data = load_accounts_data()
    if not accounts_data:
        return {"total": 0, "checked": 0, "results": {}}

    results: dict[str, Any] = {}
    for email_id in accounts_data.keys():
        try:
            results[email_id] = await refresh_account_health(email_id)
        except HTTPException as exc:
            record = build_account_health_record("error", 10, "健康检查失败", str(exc.detail))
            save_account_health_record(email_id, record)
            results[email_id] = record
        except Exception as exc:
            record = build_account_health_record("error", 10, "健康检查失败", str(exc))
            save_account_health_record(email_id, record)
            results[email_id] = record

    return {
        "total": len(accounts_data),
        "checked": len(results),
        "results": results,
    }


# ============================================================================
# IMAP核心服务 - 邮件列表
# ============================================================================

async def list_graph_folder_emails(
    credentials: AccountCredentials,
    access_token: str,
    folder: str,
    page_size: int,
    page: int = 1,
    skip_override: int | None = None,
    top_override: int | None = None,
) -> tuple[list[EmailItem], int]:
    graph_folder_key, _display_name = normalize_graph_folder_name(folder)
    folder_meta = await graph_api_get(
        access_token,
        f"/me/mailFolders/{graph_folder_key}",
        params={"$select": "id,displayName,totalItemCount"},
    )

    params: dict[str, Any] = {
        "$select": "id,subject,from,receivedDateTime,isRead,hasAttachments",
        "$orderby": "receivedDateTime DESC",
        "$top": top_override if top_override is not None else page_size,
    }
    if skip_override is not None:
        params["$skip"] = skip_override
    elif page > 1:
        params["$skip"] = (page - 1) * page_size

    payload = await graph_api_get(
        access_token,
        f"/me/mailFolders/{graph_folder_key}/messages",
        params=params,
    )
    messages = payload.get("value", [])
    email_items = [graph_message_to_email_item(message, folder) for message in messages if isinstance(message, dict)]
    total_emails = int(folder_meta.get("totalItemCount", len(email_items)) or 0)
    return email_items, total_emails


async def list_graph_emails(
    credentials: AccountCredentials,
    folder: str,
    page: int,
    page_size: int,
    force_refresh: bool = False,
) -> EmailListResponse:
    cache_key = get_account_cache_key(credentials, folder, page, page_size)
    cached_result = get_cached_emails(cache_key, force_refresh)
    if cached_result:
        return cached_result

    access_token = await get_access_token(credentials)
    catalog = load_account_classifications_data()
    email_tag_map = load_email_tags_data().get("emails", {}).get(str(credentials.email), {})

    if folder in {"inbox", "junk"}:
        emails, total_emails = await list_graph_folder_emails(credentials, access_token, folder, page_size, page=page)
        emails = [
            apply_email_tag_details(str(credentials.email), email_item, catalog, email_tag_map)
            for email_item in emails
        ]
        result = EmailListResponse(
            email_id=credentials.email,
            folder_view=folder,
            page=page,
            page_size=page_size,
            total_emails=total_emails,
            emails=emails,
        )
        set_cached_emails(cache_key, result)
        return result

    fetch_limit = page * page_size
    inbox_task = list_graph_folder_emails(
        credentials,
        access_token,
        "inbox",
        page_size,
        page=1,
        skip_override=0,
        top_override=fetch_limit,
    )
    junk_task = list_graph_folder_emails(
        credentials,
        access_token,
        "junk",
        page_size,
        page=1,
        skip_override=0,
        top_override=fetch_limit,
    )
    (inbox_emails, inbox_total), (junk_emails, junk_total) = await asyncio.gather(inbox_task, junk_task)

    all_emails = inbox_emails + junk_emails
    all_emails.sort(key=lambda item: item.date, reverse=True)

    start_index = (page - 1) * page_size
    end_index = start_index + page_size
    paginated_emails = [
        apply_email_tag_details(str(credentials.email), email_item, catalog, email_tag_map)
        for email_item in all_emails[start_index:end_index]
    ]
    result = EmailListResponse(
        email_id=credentials.email,
        folder_view=folder,
        page=page,
        page_size=page_size,
        total_emails=inbox_total + junk_total,
        emails=paginated_emails,
    )
    set_cached_emails(cache_key, result)
    return result


async def list_emails(credentials: AccountCredentials, folder: str, page: int, page_size: int, force_refresh: bool = False) -> EmailListResponse:
    """获取邮件列表 - 优化版本"""
    if normalize_account_auth_method(credentials.auth_method) == "graph":
        return await list_graph_emails(credentials, folder, page, page_size, force_refresh)

    # 检查缓存
    cache_key = get_account_cache_key(credentials, folder, page, page_size)
    cached_result = get_cached_emails(cache_key, force_refresh)
    if cached_result:
        return cached_result

    access_token = await get_access_token(credentials)

    def _sync_list_emails():
        imap_client = None
        try:
            catalog = load_account_classifications_data()
            email_tag_map = load_email_tags_data().get("emails", {}).get(str(credentials.email), {})
            # 从连接池获取连接
            imap_client = imap_pool.get_connection(credentials.email, access_token)
            
            all_emails_data = []
            
            # 根据folder参数决定要获取的文件夹
            folders_to_check = []
            if folder == "inbox":
                folders_to_check = ["INBOX"]
            elif folder == "junk":
                folders_to_check = ["Junk"]
            else:  # folder == "all"
                folders_to_check = ["INBOX", "Junk"]
            
            for folder_name in folders_to_check:
                try:
                    # 选择文件夹
                    imap_client.select(f'"{folder_name}"', readonly=True)
                    
                    # 搜索所有邮件
                    status, messages = imap_client.search(None, "ALL")
                    if status != 'OK' or not messages or not messages[0]:
                        continue
                        
                    message_ids = messages[0].split()
                    
                    # 按日期排序所需的数据（邮件ID和日期）
                    # 为了避免获取所有邮件的日期，我们假设ID顺序与日期大致相关
                    message_ids.reverse() # 通常ID越大越新
                    
                    for msg_id in message_ids:
                        all_emails_data.append({
                            "message_id_raw": msg_id,
                            "folder": folder_name
                        })

                except Exception as e:
                    logger.warning(f"Failed to access folder {folder_name}: {e}")
                    continue
            
            # 对所有文件夹的邮件进行统一分页
            total_emails = len(all_emails_data)
            start_index = (page - 1) * page_size
            end_index = start_index + page_size
            paginated_email_meta = all_emails_data[start_index:end_index]

            email_items = []
            # 按文件夹分组批量获取
            paginated_email_meta.sort(key=lambda x: x['folder'])
            
            for folder_name, group in groupby(paginated_email_meta, key=lambda x: x['folder']):
                try:
                    imap_client.select(f'"{folder_name}"', readonly=True)
                    
                    msg_ids_to_fetch = [item['message_id_raw'] for item in group]
                    if not msg_ids_to_fetch:
                        continue

                    # 批量获取邮件头 - 优化获取字段
                    msg_id_sequence = b','.join(msg_ids_to_fetch)
                    # 只获取必要的头部信息，减少数据传输
                    status, msg_data = imap_client.fetch(msg_id_sequence, '(FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT DATE FROM MESSAGE-ID)])')

                    if status != 'OK':
                        continue
                    
                    # 解析批量获取的数据
                    for i in range(0, len(msg_data), 2):
                        header_data = msg_data[i][1]
                        
                        # 从返回的原始数据中解析出msg_id
                        # e.g., b'1 (BODY[HEADER.FIELDS (SUBJECT DATE FROM)] {..}'
                        match = re.match(rb'(\d+)\s+\(', msg_data[i][0])
                        if not match:
                            continue
                        fetched_msg_id = match.group(1)

                        msg = email.message_from_bytes(header_data)
                        
                        subject = decode_header_value(msg.get('Subject', '(No Subject)'))
                        from_email = decode_header_value(msg.get('From', '(Unknown Sender)'))
                        date_str = msg.get('Date', '')
                        
                        try:
                            date_obj = parsedate_to_datetime(date_str) if date_str else datetime.now()
                            formatted_date = date_obj.isoformat()
                        except:
                            date_obj = datetime.now()
                            formatted_date = date_obj.isoformat()
                        
                        message_id = f"{folder_name}-{fetched_msg_id.decode()}"
                        
                        # 提取发件人首字母
                        sender_initial = "?"
                        if from_email:
                            # 尝试提取邮箱用户名的首字母
                            email_match = re.search(r'([a-zA-Z])', from_email)
                            if email_match:
                                sender_initial = email_match.group(1).upper()
                        
                        email_item = EmailItem(
                            message_id=message_id,
                            folder=folder_name,
                            subject=subject,
                            from_email=from_email,
                            date=formatted_date,
                            is_read=False,  # 简化处理，实际可通过IMAP flags判断
                            has_attachments=False,  # 简化处理，实际需要检查邮件结构
                            sender_initial=sender_initial,
                            sender_avatar_url=build_sender_avatar_url(from_email)
                        )
                        email_items.append(email_item)

                except Exception as e:
                    logger.warning(f"Failed to fetch bulk emails from {folder_name}: {e}")
                    continue

            # 按日期重新排序最终结果
            email_items.sort(key=lambda x: x.date, reverse=True)

            # 归还连接到池中
            imap_pool.return_connection(credentials.email, imap_client)

            result = EmailListResponse(
                email_id=credentials.email,
                folder_view=folder,
                page=page,
                page_size=page_size,
                total_emails=total_emails,
                emails=[
                    apply_email_tag_details(str(credentials.email), email_item, catalog, email_tag_map)
                    for email_item in email_items
                ]
            )

            # 设置缓存
            set_cached_emails(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"Error listing emails: {e}")
            if imap_client:
                try:
                    # 如果出错，尝试归还连接或关闭
                    if hasattr(imap_client, 'state') and imap_client.state != 'LOGOUT':
                        imap_pool.return_connection(credentials.email, imap_client)
                    else:
                        # 连接已断开，从池中移除
                        pass
                except:
                    pass
            raise HTTPException(status_code=500, detail="Failed to retrieve emails")
    
    # 在线程池中运行同步代码
    return await asyncio.to_thread(_sync_list_emails)


# ============================================================================
# IMAP核心服务 - 邮件详情
# ============================================================================

async def get_graph_email_details(credentials: AccountCredentials, message_id: str) -> EmailDetailsResponse:
    parsed_message = parse_graph_message_id(message_id)
    if not parsed_message:
        raise HTTPException(status_code=400, detail="Invalid Graph message_id format")

    _folder_name, graph_message_id = parsed_message
    access_token = await get_access_token(credentials)
    payload = await graph_api_get(
        access_token,
        f"/me/messages/{quote(graph_message_id, safe='')}",
        params={
            "$select": "id,subject,from,toRecipients,receivedDateTime,body",
        },
    )

    body = payload.get("body") if isinstance(payload.get("body"), dict) else {}
    body_content = str(body.get("content") or "")
    content_type = str(body.get("contentType") or "").lower()
    body_html = body_content if content_type == "html" else None
    body_plain = body_content if content_type == "text" else None
    if body_html and not body_plain:
        body_plain = strip_html_tags(body_html)

    from_email = format_graph_email_address(payload.get("from"))
    to_email = format_graph_recipients(payload.get("toRecipients"))

    return apply_email_tag_details(str(credentials.email), EmailDetailsResponse(
        message_id=message_id,
        subject=str(payload.get("subject") or "(No Subject)"),
        from_email=from_email or "(Unknown Sender)",
        to_email=to_email or "(Unknown Recipient)",
        date=str(payload.get("receivedDateTime") or datetime.utcnow().isoformat()),
        sender_avatar_url=build_sender_avatar_url(from_email, size=256),
        body_plain=body_plain if body_plain else None,
        body_html=body_html if body_html else None,
    ))


async def get_email_details(credentials: AccountCredentials, message_id: str) -> EmailDetailsResponse:
    """获取邮件详细内容 - 优化版本"""
    if normalize_account_auth_method(credentials.auth_method) == "graph":
        return await get_graph_email_details(credentials, message_id)

    # 解析复合message_id
    try:
        folder_name, msg_id = message_id.split('-', 1)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid message_id format")

    access_token = await get_access_token(credentials)

    def _sync_get_email_details():
        imap_client = None
        try:
            # 从连接池获取连接
            imap_client = imap_pool.get_connection(credentials.email, access_token)
            
            # 选择正确的文件夹
            imap_client.select(folder_name)
            
            # 获取完整邮件内容
            status, msg_data = imap_client.fetch(msg_id, '(RFC822)')
            
            if status != 'OK' or not msg_data:
                raise HTTPException(status_code=404, detail="Email not found")
            
            # 解析邮件
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            
            # 提取基本信息
            subject = decode_header_value(msg.get('Subject', '(No Subject)'))
            from_email = decode_header_value(msg.get('From', '(Unknown Sender)'))
            to_email = decode_header_value(msg.get('To', '(Unknown Recipient)'))
            date_str = msg.get('Date', '')
            
            # 格式化日期
            try:
                if date_str:
                    date_obj = parsedate_to_datetime(date_str)
                    formatted_date = date_obj.isoformat()
                else:
                    formatted_date = datetime.now().isoformat()
            except:
                formatted_date = datetime.now().isoformat()
            
            # 提取邮件内容
            body_plain, body_html = extract_email_content(msg)

            # 归还连接到池中
            imap_pool.return_connection(credentials.email, imap_client)

            return apply_email_tag_details(str(credentials.email), EmailDetailsResponse(
                message_id=message_id,
                subject=subject,
                from_email=from_email,
                to_email=to_email,
                date=formatted_date,
                sender_avatar_url=build_sender_avatar_url(from_email, size=256),
                body_plain=body_plain if body_plain else None,
                body_html=body_html if body_html else None
            ))

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting email details: {e}")
            if imap_client:
                try:
                    # 如果出错，尝试归还连接
                    if hasattr(imap_client, 'state') and imap_client.state != 'LOGOUT':
                        imap_pool.return_connection(credentials.email, imap_client)
                except:
                    pass
            raise HTTPException(status_code=500, detail="Failed to retrieve email details")
    
    # 在线程池中运行同步代码
    return await asyncio.to_thread(_sync_get_email_details)


# ============================================================================
# FastAPI应用和API端点
# ============================================================================

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """
    FastAPI应用生命周期管理

    处理应用启动和关闭时的资源管理
    """
    # 应用启动
    logger.info("Starting Microsoft-Email-Manager...")
    logger.info(f"IMAP connection pool initialized with max_connections={MAX_CONNECTIONS}")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if ACCOUNTS_FILE.exists() and ACCOUNTS_FILE.is_dir():
        raise RuntimeError(f"Accounts path is a directory, expected a file: {ACCOUNTS_FILE}")
    if not ACCOUNTS_FILE.exists():
        ACCOUNTS_FILE.write_text("{}", encoding="utf-8")
        logger.info(f"Created empty accounts file at {ACCOUNTS_FILE}")
    if AUTH_FILE.exists() and AUTH_FILE.is_dir():
        raise RuntimeError(f"Auth path is a directory, expected a file: {AUTH_FILE}")
    if not AUTH_FILE.exists():
        _write_json_file(
            AUTH_FILE,
            {
                "admin_password_hash": "",
                "agreement_accepted": False,
                "agreement_accepted_at": None,
                "setup_mode": None,
                "updated_at": None,
            },
        )
    if SESSIONS_FILE.exists() and SESSIONS_FILE.is_dir():
        raise RuntimeError(f"Sessions path is a directory, expected a file: {SESSIONS_FILE}")
    if not SESSIONS_FILE.exists():
        _write_json_file(SESSIONS_FILE, {"sessions": {}})
    if API_KEYS_FILE.exists() and API_KEYS_FILE.is_dir():
        raise RuntimeError(f"API keys path is a directory, expected a file: {API_KEYS_FILE}")
    if not API_KEYS_FILE.exists():
        _write_json_file(API_KEYS_FILE, {"keys": {}, "usage_logs": []})
    if PUBLIC_SHARES_FILE.exists() and PUBLIC_SHARES_FILE.is_dir():
        raise RuntimeError(f"Public shares path is a directory, expected a file: {PUBLIC_SHARES_FILE}")
    if not PUBLIC_SHARES_FILE.exists():
        _write_json_file(PUBLIC_SHARES_FILE, {"shares": {}})
    if OPEN_ACCESS_SESSIONS_FILE.exists() and OPEN_ACCESS_SESSIONS_FILE.is_dir():
        raise RuntimeError(f"Open access sessions path is a directory, expected a file: {OPEN_ACCESS_SESSIONS_FILE}")
    if not OPEN_ACCESS_SESSIONS_FILE.exists():
        _write_json_file(OPEN_ACCESS_SESSIONS_FILE, {"sessions": {}, "failed_attempts": {}})
    if ADMIN_LOGIN_ATTEMPTS_FILE.exists() and ADMIN_LOGIN_ATTEMPTS_FILE.is_dir():
        raise RuntimeError(f"Admin login attempts path is a directory, expected a file: {ADMIN_LOGIN_ATTEMPTS_FILE}")
    if not ADMIN_LOGIN_ATTEMPTS_FILE.exists():
        _write_json_file(ADMIN_LOGIN_ATTEMPTS_FILE, {"attempts": {}})
    if ACCOUNT_HEALTH_FILE.exists() and ACCOUNT_HEALTH_FILE.is_dir():
        raise RuntimeError(f"Account health path is a directory, expected a file: {ACCOUNT_HEALTH_FILE}")
    if not ACCOUNT_HEALTH_FILE.exists():
        _write_json_file(ACCOUNT_HEALTH_FILE, {"accounts": {}})
    if ACCOUNT_CLASSIFICATIONS_FILE.exists() and ACCOUNT_CLASSIFICATIONS_FILE.is_dir():
        raise RuntimeError(f"Account classifications path is a directory, expected a file: {ACCOUNT_CLASSIFICATIONS_FILE}")
    if not ACCOUNT_CLASSIFICATIONS_FILE.exists():
        _write_json_file(ACCOUNT_CLASSIFICATIONS_FILE, ensure_builtin_classifications({}, get_effective_setup_mode(load_auth_settings()))[0])
    if EMAIL_TAGS_FILE.exists() and EMAIL_TAGS_FILE.is_dir():
        raise RuntimeError(f"Email tags path is a directory, expected a file: {EMAIL_TAGS_FILE}")
    if not EMAIL_TAGS_FILE.exists():
        _write_json_file(EMAIL_TAGS_FILE, {"emails": {}})
    if SITE_SETTINGS_FILE.exists() and SITE_SETTINGS_FILE.is_dir():
        raise RuntimeError(f"Site settings path is a directory, expected a file: {SITE_SETTINGS_FILE}")
    if not SITE_SETTINGS_FILE.exists():
        _write_json_file(SITE_SETTINGS_FILE, get_default_site_settings())
    ICON_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cleanup_expired_sessions()
    cleanup_expired_open_access()
    cleanup_expired_admin_login_attempts()

    yield

    # 应用关闭
    logger.info("Shutting down Microsoft-Email-Manager...")
    logger.info("Closing IMAP connection pool...")
    imap_pool.close_all_connections()
    logger.info("Application shutdown complete.")


app = FastAPI(
    title="Microsoft-Email-Manager API 服务",
    description="基于FastAPI和IMAP协议的高性能邮件管理系统",
    version="1.0.0",
    lifespan=lifespan
)


def get_cors_allow_origins() -> list[str]:
    raw_value = str(os.getenv("CORS_ALLOW_ORIGINS", "")).strip()
    if not raw_value:
        return []

    origins: list[str] = []
    for item in raw_value.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        if candidate == "*":
            return ["*"]
        normalized = normalize_origin_value(candidate)
        if normalized:
            origins.append(normalized)
        else:
            logger.warning("Ignoring invalid CORS origin: %s", candidate)
    return origins


cors_allow_origins = get_cors_allow_origins()
if cors_allow_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_allow_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "X-API-Key", "Content-Type"],
    )

app.title = "Microsoft-Email-Manager API"
app.description = "Microsoft-Email-Manager 邮件管理后台服务"

@app.middleware("http")
async def site_access_middleware(request: Request, call_next):
    site_settings = load_site_settings()
    share_domain = site_settings.get("share_domain", "")
    share_domain_enabled = bool(site_settings.get("share_domain_enabled")) and bool(share_domain)
    request_host = get_request_host(request)
    path = request.url.path or "/"
    admin_path = get_admin_login_path(site_settings)

    if share_domain_enabled:
        on_share_domain = hosts_match(request_host, share_domain)
        if on_share_domain and not is_share_domain_allowed_path(path):
            if path.startswith("/api/"):
                return JSONResponse({"detail": "This host only serves public share pages."}, status_code=404)
            return PlainTextResponse("Not Found", status_code=404)
        if not on_share_domain and (path == "/open" or path.startswith("/open/") or path == "/api/open" or path.startswith("/api/open/")):
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Public share pages are restricted to the configured share domain."}, status_code=404)
            return PlainTextResponse("Not Found", status_code=404)

    if request.method not in SAFE_BROWSER_METHODS:
        csrf_violation = validate_browser_origin(request)
        if csrf_violation is not None:
            return csrf_violation

    if request.method in {"GET", "HEAD"} and (path == admin_path or path.startswith(admin_path + "/")):
        return FileResponse(STATIC_DIR / "index.html")

    return await call_next(request)

# 挂载静态文件服务
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/api/auth/state")
async def auth_state(request: Request):
    settings = load_auth_settings()
    site_settings = load_site_settings()
    configured = auth_is_configured()
    return {
        "site_title": site_settings.get("home_title") or DEFAULT_HOME_TITLE,
        "admin_login_path": get_admin_login_path(site_settings),
        "configured": configured,
        "authenticated": is_authenticated_request(request) if configured else False,
        "agreement_required": True,
        "agreement_accepted": bool(settings.get("agreement_accepted", False)),
        "auth_mode": "setup" if not configured else "login",
        "turnstile": build_turnstile_client_config(site_settings),
    }


@app.post("/api/auth/setup")
async def auth_setup(payload: SetupPayload, request: Request):
    if auth_is_configured():
        raise HTTPException(status_code=409, detail="Admin password is already configured")
    if not payload.agreed_terms:
        raise HTTPException(status_code=400, detail="You must agree to the terms before continuing")
    setup_mode = normalize_setup_mode(payload.setup_mode)
    if not setup_mode:
        raise HTTPException(status_code=400, detail="Invalid setup mode")
    if setup_mode == "commercial":
        raise HTTPException(status_code=400, detail="商业授权版本暂未开放")
    admin_login_path = normalize_admin_login_path(payload.admin_login_path)
    save_auth_settings(
        {
            "admin_password_hash": hash_password(payload.password),
            "agreement_accepted": True,
            "agreement_accepted_at": datetime.utcnow().isoformat(),
            "setup_mode": setup_mode,
        }
    )
    reset_account_classifications_for_mode(setup_mode)
    site_settings = load_site_settings()
    save_site_settings(
        {
            **site_settings,
            "admin_login_path": admin_login_path,
        }
    )
    raw_token, expires_at = create_session_token()
    return make_session_response(
        {
            "ok": True,
            "configured": True,
            "admin_login_path": admin_login_path,
        },
        raw_token,
        expires_at,
        request,
    )


@app.post("/api/auth/login")
async def auth_login(payload: PasswordPayload, request: Request):
    settings = load_auth_settings()
    if not auth_is_configured():
        raise HTTPException(status_code=403, detail="Admin password is not configured yet")
    blocked_state = get_admin_login_block_state(request)
    if blocked_state:
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    await enforce_turnstile(request, payload.turnstile_token, "admin_login")
    if not verify_password(payload.password, settings.get("admin_password_hash")):
        failure_state = record_admin_login_failure(request)
        if failure_state.get("blocked_until"):
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
        raise HTTPException(status_code=401, detail="Password is incorrect")
    clear_admin_login_failures(request)
    raw_token, expires_at = create_session_token()
    return make_session_response({"ok": True, "configured": True}, raw_token, expires_at, request)


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    delete_session(request.cookies.get(SESSION_COOKIE))
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/api/public/site-info")
async def get_public_site_info():
    site_settings = load_site_settings()
    return {
        "home_title": site_settings.get("home_title") or DEFAULT_HOME_TITLE,
        "home_intro": site_settings.get("home_intro") or DEFAULT_HOME_INTRO,
        "share_domain_enabled": bool(site_settings.get("share_domain_enabled", False)),
        "share_domain": site_settings.get("share_domain") or "",
    }


@app.get("/api/site-settings")
async def get_site_settings(request: Request):
    require_authenticated(request)
    site_settings = load_site_settings()
    admin_path = site_settings.get("admin_login_path") or DEFAULT_ADMIN_LOGIN_PATH
    return {
        **site_settings,
        "admin_login_url": f"{get_request_origin(request)}{admin_path}",
    }


@app.put("/api/site-settings")
async def update_site_settings(payload: SiteSettingsPayload, request: Request):
    require_authenticated(request)
    saved = save_site_settings(payload.dict())
    return {
        **saved,
        "admin_login_url": f"{get_request_origin(request)}{saved['admin_login_path']}",
    }


@app.get("/api/api-keys")
async def list_api_keys(request: Request):
    require_authenticated(request)
    data = load_api_keys_data()
    keys = [
        build_api_key_public_record(key_id, meta)
        for key_id, meta in data.get("keys", {}).items()
        if isinstance(meta, dict)
    ]
    keys.sort(key=lambda item: item.get("created_at") or "", reverse=True)

    usage_logs = data.get("usage_logs", [])
    usage_logs = [log for log in usage_logs if isinstance(log, dict)]
    usage_logs.sort(key=lambda item: item.get("used_at") or "", reverse=True)

    return {
        "keys": keys,
        "usage_logs": usage_logs[:120],
    }


@app.post("/api/api-keys")
async def create_api_key(payload: ApiKeyCreatePayload, request: Request):
    require_authenticated(request)

    now = datetime.utcnow()
    expires_mode = (payload.expires_mode or "never").strip().lower()
    request_mode = (payload.request_mode or "unlimited").strip().lower()

    if expires_mode not in {"never", "fixed"}:
        raise HTTPException(status_code=400, detail="expires_mode must be never or fixed")
    if request_mode not in {"unlimited", "fixed"}:
        raise HTTPException(status_code=400, detail="request_mode must be unlimited or fixed")

    expires_at: datetime | None = None
    if expires_mode == "fixed":
        if payload.expires_at is None:
            raise HTTPException(status_code=400, detail="expires_at is required when expires_mode=fixed")
        expires_at = normalize_utc_datetime(payload.expires_at)
        if expires_at <= now:
            raise HTTPException(status_code=400, detail="expires_at must be later than now")

    max_requests: int | None = None
    if request_mode == "fixed":
        if payload.max_requests is None:
            raise HTTPException(status_code=400, detail="max_requests is required when request_mode=fixed")
        max_requests = int(payload.max_requests)
        if max_requests < 1:
            raise HTTPException(status_code=400, detail="max_requests must be at least 1")

    raw_key = f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"
    key_id = secrets.token_hex(8)
    prefix = f"{raw_key[:12]}..."

    data = load_api_keys_data()
    data.setdefault("keys", {})[key_id] = {
        "name": payload.name.strip(),
        "prefix": prefix,
        "key_hash": hash_api_key(raw_key),
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "never_expires": expires_mode == "never",
        "unlimited_requests": request_mode == "unlimited",
        "max_requests": max_requests,
        "used_requests": 0,
        "last_used_at": None,
        "revoked_at": None,
    }
    save_api_keys_data(data)

    return {
        "api_key": raw_key,
        "key": build_api_key_public_record(key_id, data["keys"][key_id]),
        "message": "API Key created successfully. This key is shown only once.",
    }


@app.delete("/api/api-keys/{key_id}")
async def revoke_api_key(key_id: str, request: Request):
    require_authenticated(request)
    data = load_api_keys_data()
    keys = data.get("keys", {})
    meta = keys.get(key_id)
    if not isinstance(meta, dict):
        raise HTTPException(status_code=404, detail="API key not found")

    meta["revoked_at"] = datetime.utcnow().isoformat()
    keys[key_id] = meta
    data["keys"] = keys
    save_api_keys_data(data)

    return {
        "ok": True,
        "key": build_api_key_public_record(key_id, meta),
        "message": "API key revoked successfully.",
    }


@app.delete("/api/api-keys/{key_id}/permanent")
async def delete_api_key(key_id: str, request: Request):
    require_authenticated(request)
    data = load_api_keys_data()
    keys = data.get("keys", {})
    meta = keys.get(key_id)
    if not isinstance(meta, dict):
        raise HTTPException(status_code=404, detail="API key not found")
    if not meta.get("revoked_at"):
        raise HTTPException(status_code=409, detail="Only revoked API keys can be deleted permanently")

    keys.pop(key_id, None)
    data["keys"] = keys
    usage_logs = data.get("usage_logs", [])
    data["usage_logs"] = [
        log for log in usage_logs
        if not isinstance(log, dict) or log.get("key_id") != key_id
    ]
    save_api_keys_data(data)

    return {
        "ok": True,
        "deleted_key_id": key_id,
        "message": "API key deleted permanently.",
    }


@app.get("/api/public-shares/{email_id}")
async def get_public_share_config(email_id: str, request: Request):
    require_authenticated(request)
    await get_account_credentials(email_id)
    meta = get_public_share_meta(email_id)
    return build_public_share_record(email_id, meta, request)


@app.put("/api/public-shares/{email_id}")
async def update_public_share_config(email_id: str, payload: PublicShareConfigPayload, request: Request):
    require_authenticated(request)
    await get_account_credentials(email_id)

    now = datetime.utcnow()
    expires_mode = (payload.expires_mode or "never").strip().lower()
    if expires_mode not in {"never", "fixed"}:
        raise HTTPException(status_code=400, detail="expires_mode must be never or fixed")
    if payload.clear_password and payload.access_password:
        raise HTTPException(status_code=400, detail="clear_password cannot be combined with access_password")

    expires_at: datetime | None = None
    if payload.enabled and expires_mode == "fixed":
        if payload.expires_at is None:
            raise HTTPException(status_code=400, detail="expires_at is required when expires_mode=fixed")
        expires_at = normalize_utc_datetime(payload.expires_at)
        if expires_at <= now:
            raise HTTPException(status_code=400, detail="expires_at must be later than now")

    new_password = (payload.access_password or "").strip()
    if new_password and len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Access password must be at least 8 characters")

    data = load_public_shares_data()
    shares = data.setdefault("shares", {})
    existing_meta = shares.get(email_id, {})
    existing_meta = existing_meta if isinstance(existing_meta, dict) else {}

    password_hash = existing_meta.get("password_hash", "")
    password_updated_at = existing_meta.get("password_updated_at")
    password_changed = False

    if payload.clear_password:
        password_hash = ""
        password_updated_at = now.isoformat()
        password_changed = True
    elif new_password:
        password_hash = hash_password(new_password)
        password_updated_at = now.isoformat()
        password_changed = True

    shares[email_id] = {
        "enabled": bool(payload.enabled),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "password_hash": password_hash,
        "password_updated_at": password_updated_at,
        "created_at": existing_meta.get("created_at") or now.isoformat(),
        "updated_at": now.isoformat(),
    }
    data["shares"] = shares
    save_public_shares_data(data)

    if not payload.enabled or password_changed:
        revoke_open_access_sessions(email_id)

    return build_public_share_record(email_id, shares[email_id], request)


@app.get("/api/open/emails/{email_id}/status")
async def get_open_email_status(email_id: str, request: Request):
    meta = get_public_share_meta(email_id)
    if not is_public_share_active(meta):
        raise HTTPException(status_code=404, detail="Public page unavailable")
    await get_account_credentials(email_id)
    site_settings = load_site_settings()

    return {
        "email_id": email_id,
        "status": "active",
        "expires_at": meta.get("expires_at"),
        "requires_password": bool(meta.get("password_hash")),
        "access_granted": not bool(meta.get("password_hash")) or bool(get_open_access_session(request, email_id)),
        "public_url": build_public_share_url(request, email_id),
        "turnstile": build_turnstile_client_config(site_settings),
    }


@app.post("/api/open/emails/{email_id}/access")
async def create_open_email_access(email_id: str, payload: PublicShareAccessPayload, request: Request):
    meta = get_public_share_meta(email_id)
    if not is_public_share_active(meta):
        raise HTTPException(status_code=404, detail="Public page unavailable")
    await get_account_credentials(email_id)

    if not meta.get("password_hash"):
        return {"ok": True, "requires_password": False}

    blocked_state = get_open_access_block_state(email_id, request)
    if blocked_state:
        raise HTTPException(status_code=429, detail="Too many password attempts. Try again later.")

    await enforce_turnstile(request, payload.turnstile_token, "public_access")
    if not verify_password(payload.password, meta.get("password_hash")):
        failure_state = record_open_access_failure(email_id, request)
        if parse_stored_datetime(failure_state.get("blocked_until")):
            raise HTTPException(status_code=429, detail="Too many password attempts. Try again later.")
        raise HTTPException(status_code=401, detail="Access password is incorrect")

    clear_open_access_failures(email_id, request)
    raw_token, expires_at = create_open_access_session(email_id, meta)
    response = JSONResponse(
        {
            "ok": True,
            "expires_at": expires_at,
            "access_granted": True,
        }
    )
    max_age = max(60, int((parse_stored_datetime(expires_at) - datetime.utcnow()).total_seconds()))
    response.set_cookie(
        get_public_share_cookie_name(email_id),
        raw_token,
        max_age=max_age,
        expires=max_age,
        httponly=True,
        samesite="lax",
        secure=request_uses_https(request),
        path="/",
    )
    return response


@app.get("/api/open/emails/{email_id}", response_model=EmailListResponse)
async def get_open_emails(
    request: Request,
    email_id: str,
    folder: str = Query("all", regex="^(inbox|junk|all)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    refresh: bool = Query(False, description="强制刷新缓存")
):
    require_public_share_access(request, email_id)
    credentials = await get_account_credentials(email_id)
    return await list_emails(credentials, folder, page, page_size, refresh)


@app.get("/api/open/emails/{email_id}/{message_id}", response_model=EmailDetailsResponse)
async def get_open_email_detail(email_id: str, message_id: str, request: Request):
    require_public_share_access(request, email_id)
    credentials = await get_account_credentials(email_id)
    return await get_email_details(credentials, message_id)


@app.get("/accounts", response_model=AccountListResponse)
async def get_accounts(
    request: Request,
    page: int = Query(1, ge=1, description="页码，从1开始"),
    page_size: int = Query(10, ge=1, le=500, description="每页数量，范围1-500"),
    email_search: Optional[str] = Query(None, description="邮箱账号模糊搜索"),
    email_domain: Optional[str] = Query(None, description="按邮箱后缀精确过滤，例如 outlook.com"),
    tag_search: Optional[str] = Query(None, description="标签模糊搜索"),
    category_search: Optional[str] = Query(None, description="分类模糊搜索，可匹配中英文名称和 key"),
    category_key: Optional[str] = Query(None, description="按分类 key 精确过滤"),
    tag_key: Optional[str] = Query(None, description="按标签 key 精确过滤"),
):
    """获取所有已加载的邮箱账户列表，支持分页和搜索"""
    require_authenticated(request, allow_api_key=True)
    return await get_all_accounts(page, page_size, email_search, email_domain, tag_search, category_search, category_key, tag_key)


@app.get("/classifications", response_model=ClassificationCatalogResponse)
async def get_classifications(request: Request):
    require_authenticated(request, allow_api_key=True)
    return get_classification_catalog_response()


@app.post("/classifications/categories", response_model=ClassificationOption)
async def create_category(payload: ClassificationCreateRequest, request: Request):
    require_authenticated(request, allow_api_key=True)
    return upsert_classification_item("categories", payload)


@app.post("/classifications/tags", response_model=ClassificationOption)
async def create_tag_definition(payload: ClassificationCreateRequest, request: Request):
    require_authenticated(request, allow_api_key=True)
    return upsert_classification_item("tags", payload)


@app.delete("/classifications/categories/{category_key}", response_model=ActionResponse)
async def delete_category(category_key: str, request: Request):
    require_authenticated(request, allow_api_key=True)
    normalized_key = build_classification_key(category_key)
    remove_classification_item("categories", normalized_key)
    remove_account_category_references(normalized_key)
    return ActionResponse(message="Category deleted successfully.", key=normalized_key)


@app.delete("/classifications/tags/{tag_key}", response_model=ActionResponse)
async def delete_tag_definition(tag_key: str, request: Request):
    require_authenticated(request, allow_api_key=True)
    normalized_key = build_classification_key(tag_key)
    remove_classification_item("tags", normalized_key)
    remove_tag_references(normalized_key)
    clear_email_cache()
    return ActionResponse(message="Tag deleted successfully.", key=normalized_key)


@app.post("/accounts/validate", response_model=AccountResponse)
async def validate_account(credentials: AccountCredentials, request: Request):
    """验证邮箱账户配置"""
    require_authenticated(request, allow_api_key=True)
    credentials.category_key = normalize_account_category_key(credentials.category_key)
    credentials.tag_keys = normalize_account_tag_keys(credentials.tag_keys, credentials.tags)
    credentials.tags = list(credentials.tag_keys)
    validate_catalog_references(credentials.category_key, credentials.tag_keys, load_account_classifications_data())
    await validate_account_credentials(credentials)
    return AccountResponse(
        email_id=credentials.email,
        message="Account connection verified successfully."
    )


@app.post("/accounts", response_model=AccountResponse)
async def register_account(credentials: AccountCredentials, request: Request):
    """注册或更新邮箱账户"""
    require_authenticated(request, allow_api_key=True)
    try:
        credentials.auth_method = normalize_account_auth_method(credentials.auth_method)
        credentials.category_key = normalize_account_category_key(credentials.category_key)
        credentials.tag_keys = normalize_account_tag_keys(credentials.tag_keys, credentials.tags)
        credentials.tags = list(credentials.tag_keys)
        validate_catalog_references(credentials.category_key, credentials.tag_keys, load_account_classifications_data())
        health_record = await validate_account_credentials(credentials)

        # 保存凭证
        await save_account_credentials(credentials.email, credentials)
        save_account_health_record(credentials.email, health_record)

        return AccountResponse(
            email_id=credentials.email,
            message="Account verified and saved successfully."
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering account: {e}")
        raise HTTPException(status_code=500, detail="Account registration failed")


@app.post("/accounts/health-check")
async def run_accounts_health_check(request: Request):
    require_authenticated(request, allow_api_key=True)
    return await refresh_all_account_health()


@app.get("/emails/{email_id}", response_model=EmailListResponse)
async def get_emails(
    request: Request,
    email_id: str,
    folder: str = Query("all", regex="^(inbox|junk|all)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    refresh: bool = Query(False, description="强制刷新缓存")
):
    """获取邮件列表"""
    require_authenticated(request, allow_api_key=True)
    credentials = await get_account_credentials(email_id)
    return await list_emails(credentials, folder, page, page_size, refresh)


@app.get("/emails/{email_id}/dual-view")
async def get_dual_view_emails(
    request: Request,
    email_id: str,
    inbox_page: int = Query(1, ge=1),
    junk_page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100)
):
    require_authenticated(request, allow_api_key=True)
    """获取双栏视图邮件（收件箱和垃圾箱）"""
    credentials = await get_account_credentials(email_id)
    
    # 并行获取收件箱和垃圾箱邮件
    inbox_response = await list_emails(credentials, "inbox", inbox_page, page_size)
    junk_response = await list_emails(credentials, "junk", junk_page, page_size)
    
    return DualViewEmailResponse(
        email_id=email_id,
        inbox_emails=inbox_response.emails,
        junk_emails=junk_response.emails,
        inbox_total=inbox_response.total_emails,
        junk_total=junk_response.total_emails
    )


@app.put("/accounts/{email_id}/classification", response_model=AccountResponse)
async def update_account_classification(email_id: str, payload: UpdateAccountClassificationRequest, request: Request):
    """更新账户分类和标签"""
    require_authenticated(request, allow_api_key=True)
    try:
        # 检查账户是否存在
        credentials = await get_account_credentials(email_id)

        category_key = normalize_account_category_key(payload.category_key)
        tag_keys = normalize_account_tag_keys(payload.tag_keys, payload.tags)
        validate_catalog_references(category_key, tag_keys, load_account_classifications_data())

        credentials.category_key = category_key
        credentials.tag_keys = tag_keys
        credentials.tags = list(tag_keys)

        # 保存更新后的凭证
        await save_account_credentials(email_id, credentials)

        return AccountResponse(
            email_id=email_id,
            message="Account classification updated successfully."
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating account classification: {e}")
        raise HTTPException(status_code=500, detail="Failed to update account classification")


@app.put("/accounts/{email_id}/tags", response_model=AccountResponse)
async def update_account_tags_legacy(email_id: str, payload: UpdateAccountClassificationRequest, request: Request):
    return await update_account_classification(email_id, payload, request)

@app.get("/emails/{email_id}/{message_id}", response_model=EmailDetailsResponse)
async def get_email_detail(email_id: str, message_id: str, request: Request):
    require_authenticated(request, allow_api_key=True)
    """获取邮件详细内容"""
    credentials = await get_account_credentials(email_id)
    return await get_email_details(credentials, message_id)


@app.put("/emails/{email_id}/{message_id}/tags", response_model=EmailTagUpdateResponse)
async def update_email_tags(email_id: str, message_id: str, payload: UpdateEmailTagsRequest, request: Request):
    require_authenticated(request, allow_api_key=True)
    await get_account_credentials(email_id)

    tag_keys = normalize_account_tag_keys(payload.tag_keys, payload.tags)
    catalog = load_account_classifications_data()
    validate_catalog_references(None, tag_keys, catalog)
    set_email_tag_keys(email_id, message_id, tag_keys)
    clear_email_cache(email_id)

    return EmailTagUpdateResponse(
        email_id=email_id,
        message_id=message_id,
        message="Email tags updated successfully.",
        tag_keys=tag_keys,
        tag_details=resolve_tag_options(tag_keys, catalog),
    )

@app.delete("/accounts/{email_id}", response_model=AccountResponse)
async def delete_account(email_id: str, request: Request):
    """删除邮箱账户"""
    require_authenticated(request, allow_api_key=True)
    try:
        # 检查账户是否存在
        await get_account_credentials(email_id)

        deleted = False
        with auth_lock:
            accounts = _read_json_file(ACCOUNTS_FILE, {})
            accounts = accounts if isinstance(accounts, dict) else {}
            if email_id in accounts:
                del accounts[email_id]
                _write_json_file(ACCOUNTS_FILE, accounts)
                deleted = True

        if not deleted:
            raise HTTPException(status_code=404, detail="Account not found")

        remove_account_health_record(email_id)
        public_shares_data = load_public_shares_data()
        if email_id in public_shares_data.get("shares", {}):
            del public_shares_data["shares"][email_id]
            save_public_shares_data(public_shares_data)
        email_tags_data = load_email_tags_data()
        if email_id in email_tags_data.get("emails", {}):
            del email_tags_data["emails"][email_id]
            save_email_tags_data(email_tags_data)
        revoke_open_access_sessions(email_id)
        
        return AccountResponse(
            email_id=email_id,
            message="Account deleted successfully."
        )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting account: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete account")

@app.get("/open/emails/{email_id}")
async def open_email_page(email_id: str):
    return FileResponse(STATIC_DIR / "open.html")

@app.get("/")
async def root(request: Request):
    """根路径：未初始化时进入安装页，初始化后显示网站主页"""
    site_settings = load_site_settings()
    share_domain = site_settings.get("share_domain", "")
    share_domain_enabled = bool(site_settings.get("share_domain_enabled")) and bool(share_domain)
    if share_domain_enabled and hosts_match(get_request_host(request), share_domain):
        if not auth_is_configured():
            return PlainTextResponse("Not Found", status_code=404)
        return FileResponse(STATIC_DIR / "home.html")
    if not auth_is_configured():
        return FileResponse(STATIC_DIR / "index.html")
    return FileResponse(STATIC_DIR / "home.html")

@app.delete("/cache/{email_id}")
async def clear_cache(email_id: str, request: Request):
    """清除指定邮箱的缓存"""
    require_authenticated(request, allow_api_key=True)
    clear_email_cache(email_id)
    return {"message": f"Cache cleared for {email_id}"}

@app.delete("/cache")
async def clear_all_cache(request: Request):
    """清除所有缓存"""
    require_authenticated(request, allow_api_key=True)
    clear_email_cache()
    return {"message": "All cache cleared"}

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(STATIC_DIR / "assets" / "logo.png")


def build_domain_icon_svg(domain: str) -> bytes:
    label_source = (domain.split(".", 1)[0] or "?").strip()
    label = (label_source[:1] or "?").upper()
    safe_label = html_lib.escape(label)
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
<rect width="128" height="128" rx="28" fill="#ffffff"/>
<rect x="1.5" y="1.5" width="125" height="125" rx="26.5" fill="none" stroke="#dbe1ea" stroke-width="3"/>
<text x="64" y="78" text-anchor="middle" font-size="58" font-family="Arial, sans-serif" font-weight="700" fill="#111111">{safe_label}</text>
</svg>"""
    return svg.encode("utf-8")


def get_domain_icon_cache_paths(domain: str, size: int) -> tuple[Path, Path]:
    cache_key = hashlib.sha256(f"{domain}:{size}".encode("utf-8")).hexdigest()[:24]
    return (
        ICON_CACHE_DIR / f"{cache_key}.bin",
        ICON_CACHE_DIR / f"{cache_key}.json",
    )


def resolve_local_domain_icon_path(domain: str) -> Path | None:
    normalized_domain = normalize_hostname(domain)
    if not normalized_domain:
        return None

    host = normalized_domain.split(":", 1)[0].strip().lower()
    for filename, suffixes in LOCAL_DOMAIN_ICON_RULES:
        if any(host == suffix or host.endswith("." + suffix) for suffix in suffixes):
            icon_path = ICON_ASSET_DIR / filename
            if icon_path.exists():
                return icon_path
    return None


async def fetch_remote_domain_icon(domain: str, size: int) -> tuple[bytes | None, str | None]:
    sources = [
        f"https://www.google.com/s2/favicons?sz={size}&domain_url={quote(f'https://{domain}', safe='')}",
        f"https://icons.duckduckgo.com/ip3/{quote(domain, safe='')}.ico",
    ]
    headers = {
        "User-Agent": "Microsoft-Email-Manager/1.0",
        "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
    }
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, headers=headers) as client:
        for url in sources:
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                continue

            content_type = (response.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
            if response.status_code == 200 and response.content and (content_type.startswith("image/") or url.endswith(".ico")):
                return response.content, content_type or "image/x-icon"
    return None, None


@app.get("/icons/domain/{domain}", include_in_schema=False)
async def get_cached_domain_icon(domain: str, size: int = Query(128, ge=16, le=256)):
    normalized_domain = normalize_icon_domain(domain)
    if not normalized_domain:
        return Response(content=build_domain_icon_svg(domain), media_type="image/svg+xml")

    local_icon_path = resolve_local_domain_icon_path(normalized_domain)
    if local_icon_path is not None:
        return FileResponse(local_icon_path, media_type="image/svg+xml")

    cache_file, meta_file = get_domain_icon_cache_paths(normalized_domain, size)
    if cache_file.exists() and meta_file.exists():
        try:
            metadata = _read_json_file(meta_file, {"content_type": "image/png"})
            return FileResponse(cache_file, media_type=metadata.get("content_type") or "image/png")
        except Exception:
            logger.warning("Failed to read cached icon metadata for %s", normalized_domain)

    content, content_type = await fetch_remote_domain_icon(normalized_domain, size)
    if content and content_type:
        cache_file.write_bytes(content)
        _write_json_file(meta_file, {"content_type": content_type, "updated_at": datetime.utcnow().isoformat()})
        return FileResponse(cache_file, media_type=content_type)

    return Response(content=build_domain_icon_svg(normalized_domain), media_type="image/svg+xml")

@app.get("/api")
async def api_status(request: Request):
    auth_context = require_authenticated(request, allow_api_key=True)
    """API状态检查"""
    return {
        "message": "Microsoft-Email-Manager API 服务正在运行",
        "version": "1.0.0",
        "authentication": {
            "type": auth_context.get("auth_type"),
            "supports_session_cookie": True,
            "supports_api_key": True,
            "header_authorization": "Authorization: Bearer <API_KEY>",
            "header_alt": "X-API-Key: <API_KEY>",
        },
        "endpoints": {
            "auth_state": "GET /api/auth/state",
            "auth_setup": "POST /api/auth/setup",
            "auth_login": "POST /api/auth/login",
            "auth_logout": "POST /api/auth/logout",
            "list_api_keys": "GET /api/api-keys",
            "create_api_key": "POST /api/api-keys",
            "revoke_api_key": "DELETE /api/api-keys/{key_id}",
            "delete_api_key": "DELETE /api/api-keys/{key_id}/permanent",
            "get_accounts": "GET /accounts",
            "register_account": "POST /accounts",
            "get_classifications": "GET /classifications",
            "create_category": "POST /classifications/categories",
            "create_tag": "POST /classifications/tags",
            "update_account_classification": "PUT /accounts/{email_id}/classification",
            "get_emails": "GET /emails/{email_id}?refresh=true",
            "get_dual_view_emails": "GET /emails/{email_id}/dual-view",
            "get_email_detail": "GET /emails/{email_id}/{message_id}",
            "update_email_tags": "PUT /emails/{email_id}/{message_id}/tags",
            "clear_cache": "DELETE /cache/{email_id}",
            "clear_all_cache": "DELETE /cache"
        }
    }


# ============================================================================
# 启动配置
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    # 启动配置
    HOST = "0.0.0.0"
    PORT = 8000

    logger.info(f"Starting Microsoft-Email-Manager on {HOST}:{PORT}")
    logger.info("Access the web interface at: http://localhost:8000")
    logger.info("Access the API documentation at: http://localhost:8000/docs")

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level="info",
        access_log=True
    )
