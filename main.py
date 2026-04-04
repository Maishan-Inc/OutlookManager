"""
Outlook邮件管理系统 - 主应用模块

基于FastAPI和IMAP协议的高性能邮件管理系统
支持多账户管理、邮件查看、搜索过滤等功能

Author: Outlook Manager Team
Version: 1.0.0
"""

import asyncio
import email
import hashlib
import hmac
import imaplib
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

import httpx
from email.header import decode_header
from email.utils import parsedate_to_datetime
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
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
STATIC_DIR = BASE_DIR / "static"
SESSION_COOKIE = "outlookmanager_session"
SESSION_TTL_HOURS = max(1, int(os.getenv("SESSION_TTL_HOURS", "24")))
API_KEY_PREFIX = "om_"
API_KEY_USAGE_LOG_LIMIT = 500

# OAuth2配置
TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
OAUTH_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"

# IMAP服务器配置
IMAP_SERVER = "outlook.live.com"
IMAP_PORT = 993

# 连接池配置
MAX_CONNECTIONS = 5
CONNECTION_TIMEOUT = 30
SOCKET_TIMEOUT = 15

# 缓存配置
CACHE_EXPIRE_TIME = 60  # 缓存过期时间（秒）

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
    tags: Optional[List[str]] = Field(default=[])

    class Config:
        schema_extra = {
            "example": {
                "email": "user@outlook.com",
                "refresh_token": "0.AXoA...",
                "client_id": "your-client-id",
                "tags": ["工作", "个人"]
            }
        }


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
                "sender_initial": "A"
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
    body_plain: Optional[str] = None
    body_html: Optional[str] = None


class AccountResponse(BaseModel):
    """账户操作响应模型"""
    email_id: str
    message: str


class AccountInfo(BaseModel):
    """账户信息模型"""
    email_id: str
    client_id: str
    status: str = "active"
    tags: List[str] = []


class AccountListResponse(BaseModel):
    """账户列表响应模型"""
    total_accounts: int
    page: int
    page_size: int
    total_pages: int
    accounts: List[AccountInfo]

class UpdateTagsRequest(BaseModel):
    """更新标签请求模型"""
    tags: List[str]


class PasswordPayload(BaseModel):
    password: str = Field(min_length=8, max_length=256)


class SetupPayload(PasswordPayload):
    agreed_terms: bool = Field(default=False)


class ApiKeyCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    expires_mode: str = Field(default="never")
    expires_at: Optional[datetime] = None
    request_mode: str = Field(default="unlimited")
    max_requests: Optional[int] = Field(default=None, ge=1)

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
        # 检查账户文件是否存在
        accounts_path = ACCOUNTS_FILE
        if not accounts_path.exists():
            logger.warning(f"Accounts file {ACCOUNTS_FILE} not found")
            raise HTTPException(status_code=404, detail="No accounts configured")

        # 读取账户数据
        with open(accounts_path, 'r', encoding='utf-8') as f:
            accounts = json.load(f)

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

        return AccountCredentials(
            email=email_id,
            refresh_token=account_data['refresh_token'],
            client_id=account_data['client_id']
        )

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
        accounts = {}
        if ACCOUNTS_FILE.exists():
            with open(ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
                accounts = json.load(f)

        accounts[email_id] = {
            'refresh_token': credentials.refresh_token,
            'client_id': credentials.client_id,
            'tags': credentials.tags if hasattr(credentials, 'tags') else []
        }

        ACCOUNTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(ACCOUNTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(accounts, f, indent=2, ensure_ascii=False)

        logger.info(f"Account credentials saved for {email_id}")
    except Exception as e:
        logger.error(f"Error saving account credentials: {e}")
        raise HTTPException(status_code=500, detail="Failed to save account")


async def get_all_accounts(
    page: int = 1, 
    page_size: int = 10, 
    email_search: Optional[str] = None,
    tag_search: Optional[str] = None
) -> AccountListResponse:
    """获取所有已加载的邮箱账户列表，支持分页和搜索"""
    try:
        if not ACCOUNTS_FILE.exists():
            return AccountListResponse(
                total_accounts=0, 
                page=page, 
                page_size=page_size, 
                total_pages=0, 
                accounts=[]
            )

        with open(ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
            accounts_data = json.load(f)

        all_accounts = []
        for email_id, account_info in accounts_data.items():
            # 验证账户状态（可选：检查token是否有效）
            status = "active"
            try:
                # 简单验证：检查必要字段是否存在
                if not account_info.get('refresh_token') or not account_info.get('client_id'):
                    status = "invalid"
            except Exception:
                status = "error"

            account = AccountInfo(
                email_id=email_id,
                client_id=account_info.get('client_id', ''),
                status=status,
                tags=account_info.get('tags', [])
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
        
        # 标签模糊搜索
        if tag_search:
            tag_search_lower = tag_search.lower()
            filtered_accounts = [
                acc for acc in filtered_accounts 
                if any(tag_search_lower in tag.lower() for tag in acc.tags)
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
            accounts=paginated_accounts
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

auth_lock = threading.Lock()


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
                "updated_at": None,
            },
        )


def save_auth_settings(settings: dict[str, Any]) -> None:
    with auth_lock:
        payload = {
            "admin_password_hash": settings.get("admin_password_hash", ""),
            "agreement_accepted": bool(settings.get("agreement_accepted", False)),
            "agreement_accepted_at": settings.get("agreement_accepted_at"),
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
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return ""


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


def make_session_response(payload: dict[str, Any], raw_token: str | None = None, expires_at: str | None = None) -> JSONResponse:
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
            secure=False,
            path="/",
        )
    return response


async def get_access_token(credentials: AccountCredentials) -> str:
    """
    使用refresh_token获取access_token

    Args:
        credentials: 账户凭证信息

    Returns:
        str: OAuth2访问令牌

    Raises:
        HTTPException: 令牌获取失败
    """
    # 构建OAuth2请求数据
    token_request_data = {
        'client_id': credentials.client_id,
        'grant_type': 'refresh_token',
        'refresh_token': credentials.refresh_token,
        'scope': OAUTH_SCOPE
    }

    try:
        # 发送令牌请求
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(TOKEN_URL, data=token_request_data)
            response.raise_for_status()

            # 解析响应
            token_data = response.json()
            access_token = token_data.get('access_token')

            if not access_token:
                logger.error(f"No access token in response for {credentials.email}")
                raise HTTPException(
                    status_code=401,
                    detail="Failed to obtain access token from response"
                )

            logger.info(f"Successfully obtained access token for {credentials.email}")
            return access_token

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP {e.response.status_code} error getting access token for {credentials.email}: {e}")
        if e.response.status_code == 400:
            raise HTTPException(status_code=401, detail="Invalid refresh token or client credentials")
        else:
            raise HTTPException(status_code=401, detail="Authentication failed")
    except httpx.RequestError as e:
        logger.error(f"Request error getting access token for {credentials.email}: {e}")
        raise HTTPException(status_code=500, detail="Network error during token acquisition")
    except Exception as e:
        logger.error(f"Unexpected error getting access token for {credentials.email}: {e}")
        raise HTTPException(status_code=500, detail="Token acquisition failed")


# ============================================================================
# IMAP核心服务 - 邮件列表
# ============================================================================

async def list_emails(credentials: AccountCredentials, folder: str, page: int, page_size: int, force_refresh: bool = False) -> EmailListResponse:
    """获取邮件列表 - 优化版本"""

    # 检查缓存
    cache_key = get_cache_key(credentials.email, folder, page, page_size)
    cached_result = get_cached_emails(cache_key, force_refresh)
    if cached_result:
        return cached_result

    access_token = await get_access_token(credentials)

    def _sync_list_emails():
        imap_client = None
        try:
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
                            sender_initial=sender_initial
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
                emails=email_items
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

async def get_email_details(credentials: AccountCredentials, message_id: str) -> EmailDetailsResponse:
    """获取邮件详细内容 - 优化版本"""
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

            return EmailDetailsResponse(
                message_id=message_id,
                subject=subject,
                from_email=from_email,
                to_email=to_email,
                date=formatted_date,
                body_plain=body_plain if body_plain else None,
                body_html=body_html if body_html else None
            )

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
    logger.info("Starting Outlook Email Management System...")
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
    cleanup_expired_sessions()

    yield

    # 应用关闭
    logger.info("Shutting down Outlook Email Management System...")
    logger.info("Closing IMAP connection pool...")
    imap_pool.close_all_connections()
    logger.info("Application shutdown complete.")


app = FastAPI(
    title="Outlook邮件API服务",
    description="基于FastAPI和IMAP协议的高性能邮件管理系统",
    version="1.0.0",
    lifespan=lifespan
)

app.title = "OutlookManager API"
app.description = "OutlookManager 邮件管理后台服务"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载静态文件服务
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/api/auth/state")
async def auth_state(request: Request):
    settings = load_auth_settings()
    configured = auth_is_configured()
    return {
        "site_title": "OutlookManager",
        "configured": configured,
        "authenticated": is_authenticated_request(request) if configured else False,
        "agreement_required": True,
        "agreement_accepted": bool(settings.get("agreement_accepted", False)),
        "auth_mode": "setup" if not configured else "login",
    }


@app.post("/api/auth/setup")
async def auth_setup(payload: SetupPayload):
    if auth_is_configured():
        raise HTTPException(status_code=409, detail="Admin password is already configured")
    if not payload.agreed_terms:
        raise HTTPException(status_code=400, detail="You must agree to the terms before continuing")
    save_auth_settings(
        {
            "admin_password_hash": hash_password(payload.password),
            "agreement_accepted": True,
            "agreement_accepted_at": datetime.utcnow().isoformat(),
        }
    )
    raw_token, expires_at = create_session_token()
    return make_session_response({"ok": True, "configured": True}, raw_token, expires_at)


@app.post("/api/auth/login")
async def auth_login(payload: PasswordPayload):
    settings = load_auth_settings()
    if not auth_is_configured():
        raise HTTPException(status_code=403, detail="Admin password is not configured yet")
    if not verify_password(payload.password, settings.get("admin_password_hash")):
        raise HTTPException(status_code=401, detail="Password is incorrect")
    raw_token, expires_at = create_session_token()
    return make_session_response({"ok": True, "configured": True}, raw_token, expires_at)


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    delete_session(request.cookies.get(SESSION_COOKIE))
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


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


@app.get("/accounts", response_model=AccountListResponse)
async def get_accounts(
    request: Request,
    page: int = Query(1, ge=1, description="页码，从1开始"),
    page_size: int = Query(10, ge=1, le=100, description="每页数量，范围1-100"),
    email_search: Optional[str] = Query(None, description="邮箱账号模糊搜索"),
    tag_search: Optional[str] = Query(None, description="标签模糊搜索")
):
    """获取所有已加载的邮箱账户列表，支持分页和搜索"""
    require_authenticated(request, allow_api_key=True)
    return await get_all_accounts(page, page_size, email_search, tag_search)


@app.post("/accounts", response_model=AccountResponse)
async def register_account(credentials: AccountCredentials, request: Request):
    """注册或更新邮箱账户"""
    require_authenticated(request, allow_api_key=True)
    try:
        # 验证凭证有效性
        await get_access_token(credentials)

        # 保存凭证
        await save_account_credentials(credentials.email, credentials)

        return AccountResponse(
            email_id=credentials.email,
            message="Account verified and saved successfully."
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering account: {e}")
        raise HTTPException(status_code=500, detail="Account registration failed")


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
    print('credentials:' + str(credentials))
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


@app.put("/accounts/{email_id}/tags", response_model=AccountResponse)
async def update_account_tags(email_id: str, payload: UpdateTagsRequest, request: Request):
    """更新账户标签"""
    require_authenticated(request, allow_api_key=True)
    try:
        # 检查账户是否存在
        credentials = await get_account_credentials(email_id)
        
        # 更新标签
        credentials.tags = payload.tags
        
        # 保存更新后的凭证
        await save_account_credentials(email_id, credentials)
        
        return AccountResponse(
            email_id=email_id,
            message="Account tags updated successfully."
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating account tags: {e}")
        raise HTTPException(status_code=500, detail="Failed to update account tags")

@app.get("/emails/{email_id}/{message_id}", response_model=EmailDetailsResponse)
async def get_email_detail(email_id: str, message_id: str, request: Request):
    require_authenticated(request, allow_api_key=True)
    """获取邮件详细内容"""
    credentials = await get_account_credentials(email_id)
    return await get_email_details(credentials, message_id)

@app.delete("/accounts/{email_id}", response_model=AccountResponse)
async def delete_account(email_id: str, request: Request):
    """删除邮箱账户"""
    require_authenticated(request, allow_api_key=True)
    try:
        # 检查账户是否存在
        await get_account_credentials(email_id)
        
        # 读取现有账户
        accounts = {}
        if ACCOUNTS_FILE.exists():
            with open(ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
                accounts = json.load(f)
        
        # 删除指定账户
        if email_id in accounts:
            del accounts[email_id]
            
            # 保存更新后的账户列表
            with open(ACCOUNTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(accounts, f, indent=2, ensure_ascii=False)
            
            return AccountResponse(
                email_id=email_id,
                message="Account deleted successfully."
            )
        else:
            raise HTTPException(status_code=404, detail="Account not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting account: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete account")

@app.get("/")
async def root():
    """根路径 - 返回前端页面"""
    return FileResponse(STATIC_DIR / "index.html")

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

@app.get("/api")
async def api_status(request: Request):
    auth_context = require_authenticated(request, allow_api_key=True)
    """API状态检查"""
    return {
        "message": "Outlook邮件API服务正在运行",
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
            "get_accounts": "GET /accounts",
            "register_account": "POST /accounts",
            "get_emails": "GET /emails/{email_id}?refresh=true",
            "get_dual_view_emails": "GET /emails/{email_id}/dual-view",
            "get_email_detail": "GET /emails/{email_id}/{message_id}",
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

    logger.info(f"Starting Outlook Email Management System on {HOST}:{PORT}")
    logger.info("Access the web interface at: http://localhost:8000")
    logger.info("Access the API documentation at: http://localhost:8000/docs")

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level="info",
        access_log=True
    )
