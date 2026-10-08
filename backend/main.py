import os
import json
import hashlib
import hmac
import secrets
import re
import base64
import binascii
import urllib.parse
import html
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session


# ============================================================
# CONFIGURATION
# ============================================================

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./pygenic_arc.db"
)

API_KEY = os.getenv(
    "PYGENIC_ARC_API_KEY",
    "arc_demo_change_me"
)

SESSION_DAYS = int(os.getenv("SESSION_DAYS", "1"))
OTP_MINUTES = int(os.getenv("OTP_MINUTES", "5"))

OTP_PEPPER = os.getenv(
    "OTP_PEPPER",
    "change-this-otp-secret"
)

TWILIO_ACCOUNT_SID = os.getenv(
    "TWILIO_ACCOUNT_SID",
    ""
)

TWILIO_AUTH_TOKEN = os.getenv(
    "TWILIO_AUTH_TOKEN",
    ""
)

TWILIO_FROM_NUMBER = os.getenv(
    "TWILIO_FROM_NUMBER",
    ""
)

connect_args = (
    {"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {}
)

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False
)

Base = declarative_base()


# ============================================================
# DATABASE MODELS
# ============================================================

class Audit(Base):
    __tablename__ = "audit"

    id = Column(Integer, primary_key=True)

    timestamp = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    agent = Column(
        String(120),
        nullable=False
    )

    tool = Column(
        String(120),
        nullable=False
    )

    decision = Column(
        String(20),
        nullable=False
    )

    score = Column(
        Integer,
        nullable=False
    )

    level = Column(
        String(20),
        nullable=False
    )

    risks = Column(
        Text,
        nullable=False
    )

    explanation = Column(
        Text,
        nullable=False
    )

    evidence = Column(
        Text,
        nullable=False
    )


class Policy(Base):
    __tablename__ = "policy"

    id = Column(
        Integer,
        primary_key=True
    )

    max_transfer = Column(
        Integer,
        default=50000,
        nullable=False
    )

    block_prompt_injection = Column(
        Integer,
        default=1,
        nullable=False
    )

    block_secrets = Column(
        Integer,
        default=1,
        nullable=False
    )


class ActionPolicy(Base):
    __tablename__ = "action_policy"

    id = Column(
        Integer,
        primary_key=True
    )

    action = Column(
        String(120),
        unique=True,
        nullable=False
    )

    decision = Column(
        String(20),
        nullable=False,
        default="ALLOW"
    )

    require_approval = Column(
        Integer,
        nullable=False,
        default=0
    )

    enabled = Column(
        Integer,
        nullable=False,
        default=1
    )

    reason = Column(
        Text,
        nullable=False,
        default=""
    )


class AgentPermission(Base):
    __tablename__ = "agent_permission"

    id = Column(
        Integer,
        primary_key=True
    )

    agent_id = Column(
        String(120),
        nullable=False
    )

    tool = Column(
        String(120),
        nullable=False
    )

    allowed = Column(
        Integer,
        nullable=False,
        default=0
    )

    reason = Column(
        Text,
        nullable=False,
        default=""
    )


class AgentIdentity(Base):
    __tablename__ = "agent_identity"

    id = Column(
        Integer,
        primary_key=True
    )

    agent_id = Column(
        String(120),
        unique=True,
        nullable=False
    )

    role = Column(
        String(50),
        nullable=False,
        default="readonly"
    )

    enabled = Column(
        Integer,
        nullable=False,
        default=1
    )

    description = Column(
        Text,
        nullable=False,
        default=""
    )


class ArcUser(Base):
    __tablename__ = "arc_user"

    id = Column(
        Integer,
        primary_key=True
    )

    username = Column(
        String(120),
        unique=True,
        nullable=False
    )

    password_hash = Column(
        String(255),
        nullable=False
    )

    phone_number = Column(
        String(30),
        nullable=False
    )

    enabled = Column(
        Integer,
        default=1,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class UserSession(Base):
    __tablename__ = "user_session"

    id = Column(
        Integer,
        primary_key=True
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    token_hash = Column(
        String(64),
        unique=True,
        nullable=False
    )

    expires_at = Column(
        DateTime,
        nullable=False
    )

    revoked = Column(
        Integer,
        default=0,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class ApprovalRequest(Base):
    __tablename__ = "approval_request"

    id = Column(
        Integer,
        primary_key=True
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    agent_id = Column(
        String(120),
        nullable=False
    )

    action = Column(
        String(120),
        nullable=False
    )

    tool = Column(
        String(120),
        nullable=False
    )

    risk_score = Column(
        Integer,
        nullable=False
    )

    status = Column(
        String(30),
        default="PENDING",
        nullable=False
    )

    expires_at = Column(
        DateTime,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class OTPCode(Base):
    __tablename__ = "otp_code"

    id = Column(
        Integer,
        primary_key=True
    )

    approval_id = Column(
        Integer,
        nullable=False
    )

    otp_hash = Column(
        String(64),
        nullable=False
    )

    attempts = Column(
        Integer,
        default=0,
        nullable=False
    )

    expires_at = Column(
        DateTime,
        nullable=False
    )

    verified = Column(
        Integer,
        default=0,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class ThreatPolicy(Base):
    __tablename__ = "threat_policy"

    id = Column(
        Integer,
        primary_key=True
    )

    threat = Column(
        String(100),
        unique=True,
        nullable=False
    )

    decision = Column(
        String(20),
        nullable=False,
        default="BLOCK"
    )

    enabled = Column(
        Integer,
        nullable=False,
        default=1
    )

    reason = Column(
        Text,
        nullable=False,
        default=""
    )


Base.metadata.create_all(bind=engine)


# ============================================================
# REQUEST MODELS
# ============================================================

class RegisterIn(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=120
    )

    password: str = Field(
        min_length=8,
        max_length=200
    )

    phone_number: str = Field(
        min_length=8,
        max_length=30
    )


class LoginIn(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=120
    )

    password: str = Field(
        min_length=1,
        max_length=200
    )


class ApprovalRequestIn(BaseModel):
    agent_id: str = Field(
        default="agent-001",
        min_length=1,
        max_length=120
    )

    action: str = Field(
        min_length=1,
        max_length=120
    )

    tool: str = Field(
        default="unknown",
        max_length=120
    )

    target: Optional[str] = Field(
        default=None,
        max_length=500
    )

    reason: Optional[str] = Field(
        default=None,
        max_length=1000
    )


class OTPVerifyIn(BaseModel):
    approval_id: int

    otp: str = Field(
        min_length=6,
        max_length=6
    )


class ActionExecuteIn(BaseModel):
    agent_id: str = Field(
        default="agent-001",
        min_length=1,
        max_length=120
    )

    action: str = Field(
        min_length=1,
        max_length=120
    )

    tool: str = Field(
        default="unknown",
        max_length=120
    )

    target: Optional[str] = Field(
        default=None,
        max_length=500
    )

    reason: Optional[str] = Field(
        default=None,
        max_length=1000
    )

    approval_id: Optional[int] = None

    parameters: Dict[str, Any] = Field(
        default_factory=dict
    )


class ThreatPolicyIn(BaseModel):
    threat: str = Field(
        min_length=1,
        max_length=100
    )

    decision: str = Field(
        default="BLOCK",
        pattern="^(ALLOW|REVIEW|BLOCK)$"
    )

    enabled: bool = True

    reason: str = Field(
        default="",
        max_length=500
    )


class Action(BaseModel):
    agent_id: str = Field(
        default="agent-001",
        min_length=1,
        max_length=120
    )

    tool: str = Field(
        min_length=1,
        max_length=120
    )

    parameters: Dict[str, Any] = Field(
        default_factory=dict
    )

    authorization: bool = False

    state: Dict[str, Any] = Field(
        default_factory=dict
    )


class ActionControlIn(BaseModel):
    agent_id: str = Field(
        default="agent-001",
        min_length=1,
        max_length=120
    )

    action: str = Field(
        min_length=1,
        max_length=120
    )

    tool: str = Field(
        default="unknown",
        max_length=120
    )

    target: Optional[str] = Field(
        default=None,
        max_length=500
    )

    reason: Optional[str] = Field(
        default=None,
        max_length=1000
    )

    user_approved: bool = False


class ContentIn(BaseModel):
    agent_id: str = Field(
        default="agent-001",
        min_length=1,
        max_length=120
    )

    content: str = Field(
        min_length=1,
        max_length=100000
    )

    action: Optional[str] = Field(
        default=None,
        max_length=120
    )


class RAGIn(BaseModel):
    agent_id: str = Field(
        default="agent-001",
        min_length=1,
        max_length=120
    )

    source: str = Field(
        min_length=1,
        max_length=500
    )

    document_id: str = Field(
        min_length=1,
        max_length=200
    )

    content: str = Field(
        min_length=1,
        max_length=200000
    )

    trusted_source: bool = False


class MemoryIn(BaseModel):
    agent_id: str = Field(
        default="agent-001",
        min_length=1,
        max_length=120
    )

    memory_id: str = Field(
        min_length=1,
        max_length=200
    )

    content: str = Field(
        min_length=1,
        max_length=200000
    )

    memory_type: str = Field(
        default="long_term",
        max_length=50
    )

    trusted: bool = False

    source: str = Field(
        default="agent_memory",
        max_length=500
    )


class PolicyIn(BaseModel):
    max_transfer: int = Field(
        ge=100,
        le=10000000
    )

    block_prompt_injection: bool = True

    block_secrets: bool = True


class ActionPolicyIn(BaseModel):
    action: str = Field(
        min_length=1,
        max_length=120
    )

    decision: str = Field(
        default="ALLOW",
        pattern="^(ALLOW|REVIEW|BLOCK)$"
    )

    require_approval: bool = False

    enabled: bool = True

    reason: str = Field(
        default="",
        max_length=500
    )


class AgentPermissionIn(BaseModel):
    agent_id: str = Field(
        min_length=1,
        max_length=120
    )

    tool: str = Field(
        min_length=1,
        max_length=120
    )

    allowed: bool = False

    reason: str = Field(
        default="",
        max_length=500
    )


class AgentIdentityIn(BaseModel):
    agent_id: str = Field(
        min_length=1,
        max_length=120
    )

    role: str = Field(
        default="readonly",
        pattern="^(readonly|analyst|operator|admin)$"
    )

    enabled: bool = True

    description: str = Field(
        default="",
        max_length=500
    )


# ============================================================
# DATABASE
# ============================================================

def db():
    session = SessionLocal()

    try:
        yield session

    finally:
        session.close()


# ============================================================
# API KEY AUTH
# ============================================================

def auth(
    x_api_key: Optional[str] = Header(
        default=None
    )
):
    if (
        not x_api_key
        or not secrets.compare_digest(
            x_api_key,
            API_KEY
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )


# ============================================================
# PASSWORD SECURITY
# ============================================================

def hash_password(
    password: str
) -> str:

    salt = secrets.token_bytes(16)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        210000
    )

    return (
        salt.hex()
        + ":"
        + derived.hex()
    )


def verify_password(
    password: str,
    stored: str
) -> bool:

    try:
        salt_hex, hash_hex = stored.split(
            ":",
            1
        )

        salt = bytes.fromhex(
            salt_hex
        )

        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            210000
        )

        return hmac.compare_digest(
            derived.hex(),
            hash_hex
        )

    except Exception:
        return False


# ============================================================
# SESSION SECURITY
# ============================================================

def hash_token(
    token: str
) -> str:

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def create_session(
    session: Session,
    user_id: int
):

    # Revoke older active sessions.
    session.query(
        UserSession
    ).filter(
        UserSession.user_id == user_id,
        UserSession.revoked == 0
    ).update(
        {
            UserSession.revoked: 1
        },
        synchronize_session=False
    )

    raw_token = secrets.token_urlsafe(48)

    token_hash = hash_token(
        raw_token
    )

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(days=SESSION_DAYS)
    )

    row = UserSession(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        revoked=0
    )

    session.add(row)
    session.commit()

    return raw_token


def get_current_user(
    authorization: Optional[str],
    session: Session
):

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    if not authorization.startswith(
        "Bearer "
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization header"
        )

    token = authorization[7:].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid session"
        )

    token_hash = hash_token(
        token
    )

    session_row = (
        session.query(UserSession)
        .filter(
            UserSession.token_hash == token_hash,
            UserSession.revoked == 0
        )
        .first()
    )

    if session_row is None:
        raise HTTPException(
            status_code=401,
            detail="Session expired or invalid"
        )

    now = datetime.now(
        timezone.utc
    )

    expires = session_row.expires_at

    if expires.tzinfo is None:
        expires = expires.replace(
            tzinfo=timezone.utc
        )

    if expires <= now:

        session_row.revoked = 1

        session.commit()

        raise HTTPException(
            status_code=401,
            detail="Session expired"
        )

    user = (
        session.query(ArcUser)
        .filter(
            ArcUser.id == session_row.user_id,
            ArcUser.enabled == 1
        )
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User account disabled"
        )

    return user


# ============================================================
# OTP
# ============================================================

def hash_otp(
    otp: str
) -> str:

    return hashlib.sha256(
        (
            OTP_PEPPER
            + ":"
            + otp
        ).encode("utf-8")
    ).hexdigest()


def mask_phone(
    phone: str
) -> str:

    if len(phone) <= 4:
        return "****"

    return (
        "*"
        * max(
            0,
            len(phone) - 4
        )
        + phone[-4:]
    )


def send_sms(
    phone: str,
    message: str
):

    if not (
        TWILIO_ACCOUNT_SID
        and TWILIO_AUTH_TOKEN
        and TWILIO_FROM_NUMBER
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "SMS provider is not configured. "
                "Configure Twilio environment variables "
                "before requesting OTP."
            )
        )

    try:

        from twilio.rest import Client

        client = Client(
            TWILIO_ACCOUNT_SID,
            TWILIO_AUTH_TOKEN
        )

        client.messages.create(
            body=message,
            from_=TWILIO_FROM_NUMBER,
            to=phone
        )

    except ImportError:

        raise HTTPException(
            status_code=503,
            detail=(
                "Twilio SDK is not installed. "
                "Run: pip install twilio"
            )
        )

    except Exception:

        raise HTTPException(
            status_code=502,
            detail="SMS delivery failed."
        )


# ============================================================
# GLOBAL POLICY
# ============================================================

def policy_value(
    session: Session
):

    policy = session.query(
        Policy
    ).first()

    if policy is None:

        policy = Policy(
            max_transfer=50000,
            block_prompt_injection=1,
            block_secrets=1
        )

        session.add(policy)
        session.commit()
        session.refresh(policy)

    return policy


# ============================================================
# ACTION POLICIES
# ============================================================

def initialize_action_policies(
    session: Session
):

    defaults = [

        {
            "action": "search_products",
            "decision": "ALLOW",
            "require_approval": False,
            "enabled": True,
            "reason": (
                "Normal product search action is allowed."
            )
        },

        {
            "action": "transfer_money",
            "decision": "REVIEW",
            "require_approval": True,
            "enabled": True,
            "reason": (
                "Financial transfers require user approval."
            )
        },

        {
            "action": "delete_account",
            "decision": "BLOCK",
            "require_approval": True,
            "enabled": True,
            "reason": (
                "Account deletion is blocked by default."
            )
        },

        {
            "action": "delete_user",
            "decision": "BLOCK",
            "require_approval": True,
            "enabled": True,
            "reason": (
                "User deletion is blocked by default."
            )
        },

        {
            "action": "checkout",
            "decision": "REVIEW",
            "require_approval": True,
            "enabled": True,
            "reason": (
                "Checkout requires user approval."
            )
        },

        {
            "action": "send_email",
            "decision": "REVIEW",
            "require_approval": True,
            "enabled": True,
            "reason": (
                "External communication requires approval."
            )
        }
    ]

    for item in defaults:

        existing = (
            session.query(ActionPolicy)
            .filter(
                ActionPolicy.action
                == item["action"]
            )
            .first()
        )

        if existing is None:

            session.add(
                ActionPolicy(
                    action=item["action"],
                    decision=item["decision"],
                    require_approval=int(
                        item["require_approval"]
                    ),
                    enabled=int(
                        item["enabled"]
                    ),
                    reason=item["reason"]
                )
            )

    session.commit()


def get_action_policy(
    session: Session,
    action_name: str
):

    initialize_action_policies(
        session
    )

    return (
        session.query(ActionPolicy)
        .filter(
            ActionPolicy.action
            == action_name
        )
        .first()
    )


# ============================================================
# THREAT POLICIES
# ============================================================

THREAT_DEFAULTS = [

    (
        "PROMPT_INJECTION",
        "BLOCK",
        "Prompt injection is blocked by default."
    ),

    (
        "SECRETS",
        "BLOCK",
        "Secrets and credentials are blocked."
    ),

    (
        "SQL_INJECTION",
        "BLOCK",
        "SQL injection is blocked."
    ),

    (
        "COMMAND_INJECTION",
        "BLOCK",
        "Command injection is blocked."
    ),

    (
        "ENCODED_PAYLOAD",
        "REVIEW",
        "Encoded content requires inspection."
    ),

    (
        "HIDDEN_UNICODE",
        "REVIEW",
        "Hidden Unicode requires inspection."
    ),

    (
        "XSS",
        "BLOCK",
        "Browser-side script injection is blocked."
    ),

    (
        "PATH_TRAVERSAL",
        "BLOCK",
        "Path traversal is blocked."
    ),

    (
        "RAG_POISONING",
        "BLOCK",
        "RAG poisoning is blocked."
    ),

    (
        "MEMORY_POISONING",
        "BLOCK",
        "Memory poisoning is blocked."
    ),

    (
        "UNAUTHORIZED_ACTION",
        "BLOCK",
        "Unauthorized tool or action access is blocked."
    ),

    (
        "ATTACK_CHAIN",
        "REVIEW",
        "Connected suspicious activity requires review."
    )
]


def initialize_threat_policies(
    session: Session
):

    for threat, decision, reason in THREAT_DEFAULTS:

        row = (
            session.query(ThreatPolicy)
            .filter(
                ThreatPolicy.threat == threat
            )
            .first()
        )

        if row is None:

            session.add(
                ThreatPolicy(
                    threat=threat,
                    decision=decision,
                    enabled=1,
                    reason=reason
                )
            )

    session.commit()


def get_threat_policy(
    session: Session,
    threat: str
):

    initialize_threat_policies(
        session
    )

    return (
        session.query(ThreatPolicy)
        .filter(
            ThreatPolicy.threat == threat
        )
        .first()
    )


THREAT_MAP = {

    "PROMPT_INJECTION":
        "PROMPT_INJECTION",

    "PRIVATE_KEY":
        "SECRETS",

    "API_KEY":
        "SECRETS",

    "JWT":
        "SECRETS",

    "CREDENTIAL_PATTERN":
        "SECRETS",

    "SQL_INJECTION":
        "SQL_INJECTION",

    "COMMAND_INJECTION":
        "COMMAND_INJECTION",

    "ENCODED_PAYLOAD":
        "ENCODED_PAYLOAD",

    "HIDDEN_UNICODE":
        "HIDDEN_UNICODE",

    "XSS":
        "XSS",

    "PATH_TRAVERSAL":
        "PATH_TRAVERSAL",

    "RAG_POISONING":
        "RAG_POISONING",

    "INDIRECT_PROMPT_INJECTION":
        "RAG_POISONING",

    "UNTRUSTED_SOURCE":
        "RAG_POISONING",

    "MEMORY_POISONING":
        "MEMORY_POISONING",

    "UNTRUSTED_MEMORY":
        "MEMORY_POISONING",

    "UNAUTHORIZED_ACTION":
        "UNAUTHORIZED_ACTION",

    "ROLE_TOOL_NOT_AUTHORIZED":
        "UNAUTHORIZED_ACTION",

    "TOOL_NOT_AUTHORIZED":
        "UNAUTHORIZED_ACTION",

    "PERMISSION_NOT_FOUND":
        "UNAUTHORIZED_ACTION",

    "AGENT_IDENTITY_NOT_FOUND":
        "UNAUTHORIZED_ACTION",

    "AGENT_DISABLED":
        "UNAUTHORIZED_ACTION",

    "ATTACK_CHAIN":
        "ATTACK_CHAIN"
}


def apply_threat_policies(
    session: Session,
    risks
):

    initialize_threat_policies(
        session
    )

    matched = []

    final_policy = "ALLOW"

    priority = {
        "ALLOW": 0,
        "REVIEW": 1,
        "BLOCK": 2
    }

    for risk in risks:

        threat = THREAT_MAP.get(
            risk
        )

        if not threat:
            continue

        policy = get_threat_policy(
            session,
            threat
        )

        if policy is None:
            continue

        if not bool(policy.enabled):
            continue

        matched.append({
            "threat": threat,
            "risk": risk,
            "decision": policy.decision,
            "reason": policy.reason
        })

        if (
            priority[policy.decision]
            > priority[final_policy]
        ):
            final_policy = policy.decision

    return {
        "decision": final_policy,
        "matched": matched
    }


# ============================================================
# AGENT PERMISSIONS
# ============================================================

def initialize_agent_permissions(
    session: Session
):

    defaults = [

        {
            "agent_id": "agent-001",
            "tool": "product_search",
            "allowed": True,
            "reason": (
                "Agent is authorized to search products."
            )
        },

        {
            "agent_id": "agent-001",
            "tool": "knowledge_search",
            "allowed": True,
            "reason": (
                "Agent is authorized to search knowledge."
            )
        },

        {
            "agent_id": "agent-001",
            "tool": "search_products",
            "allowed": True,
            "reason": (
                "Agent is authorized to search products."
            )
        }
    ]

    for item in defaults:

        existing = (
            session.query(AgentPermission)
            .filter(
                AgentPermission.agent_id
                == item["agent_id"],
                AgentPermission.tool
                == item["tool"]
            )
            .first()
        )

        if existing is None:

            session.add(
                AgentPermission(
                    agent_id=item["agent_id"],
                    tool=item["tool"],
                    allowed=int(
                        item["allowed"]
                    ),
                    reason=item["reason"]
                )
            )

    session.commit()


def check_agent_permission(
    session: Session,
    agent_id: str,
    tool: str
):

    initialize_agent_permissions(
        session
    )

    permission = (
        session.query(AgentPermission)
        .filter(
            AgentPermission.agent_id
            == agent_id,
            AgentPermission.tool
            == tool
        )
        .first()
    )

    if permission is None:

        return {
            "allowed": False,
            "risk": "PERMISSION_NOT_FOUND",
            "reason": (
                "No explicit permission is configured."
            )
        }

    if not permission.allowed:

        return {
            "allowed": False,
            "risk": "TOOL_NOT_AUTHORIZED",
            "reason": (
                permission.reason
                or
                "Agent is not authorized "
                "to use this tool."
            )
        }

    return {
        "allowed": True,
        "risk": None,
        "reason": (
            permission.reason
            or
            "Agent is authorized "
            "to use this tool."
        )
    }


# ============================================================
# AGENT IDENTITY / RBAC
# ============================================================

ROLE_TOOL_PERMISSIONS = {

    "readonly": {
        "product_search",
        "search_products",
        "knowledge_search"
    },

    "analyst": {
        "product_search",
        "search_products",
        "knowledge_search",
        "data_search",
        "reporting_tool"
    },

    "operator": {
        "product_search",
        "search_products",
        "knowledge_search",
        "data_search",
        "reporting_tool",
        "payment_tool",
        "send_email"
    },

    "admin": {
        "*"
    }
}


def initialize_agent_identities(
    session: Session
):

    defaults = [

        {
            "agent_id": "agent-001",
            "role": "operator",
            "enabled": True,
            "description": (
                "Default operational AI agent."
            )
        }
    ]

    for item in defaults:

        existing = (
            session.query(AgentIdentity)
            .filter(
                AgentIdentity.agent_id
                == item["agent_id"]
            )
            .first()
        )

        if existing is None:

            session.add(
                AgentIdentity(
                    agent_id=item["agent_id"],
                    role=item["role"],
                    enabled=int(
                        item["enabled"]
                    ),
                    description=item["description"]
                )
            )

    session.commit()


def get_agent_identity(
    session: Session,
    agent_id: str
):

    initialize_agent_identities(
        session
    )

    identity = (
        session.query(AgentIdentity)
        .filter(
            AgentIdentity.agent_id
            == agent_id
        )
        .first()
    )

    if identity is None:

        return {
            "exists": False,
            "enabled": False,
            "role": None,
            "risk": "AGENT_IDENTITY_NOT_FOUND",
            "reason": (
                "No identity has been registered."
            )
        }

    if not identity.enabled:

        return {
            "exists": True,
            "enabled": False,
            "role": identity.role,
            "risk": "AGENT_DISABLED",
            "reason": (
                "This agent identity is disabled."
            )
        }

    return {
        "exists": True,
        "enabled": True,
        "role": identity.role,
        "risk": None,
        "reason": (
            identity.description
            or
            "Agent identity is active."
        )
    }


def check_role_permission(
    session: Session,
    agent_id: str,
    tool: str
):

    identity = get_agent_identity(
        session,
        agent_id
    )

    if not identity["exists"]:

        return {
            "allowed": False,
            "risk": identity["risk"],
            "role": None,
            "reason": identity["reason"]
        }

    if not identity["enabled"]:

        return {
            "allowed": False,
            "risk": identity["risk"],
            "role": identity["role"],
            "reason": identity["reason"]
        }

    role = identity["role"]

    allowed_tools = ROLE_TOOL_PERMISSIONS.get(
        role,
        set()
    )

    if "*" in allowed_tools:

        return {
            "allowed": True,
            "risk": None,
            "role": role,
            "reason": (
                "Admin role allows registered tools."
            )
        }

    if tool in allowed_tools:

        return {
            "allowed": True,
            "risk": None,
            "role": role,
            "reason": (
                f"Role '{role}' permits "
                f"tool '{tool}'."
            )
        }

    return {
        "allowed": False,
        "risk": "ROLE_TOOL_NOT_AUTHORIZED",
        "role": role,
        "reason": (
            f"Role '{role}' is not authorized "
            f"to use tool '{tool}'."
        )
    }


# ============================================================
# PROTECTED ACTIONS
# ============================================================

PROTECTED = {
    "transfer_money",
    "delete_account",
    "delete_user",
    "checkout",
    "send_email"
}


# ============================================================
# SECURITY PATTERNS
# ============================================================

PATTERNS = [

    (
        "PROMPT_INJECTION",
        70,
        re.compile(
            r"(?i)("
            r"ignore\s+(all|any|previous|prior)\s+instructions|"
            r"disregard\s+(all|any|previous|prior)\s+instructions|"
            r"forget\s+(all|any|previous|prior)\s+instructions|"
            r"reveal\s+(the\s+)?(system|developer)\s+prompt|"
            r"system\s+prompt|"
            r"developer\s+message|"
            r"jailbreak|"
            r"bypass\s+(security|guardrails|policies)|"
            r"disable\s+(security|guardrails|policies)"
            r")"
        )
    ),

    (
        "SQL_INJECTION",
        70,
        re.compile(
            r"(?i)("
            r"union\s+select|"
            r"\bor\s+1\s*=\s*1\b|"
            r"drop\s+table|"
            r"insert\s+into|"
            r"delete\s+from|"
            r"select\s+.*\s+from"
            r")"
        )
    ),

    (
        "COMMAND_INJECTION",
        70,
        re.compile(
            r"(?i)("
            r";\s*(curl|wget|bash|sh|powershell|cmd)\b|"
            r"\|\s*(bash|sh)\b|"
            r"\b(rm\s+-rf|chmod\s+777|nc\s+-e)\b"
            r")"
        )
    ),

    (
        "XSS",
        70,
        re.compile(
            r"(?i)("
            r"<script\b|"
            r"javascript:\s*|"
            r"onerror\s*=|"
            r"onload\s*="
            r")"
        )
    ),

    (
        "PATH_TRAVERSAL",
        50,
        re.compile(
            r"(?i)("
            r"\.\./|"
            r"\.\.\\|"
            r"%2e%2e%2f|"
            r"%2e%2e%5c"
            r")"
        )
    ),

    (
        "PRIVATE_KEY",
        90,
        re.compile(
            r"-----BEGIN "
            r"(?:RSA |EC |OPENSSH )?"
            r"PRIVATE KEY-----"
        )
    ),

    (
        "API_KEY",
        80,
        re.compile(
            r"(?i)\b(?:"
            r"sk-[A-Za-z0-9]{20,}|"
            r"AKIA[0-9A-Z]{16}|"
            r"ghp_[A-Za-z0-9]{30,}|"
            r"AIza[A-Za-z0-9_-]{30,}"
            r")\b"
        )
    ),

    (
        "JWT",
        80,
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]{8,}\b"
        )
    ),

    (
        "CREDENTIAL_PATTERN",
        75,
        re.compile(
            r"(?i)"
            r"(password|passwd|secret|token)"
            r"\s*[:=]\s*['\"]?[^\s'\"]{6,}"
        )
    )
]


ZERO_WIDTH = re.compile(
    r"[\u200b-\u200f"
    r"\u202a-\u202e"
    r"\u2060"
    r"\u2066-\u206f"
    r"\ufeff]"
)


# ============================================================
# CONTENT DECODING
# ============================================================

def decode_candidates(
    text: str
):

    candidates = []

    compact = re.sub(
        r"\s+",
        "",
        text
    )

    if (
        len(compact) >= 12
        and re.fullmatch(
            r"[A-Za-z0-9+/=]+",
            compact
        )
        and len(compact) % 4 == 0
    ):

        try:

            decoded = base64.b64decode(
                compact,
                validate=True
            ).decode(
                "utf-8",
                "ignore"
            )

            if decoded:

                printable_ratio = (
                    sum(
                        c.isprintable()
                        or c.isspace()
                        for c in decoded
                    )
                    / len(decoded)
                )

                if printable_ratio > 0.85:

                    candidates.append(
                        (
                            "BASE64_OBFUSCATION",
                            decoded
                        )
                    )

        except (
            ValueError,
            binascii.Error
        ):
            pass

    if re.search(
        r"(?i)%[0-9a-f]{2}",
        text
    ):

        decoded = urllib.parse.unquote(
            text
        )

        if decoded != text:

            candidates.append(
                (
                    "URL_ENCODING",
                    decoded
                )
            )

    if "&" in text and ";" in text:

        decoded = html.unescape(
            text
        )

        if decoded != text:

            candidates.append(
                (
                    "HTML_ENTITY_ENCODING",
                    decoded
                )
            )

    return candidates


def normalize_content(
    text: str
):

    normalized = ZERO_WIDTH.sub(
        "",
        text
    )

    normalized = html.unescape(
        normalized
    )

    normalized = urllib.parse.unquote(
        normalized
    )

    return normalized


# ============================================================
# CONTENT INSPECTION
# ============================================================

def inspect_content(
    text: str,
    session: Session
):

    policy = policy_value(
        session
    )

    original = text

    hidden_matches = ZERO_WIDTH.findall(
        text
    )

    normalized = normalize_content(
        text
    )

    risks = []

    score = 0

    evidence = []

    if hidden_matches:

        risks.append(
            "HIDDEN_UNICODE"
        )

        score += 20

        evidence.append({
            "risk": "HIDDEN_UNICODE",
            "source": "unicode_normalization",
            "count": len(hidden_matches)
        })

    for risk_name, risk_score, pattern in PATTERNS:

        if pattern.search(normalized):

            if (
                risk_name == "PROMPT_INJECTION"
                and not policy.block_prompt_injection
            ):
                continue

            if (
                risk_name in {
                    "API_KEY",
                    "JWT",
                    "PRIVATE_KEY",
                    "CREDENTIAL_PATTERN"
                }
                and not policy.block_secrets
            ):
                continue

            if risk_name not in risks:

                risks.append(
                    risk_name
                )

                score += risk_score

                evidence.append({
                    "risk": risk_name,
                    "source": "direct_content"
                })

    decoded_payloads = []

    for encoding_name, decoded in decode_candidates(text):

        decoded_normalized = normalize_content(
            decoded
        )

        decoded_payloads.append({
            "encoding": encoding_name,
            "content": decoded
        })

        if "ENCODED_PAYLOAD" not in risks:

            risks.append(
                "ENCODED_PAYLOAD"
            )

            score += 15

            evidence.append({
                "risk": "ENCODED_PAYLOAD",
                "source": encoding_name
            })

        for risk_name, risk_score, pattern in PATTERNS:

            if pattern.search(
                decoded_normalized
            ):

                if (
                    risk_name == "PROMPT_INJECTION"
                    and not policy.block_prompt_injection
                ):
                    continue

                if (
                    risk_name in {
                        "API_KEY",
                        "JWT",
                        "PRIVATE_KEY",
                        "CREDENTIAL_PATTERN"
                    }
                    and not policy.block_secrets
                ):
                    continue

                if risk_name not in risks:

                    risks.append(
                        risk_name
                    )

                    score += risk_score

                evidence.append({
                    "risk": risk_name,
                    "source": encoding_name
                })

    score = min(
        score,
        100
    )

    policy_result = apply_threat_policies(
        session,
        risks
    )

    if policy_result["decision"] == "BLOCK":

        decision = "BLOCK"

    elif policy_result["decision"] == "REVIEW":

        decision = "REVIEW"

    elif score >= 70:

        decision = "BLOCK"

    elif score >= 40:

        decision = "REVIEW"

    elif score > 0:

        decision = "REVIEW"

    else:

        decision = "ALLOW"

    if decision == "BLOCK":

        level = "CRITICAL"

    elif decision == "REVIEW":

        level = "MEDIUM"

    else:

        level = "LOW"

    evidence_hash = hashlib.sha256(
        json.dumps(
            evidence,
            sort_keys=True
        ).encode()
    ).hexdigest()

    content_hash = hashlib.sha256(
        original.encode(
            "utf-8",
            "ignore"
        )
    ).hexdigest()

    return {

        "decision": decision,

        "risk_score": score,

        "risk_level": level,

        "risks": list(
            dict.fromkeys(risks)
        ),

        "evidence": evidence,

        "content_hash": content_hash,

        "evidence_hash": evidence_hash,

        "normalized_content": normalized,

        "normalized_length": len(
            normalized
        ),

        "security_analysis": {

            "hidden_unicode_detected": bool(
                hidden_matches
            ),

            "hidden_unicode_count": len(
                hidden_matches
            ),

            "encoded_content_detected": bool(
                decoded_payloads
            ),

            "encoding_types": [
                x["encoding"]
                for x in decoded_payloads
            ],

            "normalization_applied": (
                normalized != original
            ),

            "decoded_payloads": decoded_payloads
        },

        "applied_policies": policy_result,

        "policy_enforced": True
    }


# ============================================================
# AUDIT
# ============================================================

def save_audit(
    session: Session,
    agent: str,
    tool: str,
    result: Dict[str, Any]
):

    audit = Audit(

        agent=agent,

        tool=tool,

        decision=result["decision"],

        score=result.get(
            "risk_score",
            0
        ),

        level=result.get(
            "risk_level",
            "LOW"
        ),

        risks=json.dumps(
            result.get(
                "risks",
                []
            )
        ),

        explanation=result.get(
            "explanation",
            ""
        ),

        evidence=json.dumps(
            result.get(
                "evidence",
                {}
            )
        )
    )

    session.add(audit)

    session.commit()

    session.refresh(audit)

    return audit.id


# ============================================================
# ACTION CONTROL
# ============================================================

def inspect_action_control(
    action: ActionControlIn,
    session: Session,
    ignore_approval: bool = False
):

    action_name = action.action.strip().lower()

    tool_name = (
        action.tool.strip().lower()
        if action.tool
        else "unknown"
    )

    identity = get_agent_identity(
        session,
        action.agent_id
    )

    role_permission = check_role_permission(
        session,
        action.agent_id,
        tool_name
    )

    explicit_permission = (
        session.query(AgentPermission)
        .filter(
            AgentPermission.agent_id
            == action.agent_id,
            AgentPermission.tool
            == tool_name
        )
        .first()
    )

    action_policy = get_action_policy(
        session,
        action_name
    )

    risks = []

    score = 0

    if not identity["exists"]:

        risks.append(
            "AGENT_IDENTITY_NOT_FOUND"
        )

        score += 70

    elif not identity["enabled"]:

        risks.append(
            "AGENT_DISABLED"
        )

        score += 80

    if not role_permission["allowed"]:

        risks.append(
            role_permission["risk"]
        )

        score += 50

    if (
        explicit_permission is not None
        and not explicit_permission.allowed
    ):

        risks.append(
            "TOOL_NOT_AUTHORIZED"
        )

        score += 50

    if action_policy is not None:

        if not bool(
            action_policy.enabled
        ):

            risks.append(
                "ACTION_DISABLED"
            )

            score += 70

        if (
            action_policy.require_approval
            and not ignore_approval
            and not action.user_approved
        ):

            risks.append(
                "USER_APPROVAL_REQUIRED"
            )

            score += 30

    if tool_name == "unknown":

        risks.append(
            "UNKNOWN_TOOL"
        )

        score += 20

    if action_name in PROTECTED:

        risks.append(
            "HIGH_IMPACT_ACTION"
        )

        score += 20

    # --------------------------------------------------------
    # TRANSFER LIMIT
    # --------------------------------------------------------

    transfer_amount = None

    if action_name == "transfer_money":

        candidates = [
            action.target
        ]

        if action.target:
            try:
                transfer_amount = float(
                    action.target
                )
            except Exception:
                transfer_amount = None

        if transfer_amount is None:
            risks.append(
                "INVALID_TRANSFER_AMOUNT"
            )
            score += 60

        else:

            policy = policy_value(
                session
            )

            if transfer_amount <= 0:

                risks.append(
                    "INVALID_TRANSFER_AMOUNT"
                )

                score += 60

            elif transfer_amount > policy.max_transfer:

                risks.append(
                    "TRANSFER_LIMIT_EXCEEDED"
                )

                score += 60

    score = min(
        score,
        100
    )

    policy_result = apply_threat_policies(
        session,
        risks
    )

    base_decision = "ALLOW"

    if action_policy is not None:

        base_decision = (
            action_policy.decision
        )

    # --------------------------------------------------------
    # DECISION
    # --------------------------------------------------------

    if not identity["exists"]:

        decision = "BLOCK"

    elif not identity["enabled"]:

        decision = "BLOCK"

    elif not role_permission["allowed"]:

        decision = "BLOCK"

    elif (
        explicit_permission is not None
        and not explicit_permission.allowed
    ):

        decision = "BLOCK"

    elif "TRANSFER_LIMIT_EXCEEDED" in risks:

        decision = "BLOCK"

    elif "INVALID_TRANSFER_AMOUNT" in risks:

        decision = "BLOCK"

    elif base_decision == "BLOCK":

        decision = "BLOCK"

    elif policy_result["decision"] == "BLOCK":

        decision = "BLOCK"

    elif (
        base_decision == "REVIEW"
        or
        policy_result["decision"] == "REVIEW"
    ):

        if (
            ignore_approval
            or action.user_approved
        ):

            decision = "ALLOW"

        else:

            decision = "REVIEW"

    elif score >= 70:

        decision = "BLOCK"

    elif score >= 40:

        decision = "REVIEW"

    else:

        decision = "ALLOW"

    if decision == "BLOCK":

        level = "CRITICAL"

    elif decision == "REVIEW":

        level = "MEDIUM"

    else:

        level = "LOW"

    explanation_parts = [

        identity["reason"],

        role_permission["reason"]
    ]

    if explicit_permission is not None:

        explanation_parts.append(
            explicit_permission.reason
            or
            "Explicit tool permission checked."
        )

    if action_policy is not None:

        explanation_parts.append(
            "Action policy: "
            + action_policy.decision
            + "."
        )

        if action_policy.reason:

            explanation_parts.append(
                action_policy.reason
            )

    if transfer_amount is not None:

        policy = policy_value(
            session
        )

        explanation_parts.append(
            f"Transfer amount: "
            f"{transfer_amount:g}. "
            f"Maximum allowed: "
            f"{policy.max_transfer}."
        )

    if policy_result["matched"]:

        explanation_parts.append(
            "Threat policies applied: "
            + ", ".join(
                x["threat"]
                for x in policy_result["matched"]
            )
            + "."
        )

    if action.user_approved:

        explanation_parts.append(
            "User approval was provided."
        )

    if risks:

        explanation_parts.append(
            "Detected risks: "
            + ", ".join(
                dict.fromkeys(risks)
            )
            + "."
        )

    result = {

        "decision": decision,

        "risk_score": score,

        "risk_level": level,

        "risks": list(
            dict.fromkeys(risks)
        ),

        "explanation": " ".join(
            explanation_parts
        ),

        "agent_id": action.agent_id,

        "action": action_name,

        "tool": tool_name,

        "target": action.target,

        "reason": action.reason,

        "user_approved": action.user_approved,

        "identity": {

            "agent_id": action.agent_id,

            "role": identity["role"],

            "enabled": identity["enabled"]
        },

        "role_permission": {

            "allowed":
                role_permission["allowed"],

            "role":
                role_permission["role"]
        },

        "permission": {

            "exists":
                explicit_permission is not None,

            "allowed": (
                bool(
                    explicit_permission.allowed
                )
                if explicit_permission
                else None
            )
        },

        "policy": (

            {

                "action":
                    action_policy.action,

                "decision":
                    action_policy.decision,

                "require_approval":
                    bool(
                        action_policy.require_approval
                    ),

                "enabled":
                    bool(
                        action_policy.enabled
                    ),

                "reason":
                    action_policy.reason
            }

            if action_policy

            else None
        ),

        "threat_policy":
            policy_result,

        "action_allowed":
            decision == "ALLOW",

        "policy_enforced":
            True
    }

    return result


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(

    title="Pygenic Arc Guardrail Engine",

    version="3.0.0",

    description=(
        "Security and reliability runtime "
        "for AI agents."
    )
)


app.add_middleware(

    CORSMiddleware,

    allow_origins=[
        origin.strip()
        for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
        if origin.strip()
    ],

    allow_credentials=False,

    allow_methods=["*"],

    allow_headers=["*"]
)


# ============================================================
# AUTH ROUTES
# ============================================================

@app.post("/api/auth/register")
def register(
    data: RegisterIn,
    session: Session = Depends(db)
):

    username = data.username.strip()

    if not re.fullmatch(
        r"[A-Za-z0-9_.-]{3,120}",
        username
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid username."
        )

    phone = data.phone_number.strip()

    if not re.fullmatch(
        r"\+[1-9]\d{7,14}",
        phone
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "Phone number must use "
                "international format, "
                "e.g. +919876543210."
            )
        )

    existing = (
        session.query(ArcUser)
        .filter(
            ArcUser.username == username
        )
        .first()
    )

    if existing:

        raise HTTPException(
            status_code=409,
            detail="Username already exists."
        )

    user = ArcUser(

        username=username,

        password_hash=hash_password(
            data.password
        ),

        phone_number=phone,

        enabled=1
    )

    session.add(user)

    session.commit()

    session.refresh(user)

    return {

        "status": "success",

        "message": (
            "Account created successfully. "
            "You can now log in."
        ),

        "user": {

            "id": user.id,

            "username": user.username,

            "phone":
                mask_phone(
                    user.phone_number
                )
        }
    }


@app.post("/api/auth/login")
def login(
    data: LoginIn,
    session: Session = Depends(db)
):

    username = data.username.strip()

    user = (
        session.query(ArcUser)
        .filter(
            ArcUser.username == username
        )
        .first()
    )

    if user is None:

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password."
        )

    if not user.enabled:

        raise HTTPException(
            status_code=401,
            detail="User account is disabled."
        )

    if not verify_password(
        data.password,
        user.password_hash
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password."
        )

    token = create_session(
        session,
        user.id
    )

    masked_phone = mask_phone(
        user.phone_number
    )

    return {

        "status": "success",

        # Frontend compatibility.
        "token": token,

        # Standard naming.
        "access_token": token,

        "token_type": "bearer",

        "id": user.id,

        "username": user.username,

        "phone_number":
            user.phone_number,

        "user": {

            "id": user.id,

            "username": user.username,

            "phone": masked_phone,

            "phone_number":
                user.phone_number
        }
    }


@app.get("/api/auth/me")
def me(
    authorization: Optional[str] = Header(
        default=None
    ),
    session: Session = Depends(db)
):

    user = get_current_user(
        authorization,
        session
    )

    masked_phone = mask_phone(
        user.phone_number
    )

    return {

        "authenticated": True,

        "id": user.id,

        "username": user.username,

        "phone_number":
            user.phone_number,

        "phone":
            masked_phone,

        "user": {

            "id": user.id,

            "username": user.username,

            "phone": masked_phone,

            "phone_number":
                user.phone_number
        }
    }


@app.post("/api/auth/logout")
def logout(
    authorization: Optional[str] = Header(
        default=None
    ),
    session: Session = Depends(db)
):

    if (
        authorization
        and authorization.startswith("Bearer ")
    ):

        token = authorization[7:].strip()

        if token:

            row = (
                session.query(UserSession)
                .filter(
                    UserSession.token_hash
                    == hash_token(token)
                )
                .first()
            )

            if row:

                row.revoked = 1

                session.commit()

    return {

        "status": "success",

        "message":
            "Logged out successfully."
    }


# ============================================================
# OTP APPROVAL
# ============================================================

@app.post("/api/approval/request")
def request_approval(
    data: ApprovalRequestIn,
    authorization: Optional[str] = Header(
        default=None
    ),
    session: Session = Depends(db)
):

    user = get_current_user(
        authorization,
        session
    )

    action = ActionControlIn(

        agent_id=data.agent_id,

        action=data.action,

        tool=data.tool,

        target=data.target,

        reason=data.reason,

        user_approved=False
    )

    result = inspect_action_control(
        action,
        session
    )

    if result["decision"] == "BLOCK":

        save_audit(
            session,
            data.agent_id,
            data.tool,
            result
        )

        raise HTTPException(

            status_code=403,

            detail={

                "message": (
                    "Action is blocked by "
                    "security policy. "
                    "OTP cannot override BLOCK."
                ),

                "decision": "BLOCK",

                "risks":
                    result["risks"],

                "policy":
                    result.get(
                        "threat_policy"
                    )
            }
        )

    if result["decision"] == "ALLOW":

        raise HTTPException(
            status_code=400,
            detail=(
                "Action does not require approval."
            )
        )

    now = datetime.now(
        timezone.utc
    )

    approval = ApprovalRequest(

        user_id=user.id,

        agent_id=data.agent_id,

        action=data.action.strip().lower(),

        tool=data.tool.strip().lower(),

        risk_score=result["risk_score"],

        status="PENDING",

        expires_at=(
            now
            + timedelta(
                minutes=OTP_MINUTES
            )
        )
    )

    session.add(approval)

    session.commit()

    session.refresh(approval)

    otp = f"{secrets.randbelow(1000000):06d}"

    otp_row = OTPCode(

        approval_id=approval.id,

        otp_hash=hash_otp(
            otp
        ),

        attempts=0,

        expires_at=(
            now
            + timedelta(
                minutes=OTP_MINUTES
            )
        ),

        verified=0
    )

    session.add(otp_row)

    session.commit()

    message = (
        "Pygenic Arc approval code: "
        f"{otp}. "
        f"Action: {data.action}. "
        f"Valid for {OTP_MINUTES} minutes. "
        "Do not share this code."
    )

    send_sms(
        user.phone_number,
        message
    )

    return {

        "status": "OTP_SENT",

        "approval_id":
            approval.id,

        "phone":
            mask_phone(
                user.phone_number
            ),

        "expires_in_seconds":
            OTP_MINUTES * 60,

        "decision":
            "REVIEW"
    }


@app.post("/api/approval/verify")
def verify_approval(
    data: OTPVerifyIn,
    authorization: Optional[str] = Header(
        default=None
    ),
    session: Session = Depends(db)
):

    user = get_current_user(
        authorization,
        session
    )

    approval = (
        session.query(ApprovalRequest)
        .filter(
            ApprovalRequest.id
            == data.approval_id,

            ApprovalRequest.user_id
            == user.id
        )
        .first()
    )

    if approval is None:

        raise HTTPException(
            status_code=404,
            detail="Approval request not found."
        )

    if approval.status != "PENDING":

        raise HTTPException(
            status_code=400,
            detail=(
                "Approval is no longer pending."
            )
        )

    now = datetime.now(
        timezone.utc
    )

    expires = approval.expires_at

    if expires.tzinfo is None:

        expires = expires.replace(
            tzinfo=timezone.utc
        )

    if expires <= now:

        approval.status = "EXPIRED"

        session.commit()

        raise HTTPException(
            status_code=400,
            detail="Approval request expired."
        )

    otp_row = (
        session.query(OTPCode)
        .filter(
            OTPCode.approval_id
            == approval.id,

            OTPCode.verified == 0
        )
        .order_by(
            OTPCode.id.desc()
        )
        .first()
    )

    if otp_row is None:

        raise HTTPException(
            status_code=400,
            detail="No active OTP found."
        )

    if otp_row.attempts >= 3:

        approval.status = "FAILED"

        session.commit()

        raise HTTPException(
            status_code=429,
            detail="Maximum OTP attempts exceeded."
        )

    otp_expires = otp_row.expires_at

    if otp_expires.tzinfo is None:

        otp_expires = otp_expires.replace(
            tzinfo=timezone.utc
        )

    if otp_expires <= now:

        approval.status = "EXPIRED"

        session.commit()

        raise HTTPException(
            status_code=400,
            detail="OTP expired."
        )

    if not hmac.compare_digest(
        otp_row.otp_hash,
        hash_otp(data.otp)
    ):

        otp_row.attempts += 1

        session.commit()

        raise HTTPException(
            status_code=401,
            detail="Invalid OTP."
        )

    action = ActionControlIn(

        agent_id=approval.agent_id,

        action=approval.action,

        tool=approval.tool,

        user_approved=True
    )

    result = inspect_action_control(
        action,
        session,
        ignore_approval=True
    )

    if result["decision"] == "BLOCK":

        approval.status = "BLOCKED"

        session.commit()

        raise HTTPException(
            status_code=403,
            detail=(
                "Policy changed or action became unsafe. "
                "Execution remains blocked."
            )
        )

    otp_row.verified = 1

    approval.status = "APPROVED"

    session.commit()

    return {

        "status": "APPROVED",

        "approval_id":
            approval.id,

        "decision":
            "ALLOW",

        "message": (
            "OTP verified. "
            "Action may proceed "
            "through the execution gate."
        )
    }


# ============================================================
# ACTION EXECUTION
# ============================================================

@app.post("/api/action/execute")
def execute_action(
    data: ActionExecuteIn,
    authorization: Optional[str] = Header(
        default=None
    ),
    session: Session = Depends(db)
):

    user = get_current_user(
        authorization,
        session
    )

    action = ActionControlIn(

        agent_id=data.agent_id,

        action=data.action,

        tool=data.tool,

        target=data.target,

        reason=data.reason,

        user_approved=False
    )

    result = inspect_action_control(
        action,
        session
    )

    # --------------------------------------------------------
    # BLOCK
    # --------------------------------------------------------

    if result["decision"] == "BLOCK":

        audit_id = save_audit(
            session,
            data.agent_id,
            data.tool,
            result
        )

        return {

            "status": "BLOCKED",

            "executed": False,

            "decision": "BLOCK",

            "audit_id": audit_id,

            "message": (
                "Execution prevented "
                "by Pygenic Arc."
            ),

            "result": result
        }

    # --------------------------------------------------------
    # REVIEW / OTP
    # --------------------------------------------------------

    if result["decision"] == "REVIEW":

        if not data.approval_id:

            return {

                "status": "OTP_REQUIRED",

                "executed": False,

                "decision": "REVIEW",

                "message": (
                    "User approval is required "
                    "before execution."
                ),

                "result": result
            }

        approval = (
            session.query(ApprovalRequest)
            .filter(

                ApprovalRequest.id
                == data.approval_id,

                ApprovalRequest.user_id
                == user.id,

                ApprovalRequest.status
                == "APPROVED"
            )
            .first()
        )

        if approval is None:

            return {

                "status": "OTP_REQUIRED",

                "executed": False,

                "decision": "REVIEW",

                "message": (
                    "A verified OTP approval "
                    "is required."
                )
            }

        # Final security re-check.
        verified_action = ActionControlIn(

            agent_id=data.agent_id,

            action=data.action,

            tool=data.tool,

            target=data.target,

            reason=data.reason,

            user_approved=True
        )

        final_result = inspect_action_control(

            verified_action,

            session,

            ignore_approval=True
        )

        if final_result["decision"] != "ALLOW":

            return {

                "status": "BLOCKED",

                "executed": False,

                "decision":
                    final_result["decision"],

                "message": (
                    "Final security re-check "
                    "did not permit execution."
                ),

                "result": final_result
            }

    else:

        final_result = result

    # --------------------------------------------------------
    # SIMULATED EXECUTION
    # --------------------------------------------------------

    execution_result = {

        "status": "EXECUTED",

        "executed": True,

        "decision": "ALLOW",

        "message": (
            "Action passed Pygenic Arc policy "
            "and was allowed to execute."
        ),

        "execution": {

            "agent_id":
                data.agent_id,

            "action":
                data.action,

            "tool":
                data.tool,

            "target":
                data.target,

            "user":
                user.username,

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat()
        },

        "security":
            final_result
    }

    audit_id = save_audit(
        session,
        data.agent_id,
        data.tool,
        execution_result
    )

    execution_result["audit_id"] = audit_id

    return execution_result


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
def health():

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable"
        ) from exc

    return {

        "status": "ok",

        "service":
            "Pygenic Arc Guardrail Engine",

        "version": "3.0.0"
    }


@app.get("/api/config")
def frontend_config():

    return {
        "api_key": API_KEY
    }


# ============================================================
# CONTENT
# ============================================================

@app.post(
    "/api/analyze-content",
    dependencies=[Depends(auth)]
)
def analyze_content(
    content: ContentIn,
    session: Session = Depends(db)
):

    result = inspect_content(
        content.content,
        session
    )

    result["agent_id"] = content.agent_id

    result["action"] = content.action

    result["explanation"] = (
        "Content inspected for prompt injection, "
        "secrets, SQL injection, command injection, "
        "XSS, path traversal, hidden Unicode "
        "and encoded payloads."
    )

    audit_id = save_audit(
        session,
        content.agent_id,
        content.action or "content",
        result
    )

    result["audit_id"] = audit_id

    return result


@app.post(
    "/api/analyze",
    dependencies=[Depends(auth)]
)
def analyze(
    content: ContentIn,
    session: Session = Depends(db)
):

    result = inspect_content(
        content.content,
        session
    )

    result["agent_id"] = content.agent_id

    result["action"] = content.action

    result["explanation"] = (
        "Pygenic Arc analyzed the supplied content."
    )

    audit_id = save_audit(
        session,
        content.agent_id,
        content.action or "analyze",
        result
    )

    result["audit_id"] = audit_id

    return result


# ============================================================
# RAG
# ============================================================

@app.post(
    "/api/rag/inspect",
    dependencies=[Depends(auth)]
)
def rag_inspect(
    rag: RAGIn,
    session: Session = Depends(db)
):

    result = inspect_content(
        rag.content,
        session
    )

    risks = list(
        result["risks"]
    )

    score = result["risk_score"]

    if not rag.trusted_source:

        risks.append(
            "UNTRUSTED_SOURCE"
        )

        score += 15

    indirect_patterns = [

        r"ignore\s+(all|any|previous|prior)\s+instructions",

        r"you\s+are\s+now\s+an?\s+administrator",

        r"reveal\s+(the\s+)?system\s+prompt",

        r"send\s+(me\s+)?credentials",

        r"send\s+(me\s+)?secrets",

        r"disable\s+(security|guardrails|policies)"
    ]

    indirect_detected = any(

        re.search(
            pattern,
            rag.content,
            re.IGNORECASE
        )

        for pattern in indirect_patterns
    )

    if indirect_detected:

        risks.append(
            "INDIRECT_PROMPT_INJECTION"
        )

        score += 35

    score = min(
        score,
        100
    )

    policy_result = apply_threat_policies(
        session,
        risks
    )

    if policy_result["decision"] == "BLOCK":

        decision = "BLOCK"

    elif policy_result["decision"] == "REVIEW":

        decision = "REVIEW"

    elif score >= 70:

        decision = "BLOCK"

    elif score >= 40:

        decision = "REVIEW"

    else:

        decision = "ALLOW"

    level = (
        "CRITICAL"
        if decision == "BLOCK"
        else
        "MEDIUM"
        if decision == "REVIEW"
        else
        "LOW"
    )

    output = {

        "decision": decision,

        "risk_score": score,

        "risk_level": level,

        "risks": list(
            dict.fromkeys(risks)
        ),

        "explanation": (
            "RAG content inspected for "
            "indirect prompt injection, "
            "untrusted sources and malicious content."
        ),

        "evidence": {

            "document_id":
                rag.document_id,

            "source":
                rag.source,

            "trusted_source":
                rag.trusted_source,

            "content_hash":
                result["content_hash"],

            "evidence_hash":
                result["evidence_hash"]
        },

        "applied_policies":
            policy_result,

        "context_allowed":
            decision == "ALLOW"
    }

    audit_id = save_audit(
        session,
        rag.agent_id,
        "rag_inspect",
        output
    )

    output["audit_id"] = audit_id

    return output


# ============================================================
# MEMORY
# ============================================================

@app.post(
    "/api/memory/inspect",
    dependencies=[Depends(auth)]
)
def memory_inspect(
    memory: MemoryIn,
    session: Session = Depends(db)
):

    result = inspect_content(
        memory.content,
        session
    )

    risks = list(
        result["risks"]
    )

    score = result["risk_score"]

    if not memory.trusted:

        risks.append(
            "UNTRUSTED_MEMORY"
        )

        score += 15

    poisoning_patterns = [

        r"always\s+ignore\s+future\s+instructions",

        r"remember\s+that\s+you\s+must",

        r"store\s+this\s+as\s+a\s+permanent\s+instruction",

        r"do\s+not\s+tell\s+the\s+user",

        r"override\s+(security|safety|policy)\s+rules",

        r"ignore\s+(security|safety|policy)\s+rules"
    ]

    poisoning_detected = any(

        re.search(
            pattern,
            memory.content,
            re.IGNORECASE
        )

        for pattern in poisoning_patterns
    )

    if poisoning_detected:

        risks.append(
            "MEMORY_POISONING"
        )

        score += 35

    score = min(
        score,
        100
    )

    policy_result = apply_threat_policies(
        session,
        risks
    )

    if policy_result["decision"] == "BLOCK":

        decision = "BLOCK"

    elif policy_result["decision"] == "REVIEW":

        decision = "REVIEW"

    elif score >= 70:

        decision = "BLOCK"

    elif score >= 40:

        decision = "REVIEW"

    else:

        decision = "ALLOW"

    level = (
        "CRITICAL"
        if decision == "BLOCK"
        else
        "MEDIUM"
        if decision == "REVIEW"
        else
        "LOW"
    )

    output = {

        "decision": decision,

        "risk_score": score,

        "risk_level": level,

        "risks": list(
            dict.fromkeys(risks)
        ),

        "explanation": (
            "Memory inspected for poisoning, "
            "prompt injection, secrets and "
            "malicious content."
        ),

        "evidence": {

            "memory_id":
                memory.memory_id,

            "memory_type":
                memory.memory_type,

            "source":
                memory.source,

            "trusted":
                memory.trusted,

            "memory_hash":
                result["content_hash"]
        },

        "applied_policies":
            policy_result,

        "memory_allowed":
            decision == "ALLOW"
    }

    audit_id = save_audit(
        session,
        memory.agent_id,
        "memory_inspect",
        output
    )

    output["audit_id"] = audit_id

    return output


# ============================================================
# ACTION CONTROL
# ============================================================

@app.post(
    "/api/action-control",
    dependencies=[Depends(auth)]
)
def action_control(
    action: ActionControlIn,
    session: Session = Depends(db)
):

    result = inspect_action_control(
        action,
        session
    )

    audit_id = save_audit(
        session,
        action.agent_id,
        action.tool,
        result
    )

    result["audit_id"] = audit_id

    return result


# ============================================================
# THREAT POLICIES
# ============================================================

@app.get(
    "/api/threat-policies",
    dependencies=[Depends(auth)]
)
def list_threat_policies(
    session: Session = Depends(db)
):

    initialize_threat_policies(
        session
    )

    rows = (
        session.query(
            ThreatPolicy
        )
        .order_by(
            ThreatPolicy.id
        )
        .all()
    )

    return {

        "policies": [

            {

                "id": row.id,

                "threat": row.threat,

                "decision":
                    row.decision,

                "enabled":
                    bool(row.enabled),

                "reason":
                    row.reason
            }

            for row in rows
        ]
    }


@app.post(
    "/api/threat-policies",
    dependencies=[Depends(auth)]
)
def set_threat_policy(
    data: ThreatPolicyIn,
    session: Session = Depends(db)
):

    threat = (
        data.threat
        .strip()
        .upper()
    )

    row = (
        session.query(
            ThreatPolicy
        )
        .filter(
            ThreatPolicy.threat
            == threat
        )
        .first()
    )

    if row is None:

        row = ThreatPolicy(
            threat=threat
        )

        session.add(row)

    row.decision = data.decision

    row.enabled = int(
        data.enabled
    )

    row.reason = data.reason

    session.commit()

    session.refresh(row)

    return {

        "status": "success",

        "policy": {

            "id": row.id,

            "threat":
                row.threat,

            "decision":
                row.decision,

            "enabled":
                bool(row.enabled),

            "reason":
                row.reason
        }
    }


# ============================================================
# GLOBAL POLICY
# ============================================================

@app.get(
    "/api/policy",
    dependencies=[Depends(auth)]
)
def get_policy(
    session: Session = Depends(db)
):

    policy = policy_value(
        session
    )

    return {

        "id":
            policy.id,

        "max_transfer":
            policy.max_transfer,

        "block_prompt_injection":
            bool(
                policy.block_prompt_injection
            ),

        "block_secrets":
            bool(
                policy.block_secrets
            )
    }


@app.post(
    "/api/policy",
    dependencies=[Depends(auth)]
)
def update_policy(
    data: PolicyIn,
    session: Session = Depends(db)
):

    policy = policy_value(
        session
    )

    policy.max_transfer = (
        data.max_transfer
    )

    policy.block_prompt_injection = int(
        data.block_prompt_injection
    )

    policy.block_secrets = int(
        data.block_secrets
    )

    session.commit()

    return {

        "status": "success",

        "policy": {

            "max_transfer":
                policy.max_transfer,

            "block_prompt_injection":
                bool(
                    policy.block_prompt_injection
                ),

            "block_secrets":
                bool(
                    policy.block_secrets
                )
        }
    }


# ============================================================
# ACTION POLICIES
# ============================================================

@app.get(
    "/api/policies/actions",
    dependencies=[Depends(auth)]
)
def list_action_policies(
    session: Session = Depends(db)
):

    initialize_action_policies(
        session
    )

    rows = (
        session.query(
            ActionPolicy
        )
        .order_by(
            ActionPolicy.id
        )
        .all()
    )

    return {

        "policies": [

            {

                "id": row.id,

                "action":
                    row.action,

                "decision":
                    row.decision,

                "require_approval":
                    bool(
                        row.require_approval
                    ),

                "enabled":
                    bool(
                        row.enabled
                    ),

                "reason":
                    row.reason
            }

            for row in rows
        ]
    }


@app.post(
    "/api/policies/actions",
    dependencies=[Depends(auth)]
)
def set_action_policy(
    data: ActionPolicyIn,
    session: Session = Depends(db)
):

    action_name = (
        data.action
        .strip()
        .lower()
    )

    row = (
        session.query(
            ActionPolicy
        )
        .filter(
            ActionPolicy.action
            == action_name
        )
        .first()
    )

    if row is None:

        row = ActionPolicy(
            action=action_name
        )

        session.add(row)

    row.decision = data.decision

    row.require_approval = int(
        data.require_approval
    )

    row.enabled = int(
        data.enabled
    )

    row.reason = data.reason

    session.commit()

    session.refresh(row)

    return {

        "status": "success",

        "policy": {

            "id": row.id,

            "action":
                row.action,

            "decision":
                row.decision,

            "require_approval":
                bool(
                    row.require_approval
                ),

            "enabled":
                bool(
                    row.enabled
                ),

            "reason":
                row.reason
        }
    }


# ============================================================
# PERMISSIONS
# ============================================================

@app.get(
    "/api/permissions",
    dependencies=[Depends(auth)]
)
def list_permissions(
    session: Session = Depends(db)
):

    initialize_agent_permissions(
        session
    )

    rows = (
        session.query(
            AgentPermission
        )
        .order_by(
            AgentPermission.id
        )
        .all()
    )

    return {

        "permissions": [

            {

                "id":
                    row.id,

                "agent_id":
                    row.agent_id,

                "tool":
                    row.tool,

                "allowed":
                    bool(row.allowed),

                "reason":
                    row.reason
            }

            for row in rows
        ]
    }


@app.post(
    "/api/permissions",
    dependencies=[Depends(auth)]
)
def set_permission(
    data: AgentPermissionIn,
    session: Session = Depends(db)
):

    agent_id = data.agent_id.strip()

    tool = data.tool.strip().lower()

    row = (
        session.query(
            AgentPermission
        )
        .filter(
            AgentPermission.agent_id
            == agent_id,

            AgentPermission.tool
            == tool
        )
        .first()
    )

    if row is None:

        row = AgentPermission(

            agent_id=agent_id,

            tool=tool
        )

        session.add(row)

    row.allowed = int(
        data.allowed
    )

    row.reason = data.reason

    session.commit()

    session.refresh(row)

    return {

        "status": "success",

        "permission": {

            "id":
                row.id,

            "agent_id":
                row.agent_id,

            "tool":
                row.tool,

            "allowed":
                bool(row.allowed),

            "reason":
                row.reason
        }
    }


# ============================================================
# IDENTITY
# ============================================================

@app.get(
    "/api/identity/agents",
    dependencies=[Depends(auth)]
)
def list_agent_identities(
    session: Session = Depends(db)
):

    initialize_agent_identities(
        session
    )

    rows = (
        session.query(
            AgentIdentity
        )
        .order_by(
            AgentIdentity.id
        )
        .all()
    )

    return {

        "agents": [

            {

                "id":
                    row.id,

                "agent_id":
                    row.agent_id,

                "role":
                    row.role,

                "enabled":
                    bool(row.enabled),

                "description":
                    row.description
            }

            for row in rows
        ]
    }


@app.post(
    "/api/identity/agents",
    dependencies=[Depends(auth)]
)
def set_agent_identity(
    identity: AgentIdentityIn,
    session: Session = Depends(db)
):

    agent_id = identity.agent_id.strip()

    role = identity.role.strip().lower()

    row = (
        session.query(
            AgentIdentity
        )
        .filter(
            AgentIdentity.agent_id
            == agent_id
        )
        .first()
    )

    if row is None:

        row = AgentIdentity(
            agent_id=agent_id
        )

        session.add(row)

    row.role = role

    row.enabled = int(
        identity.enabled
    )

    row.description = (
        identity.description
    )

    session.commit()

    session.refresh(row)

    return {

        "status": "success",

        "agent": {

            "id":
                row.id,

            "agent_id":
                row.agent_id,

            "role":
                row.role,

            "enabled":
                bool(row.enabled),

            "description":
                row.description
        }
    }


# ============================================================
# DASHBOARD
# ============================================================

@app.get(
    "/api/dashboard",
    dependencies=[Depends(auth)]
)
def dashboard(
    session: Session = Depends(db)
):

    total = session.query(
        Audit
    ).count()

    blocked = (
        session.query(Audit)
        .filter(
            Audit.decision == "BLOCK"
        )
        .count()
    )

    review = (
        session.query(Audit)
        .filter(
            Audit.decision == "REVIEW"
        )
        .count()
    )

    allowed = (
        session.query(Audit)
        .filter(
            Audit.decision == "ALLOW"
        )
        .count()
    )

    recent = (
        session.query(Audit)
        .order_by(
            Audit.id.desc()
        )
        .limit(20)
        .all()
    )

    return {

        "summary": {

            "total":
                total,

            "blocked":
                blocked,

            "review":
                review,

            "allowed":
                allowed
        },

        "recent": [

            {

                "id":
                    row.id,

                "timestamp":
                    row.timestamp.isoformat(),

                "agent":
                    row.agent,

                "tool":
                    row.tool,

                "decision":
                    row.decision,

                "score":
                    row.score,

                "level":
                    row.level,

                "risks":
                    json.loads(
                        row.risks
                    ),

                "explanation":
                    row.explanation
            }

            for row in recent
        ]
    }


# ============================================================
# RESET
# ============================================================

@app.post(
    "/api/reset",
    dependencies=[Depends(auth)]
)
def reset(
    session: Session = Depends(db)
):

    session.query(
        Audit
    ).delete()

    session.commit()

    return {

        "status":
            "success",

        "message":
            "Audit data reset successfully."
    }


# ============================================================
# FRONTEND
# ============================================================

frontend_path = os.path.abspath(

    os.path.join(

        os.path.dirname(__file__),

        "..",

        "frontend"
    )
)


if os.path.isdir(
    frontend_path
):

    app.mount(

        "/",

        StaticFiles(
            directory=frontend_path,
            html=True
        ),

        name="frontend"
    )