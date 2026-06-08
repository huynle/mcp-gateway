import hashlib
from collections.abc import Generator

from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from mcp_gateway.models import Base, MCPServer, User
from mcp_gateway.settings import Settings, get_settings


class Database:
    def __init__(self, settings: Settings):
        connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
        self.engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)
        self.session_factory = sessionmaker(bind=self.engine, autoflush=False, autocommit=False, expire_on_commit=False)

    def init(self, settings: Settings) -> None:
        if settings.auto_create_schema:
            Base.metadata.create_all(self.engine)
        with self.session_factory() as db:
            try:
                seed_defaults(db, settings)
            except IntegrityError:
                db.rollback()


def seed_defaults(db: Session, settings: Settings) -> None:
    admin = db.scalar(select(User).where(User.external_id == "admin"))
    if admin is None:
        db.add(
            User(
                external_id="admin",
                display_name="Gateway Admin",
                is_admin=True,
                token_hash=hashlib.sha256(settings.admin_token.encode("utf-8")).hexdigest(),
            )
        )

    if not settings.seed_builtin_servers:
        db.commit()
        return

    defaults = [
        MCPServer(
            slug="jira",
            display_name="Jira",
            url="http://jira-mcp:8000/mcp",
            first_party=True,
            credential_header_map={
                "base_url": "X-Atlassian-Base-Url",
                "pat": "X-Atlassian-Token",
                "email": "X-Atlassian-Email",
            },
        ),
        MCPServer(
            slug="confluence",
            display_name="Confluence",
            url="http://confluence-mcp:8000/mcp",
            first_party=True,
            credential_header_map={
                "base_url": "X-Atlassian-Base-Url",
                "pat": "X-Atlassian-Token",
                "email": "X-Atlassian-Email",
            },
        ),
    ]
    existing = {server.slug for server in db.scalars(select(MCPServer)).all()}
    for server in defaults:
        if server.slug not in existing:
            db.add(server)
    db.commit()


_database: Database | None = None


def configure_database(settings: Settings) -> Database:
    global _database
    _database = Database(settings)
    return _database


def get_database() -> Database:
    global _database
    if _database is None:
        _database = Database(get_settings())
    return _database


def get_db() -> Generator[Session, None, None]:
    db = get_database().session_factory()
    try:
        yield db
    finally:
        db.close()
