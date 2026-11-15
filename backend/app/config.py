from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SecureChange API"
    environment: str = "development"
    database_url: str = "postgresql+psycopg://securechange:securechange_dev@localhost:5432/securechange"
    frontend_origin: str = "http://localhost:5173"
    github_token: str | None = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()

