from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8000
    frontend_origin: str = "http://localhost:5173"
    max_upload_bytes: int = 2097152
    max_requests_per_scan: int = 100
    max_concurrency: int = 2
    request_timeout_seconds: int = 10
    max_response_bytes: int = 1048576
    follow_redirects: bool = False
    fetch_remote_references: bool = False
    allow_lab_exception: bool = False
    lab_port: int = 5000
    database_path: str = "./data/apishield.db"
    reports_dir: str = "./reports"


settings = Settings()
