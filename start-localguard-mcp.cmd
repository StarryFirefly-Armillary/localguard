@echo off
set "GRYPE_DB_CACHE_DIR=%~dp0.localguard\grype-db"
set "PYTHONIOENCODING=utf-8"
"%~dp0.localguard\app-env\Scripts\python.exe" -m localguard --config "%~dp0localguard.local.json" mcp
