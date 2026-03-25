"""Google Drive service implementation."""

import io
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

from ..auth.oauth_handler import get_oauth_handler
from ..utils.logger import setup_logger
from ..utils.error_handler import with_error_handling, ResourceNotFoundError
from ..utils.rate_limiter import rate_limited_call
from ..utils.cache import cached_call, cache_key

logger = setup_logger(__name__)


class DriveService:
    """Google Drive service wrapper."""

    def __init__(self):
        """Initialize Drive service."""
        self.oauth = get_oauth_handler()
        self._service = None

    @property
    def service(self):
        """Get or create Drive service instance."""
        if self._service is None:
            self._service = self.oauth.get_service('drive', 'v3')
        return self._service

    # パストラバーサル防止: 許可ディレクトリ（ダウンロード先）
    ALLOWED_DOWNLOAD_DIRS = [
        '/mnt/c/Users/okara/',
        '/home/okara/',
        '/tmp/',
    ]

    # パストラバーサル防止: アップロード禁止パス（機密情報）
    BLOCKED_UPLOAD_PATHS = [
        os.path.expanduser('~/.ssh/'),
        os.path.expanduser('~/.gnupg/'),
        os.path.expanduser('~/.config/credentials/'),
        '/etc/',
    ]
    BLOCKED_UPLOAD_FILENAMES = [
        '.env',
    ]

    def _validate_download_path(self, path: str) -> None:
        """ダウンロード先パスのバリデーション。

        許可ディレクトリ外へのダウンロードを拒否し、
        パストラバーサル攻撃（..を使った上位ディレクトリへの脱出）を防止する。

        Args:
            path: ダウンロード先のローカルパス

        Raises:
            ValueError: パスが不正な場合
        """
        # パストラバーサルの検出（.. を含むパスを拒否）
        if '..' in Path(path).parts:
            raise ValueError(
                f"パストラバーサルが検出されました: パスに '..' を含むことはできません: {path}"
            )

        # シンボリックリンクを解決して実際のパスを取得
        real_path = os.path.realpath(path)

        # 許可ディレクトリ内かチェック
        allowed = any(real_path.startswith(d) for d in self.ALLOWED_DOWNLOAD_DIRS)
        if not allowed:
            raise ValueError(
                f"ダウンロード先が許可されていません: {real_path}\n"
                f"許可ディレクトリ: {self.ALLOWED_DOWNLOAD_DIRS}"
            )

    def _validate_upload_path(self, path: str) -> None:
        """アップロード元パスのバリデーション。

        機密情報を含むディレクトリやファイルのアップロードを拒否し、
        パストラバーサル攻撃を防止する。

        Args:
            path: アップロード元のローカルパス

        Raises:
            ValueError: パスが不正な場合
        """
        # パストラバーサルの検出（.. を含むパスを拒否）
        if '..' in Path(path).parts:
            raise ValueError(
                f"パストラバーサルが検出されました: パスに '..' を含むことはできません: {path}"
            )

        # シンボリックリンクを解決して実際のパスを取得
        real_path = os.path.realpath(path)

        # ブラックリストディレクトリのチェック
        for blocked_dir in self.BLOCKED_UPLOAD_PATHS:
            if real_path.startswith(blocked_dir):
                raise ValueError(
                    f"機密ディレクトリからのアップロードは禁止されています: {real_path}"
                )

        # ブラックリストファイル名のチェック
        filename = os.path.basename(real_path)
        for blocked_name in self.BLOCKED_UPLOAD_FILENAMES:
            if filename == blocked_name:
                raise ValueError(
                    f"機密ファイルのアップロードは禁止されています: {filename}"
                )

    def _log_operation(self, operation: str, file_id: str = "", file_name: str = "", status: str = "success", details: str = ""):
        """Drive書き込み操作を専用ログファイルに記録"""
        log_dir = os.path.expanduser("~/.config/gw-mcp")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "drive-operations.log")

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = f"{timestamp} | {operation:8s} | file_id={file_id} | name={file_name} | status={status}"
        if details:
            entry += f" | {details}"
        entry += "\n"

        with open(log_path, "a") as f:
            f.write(entry)

    @with_error_handling
    async def search_files(
        self,
        query: Optional[str] = None,
        folder_id: Optional[str] = None,
        file_type: Optional[str] = None,
        max_results: int = 100
    ) -> List[Dict[str, Any]]:
        """Search for files in Drive.

        Args:
            query: Search query string
            folder_id: Limit search to specific folder
            file_type: Filter by MIME type
            max_results: Maximum number of results

        Returns:
            List of file metadata dictionaries
        """
        # Build query
        query_parts = []
        if query:
            safe_query = query.replace("'", "\\'")
            query_parts.append(f"name contains '{safe_query}'")
        if folder_id:
            query_parts.append(f"'{folder_id}' in parents")
        if file_type:
            query_parts.append(f"mimeType='{file_type}'")

        q = " and ".join(query_parts) if query_parts else None

        async def _search():
            results = self.service.files().list(
                q=q,
                pageSize=min(max_results, 1000),
                fields="files(id, name, mimeType, modifiedTime, size, parents)"
            ).execute()

            files = results.get('files', [])
            logger.info(f"Found {len(files)} files")
            return files

        cache_k = cache_key("search", query, folder_id, file_type, max_results)
        return await rate_limited_call("drive", cached_call, "drive", cache_k, _search)

    @with_error_handling
    async def read_file(
        self,
        file_id: str,
        mime_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Read file content from Drive.

        Args:
            file_id: File ID
            mime_type: Export MIME type for Google Docs files

        Returns:
            Dictionary with file metadata and content
        """
        async def _read():
            # Get file metadata
            file_meta = self.service.files().get(
                fileId=file_id,
                fields="id, name, mimeType, modifiedTime, size"
            ).execute()

            # Get file content
            if mime_type or 'google-apps' in file_meta['mimeType']:
                # Export Google Workspace file
                export_mime = mime_type or 'text/plain'
                content = self.service.files().export(
                    fileId=file_id,
                    mimeType=export_mime
                ).execute()
            else:
                # Download binary file
                request = self.service.files().get_media(fileId=file_id)
                fh = io.BytesIO()
                downloader = MediaIoBaseDownload(fh, request)

                done = False
                while not done:
                    status, done = downloader.next_chunk()

                content = fh.getvalue()

            logger.info(f"Read file: {file_meta['name']}")
            return {
                "metadata": file_meta,
                "content": content if isinstance(content, str) else content.decode('utf-8', errors='ignore')
            }

        cache_k = cache_key("read", file_id, mime_type)
        return await rate_limited_call("drive", cached_call, "drive", cache_k, _read)

    @with_error_handling
    async def create_file(
        self,
        name: str,
        content: str = "",
        mime_type: str = "text/plain",
        folder_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create new file in Drive.

        Args:
            name: File name
            content: File content
            mime_type: MIME type
            folder_id: Parent folder ID

        Returns:
            Created file metadata
        """
        async def _create():
            file_metadata = {'name': name}
            if folder_id:
                file_metadata['parents'] = [folder_id]

            media = MediaFileUpload(
                io.BytesIO(content.encode()),
                mimetype=mime_type,
                resumable=True
            )

            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id, name, mimeType, webViewLink'
            ).execute()

            logger.info(f"Created file: {file['name']} ({file['id']})")
            self._log_operation("CREATE", file['id'], file['name'])
            return file

        return await rate_limited_call("drive", _create)

    @with_error_handling
    async def update_file(
        self,
        file_id: str,
        content: Optional[str] = None,
        name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update existing file.

        Args:
            file_id: File ID
            content: New content (optional)
            name: New name (optional)

        Returns:
            Updated file metadata
        """
        async def _update():
            file_metadata = {}
            if name:
                file_metadata['name'] = name

            kwargs = {'fileId': file_id, 'fields': 'id, name, modifiedTime'}

            if file_metadata:
                kwargs['body'] = file_metadata

            if content:
                kwargs['media_body'] = MediaFileUpload(
                    io.BytesIO(content.encode()),
                    resumable=True
                )

            file = self.service.files().update(**kwargs).execute()
            logger.info(f"Updated file: {file_id}")
            self._log_operation("UPDATE", file_id, name or "")
            return file

        return await rate_limited_call("drive", _update)

    @with_error_handling
    async def delete_file(self, file_id: str) -> bool:
        """Delete file from Drive.

        Args:
            file_id: File ID

        Returns:
            True if deleted successfully
        """
        async def _delete():
            self.service.files().delete(fileId=file_id).execute()
            logger.info(f"Deleted file: {file_id}")
            self._log_operation("DELETE", file_id)
            return True

        return await rate_limited_call("drive", _delete)

    @with_error_handling
    async def upload_file(
        self,
        local_path: str,
        name: Optional[str] = None,
        folder_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Upload local file to Drive.

        Args:
            local_path: Local file path
            name: Name for uploaded file (defaults to filename)
            folder_id: Parent folder ID

        Returns:
            Uploaded file metadata
        """
        import mimetypes

        async def _upload():
            # パストラバーサル防止バリデーション
            self._validate_upload_path(local_path)

            file_name = name or os.path.basename(local_path)
            mime_type = mimetypes.guess_type(local_path)[0] or 'application/octet-stream'

            file_metadata = {'name': file_name}
            if folder_id:
                file_metadata['parents'] = [folder_id]

            media = MediaFileUpload(local_path, mimetype=mime_type, resumable=True)

            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id, name, mimeType, size, webViewLink'
            ).execute()

            logger.info(f"Uploaded file: {file['name']} ({file['id']})")
            self._log_operation("UPLOAD", file['id'], file['name'])
            return file

        return await rate_limited_call("drive", _upload)

    @with_error_handling
    async def download_file(
        self,
        file_id: str,
        local_path: str,
        mime_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Download file from Drive to local system.

        Args:
            file_id: File ID
            local_path: Local path to save file
            mime_type: Export MIME type for Google Docs files

        Returns:
            Dictionary with download info
        """
        async def _download():
            # パストラバーサル防止バリデーション
            self._validate_download_path(local_path)

            # Get file metadata
            file_meta = self.service.files().get(
                fileId=file_id,
                fields="id, name, mimeType, size"
            ).execute()

            # Download content
            if mime_type or 'google-apps' in file_meta['mimeType']:
                export_mime = mime_type or 'application/pdf'
                content = self.service.files().export(
                    fileId=file_id,
                    mimeType=export_mime
                ).execute()
            else:
                request = self.service.files().get_media(fileId=file_id)
                fh = io.BytesIO()
                downloader = MediaIoBaseDownload(fh, request)

                done = False
                while not done:
                    status, done = downloader.next_chunk()

                content = fh.getvalue()

            # Write to local file
            mode = 'w' if isinstance(content, str) else 'wb'
            with open(local_path, mode) as f:
                f.write(content)

            logger.info(f"Downloaded file to: {local_path}")
            return {
                "file_id": file_id,
                "name": file_meta['name'],
                "local_path": local_path,
                "size": len(content)
            }

        return await rate_limited_call("drive", _download)

    @with_error_handling
    async def list_shared_drives(self, max_results: int = 100) -> List[Dict[str, Any]]:
        """List shared drives (Team Drives).

        Args:
            max_results: Maximum number of results

        Returns:
            List of shared drive metadata
        """
        async def _list():
            results = self.service.drives().list(
                pageSize=min(max_results, 100),
                fields="drives(id, name)"
            ).execute()

            drives = results.get('drives', [])
            logger.info(f"Found {len(drives)} shared drives")
            return drives

        cache_k = cache_key("shared_drives", max_results)
        return await rate_limited_call("drive", cached_call, "drive", cache_k, _list)
