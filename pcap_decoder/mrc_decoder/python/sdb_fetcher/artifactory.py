"""Resolve an SDB version into a directory of CAN/LIN databases (DBC/LDF).

SPA2 (project "p519") acquisition from Artifactory, walking:
  complete/p519 POM  ->  hotel-node POMs  ->  comsystem POMs + ZIPs
Only databases (.dbc/.ldf) referenced in each comsystem POM's <properties> are
extracted. Signal definitions and frame IDs live in these databases, not ARXML.

Security: the Artifactory bearer token is passed in by the caller (prompted at
runtime); it is never written to disk or logged.
"""

from __future__ import annotations

import logging
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

import requests
import yaml

logger = logging.getLogger(__name__)

BASE_URL = "https://ara-artifactory.volvocars.biz/artifactory/SDB-Hub-LTS"
COMPLETE_GROUP = "com/volvo/sdb/complete"
HOTELNODE_GROUP = "com/volvo/sdb/hotelnode"
COMSYSTEM_GROUP = "com/volvo/sdb/comsystem"

DB_EXTENSIONS = {".dbc", ".ldf"}
POM_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


class ArtifactoryError(RuntimeError):
    pass


@dataclass
class FetchResult:
    db_dir: Path
    manifest_path: Optional[Path] = None
    db_files: List[str] = field(default_factory=list)
    zips_downloaded: int = 0
    zips_reused: int = 0


class SdbFetcher:
    def __init__(
        self,
        token: str,
        cache_root: Optional[Path] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        # token kept in memory only; never logged.
        self._session = session or requests.Session()
        self._session.trust_env = False  # ignore ~/.netrc so our Bearer header wins
        self._session.headers["Authorization"] = f"Bearer {token}"
        self.cache_root = Path(
            cache_root or (Path.home() / ".cache" / "mrc_decoder" / "sdb")
        )

    # -- HTTP ---------------------------------------------------------------
    def _get(self, url: str, timeout: int = 120) -> requests.Response:
        try:
            resp = self._session.get(url, timeout=timeout)
        except requests.RequestException as exc:
            raise ArtifactoryError(f"GET {url} failed: {exc}") from exc
        if resp.status_code == 404:
            raise ArtifactoryError(f"Not found: {url}")
        if resp.status_code != 200:
            raise ArtifactoryError(f"GET {url} -> HTTP {resp.status_code}")
        return resp

    def list_versions(self, project: str = "p519") -> List[str]:
        server, repository = BASE_URL.rsplit("/", 1)
        url = f"{server}/api/storage/{repository}/{COMPLETE_GROUP}/{project}"
        listing = self._get(url, timeout=30).json()
        return sorted({
            child["uri"].strip("/")
            for child in listing.get("children", [])
            if child.get("folder") and child.get("uri")
        }, reverse=True)

    def _fetch_pom(self, group: str, artifact: str, version: str) -> ET.Element:
        url = f"{BASE_URL}/{group}/{artifact}/{version}/{artifact}-{version}.pom"
        return ET.fromstring(self._get(url).content)

    @staticmethod
    def _parse_dependencies(root: ET.Element) -> List[Tuple[str, str]]:
        deps: List[Tuple[str, str]] = []
        for dep in root.findall(".//m:dependencies/m:dependency", POM_NS):
            art = dep.find("m:artifactId", POM_NS)
            ver = dep.find("m:version", POM_NS)
            if art is not None and art.text and ver is not None and ver.text:
                deps.append((art.text, ver.text))
        return deps

    @staticmethod
    def _parse_pom_db_names(root: ET.Element) -> set:
        """Database filenames (.dbc/.ldf) referenced in a POM's <properties>."""
        names: set = set()
        props = root.find(".//m:properties", POM_NS)
        if props is None:
            return names
        for prop in props:
            val = (prop.text or "").strip()
            if val and val != "None" and Path(val).suffix.lower() in DB_EXTENSIONS:
                names.add(val)
        return names

    # -- Main resolution ----------------------------------------------------
    def fetch(self, version: str, project: str = "p519") -> FetchResult:
        db_dir = self.cache_root / f"{project}_{version}" / "db"
        db_dir.mkdir(parents=True, exist_ok=True)
        result = FetchResult(db_dir=db_dir)

        # 1. complete POM -> hotel nodes
        complete_root = self._fetch_pom(COMPLETE_GROUP, project, version)
        hotel_nodes = self._parse_dependencies(complete_root)
        logger.info(
            "Hotel nodes (%d): %s",
            len(hotel_nodes),
            ", ".join(a for a, _ in hotel_nodes),
        )

        # 2. hotel-node POMs -> unique comsystems (dedup across nodes)
        comsystems: Dict[str, str] = {}
        for hn_art, hn_ver in hotel_nodes:
            try:
                hn_root = self._fetch_pom(HOTELNODE_GROUP, hn_art, hn_ver)
            except ArtifactoryError as exc:
                logger.warning("Skipping hotel node %s: %s", hn_art, exc)
                continue
            for cs_art, cs_ver in self._parse_dependencies(hn_root):
                comsystems[cs_art] = cs_ver  # last version wins
        logger.info("Unique comsystems: %d", len(comsystems))

        # 3. comsystem POMs + ZIPs -> extract referenced DBC/LDF
        zip_cache: Dict[str, Path] = {}
        seen: set = set()
        for cs_art in sorted(comsystems):
            cs_ver = comsystems[cs_art]
            try:
                cs_root = self._fetch_pom(COMSYSTEM_GROUP, cs_art, cs_ver)
            except ArtifactoryError as exc:
                logger.warning("Skipping comsystem %s-%s: %s", cs_art, cs_ver, exc)
                continue
            pom_dbs = self._parse_pom_db_names(cs_root)
            zip_path = self._ensure_zip(cs_art, cs_ver, zip_cache, result)
            if zip_path is None:
                continue
            for name in self._extract_dbs(zip_path, pom_dbs, db_dir):
                if name not in seen:
                    seen.add(name)
                    result.db_files.append(name)

        result.db_files.sort()
        manifest = self.cache_root / f"{project}_{version}" / "manifest.yaml"
        manifest.write_text(yaml.safe_dump(result.db_files, default_flow_style=False))
        result.manifest_path = manifest
        logger.info("Extracted %d databases into %s", len(result.db_files), db_dir)
        return result

    def _ensure_zip(
        self,
        artifact: str,
        version: str,
        cache: Dict[str, Path],
        result: FetchResult,
    ) -> Optional[Path]:
        key = f"{artifact}-{version}"
        if key in cache:  # already downloaded this run
            result.zips_reused += 1
            return cache[key]

        local = self.cache_root / "zips" / f"{key}.zip"
        local.parent.mkdir(parents=True, exist_ok=True)
        if local.exists():  # cross-run cache hit
            cache[key] = local
            result.zips_reused += 1
            return local

        url = f"{BASE_URL}/{COMSYSTEM_GROUP}/{artifact}/{version}/{key}.zip"
        try:
            resp = self._get(url)
        except ArtifactoryError as exc:
            logger.warning("Skipping ZIP %s: %s", key, exc)
            return None
        local.write_bytes(resp.content)
        cache[key] = local
        result.zips_downloaded += 1
        return local

    @staticmethod
    def _extract_dbs(zip_path: Path, pom_dbs: set, db_dir: Path) -> List[str]:
        """Extract DBC/LDF (POM-referenced when listed, else all) into db_dir."""
        out: List[str] = []
        with zipfile.ZipFile(zip_path) as zf:
            zip_dbs = {
                n for n in zf.namelist() if Path(n).suffix.lower() in DB_EXTENSIONS
            }
            targets = (pom_dbs & zip_dbs) if pom_dbs else zip_dbs
            for member in sorted(targets):
                data = zf.read(member)
                dest = db_dir / Path(member).name  # flatten
                if not dest.exists() or dest.read_bytes() != data:
                    dest.write_bytes(data)
                out.append(Path(member).name)
        return out


def fetch_sdb(
    version: str,
    token: str,
    cache_root: Optional[os.PathLike] = None,
    project: str = "p519",
) -> FetchResult:
    """Resolve `version` into a directory of CAN/LIN databases (DBC/LDF)."""
    fetcher = SdbFetcher(
        token=token, cache_root=Path(cache_root) if cache_root else None
    )
    return fetcher.fetch(version, project=project)
