"""
File handling (logging) helpers.
"""
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Optional

def make_logfile(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.replace(":", "_")
    path = (parsed.path or "").strip("/").replace("/", "_")
    slug = f"_{path}" if path else ""
    filename = f"seo_report_{host}{slug}.txt"
    return filename

@dataclass
class FileLogger:
    path: str
    fh: Optional[object] = None

    def __post_init__(self):
        self.fh = open(self.path, "a", encoding="utf-8")

    def log(self, msg: str = "") -> None:
        print(msg)
        if self.fh:
            self.fh.write(str(msg) + "\n")
            self.fh.flush()

    def close(self):
        if self.fh:
            try:
                self.fh.close()
            finally:
                self.fh = None

def pretty_header(logger: "FileLogger", title: str) -> None:
    logger.log("\n" + "=" * 80)
    logger.log(title)
    logger.log("=" * 80)
