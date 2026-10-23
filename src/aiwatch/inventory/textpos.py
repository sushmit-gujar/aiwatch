"""Map AST (line, utf-8 byte column) positions to str offsets."""

from __future__ import annotations


class TextIndex:
    def __init__(self, text: str) -> None:
        self.text = text
        self.starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self.starts.append(i + 1)

    def offset(self, lineno: int, col_bytes: int) -> int:
        start = self.starts[lineno - 1]
        end = self.starts[lineno] if lineno < len(self.starts) else len(self.text)
        line = self.text[start:end]
        prefix = line.encode("utf-8")[:col_bytes].decode("utf-8", errors="ignore")
        return start + len(prefix)
