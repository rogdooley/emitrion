"""Base class and config dataclass for payload templates."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class TemplateConfig:
    """Runtime parameters for a payload template.

    Fields that default to None are manifest-overridable: None means
    "preserve the manifest value."  The build pipeline backfills them
    from the manifest before any template sees them.
    """
    lhost: str = "127.0.0.1"
    lport: int = 4444
    command: str | None = None
    src_path: str | None = None
    dst_path: str | None = None
    url: str | None = None
    url_path: str | None = None
    alloc_size: int | None = None
    process_name: str | None = None
    service_name: str | None = None
    badchars: set[int] = field(default_factory=lambda: {0x00})


class PayloadTemplate(ABC):
    """Base class for all payload templates.

    Subclasses implement emit() to generate payload-specific assembly.
    The builder auto-derives API and variable requirements by probing
    emit() with a RecordingLayout - no manual declarations needed.

    Contract: emit() MUST use layout.slot(name).ebp_ref for all stack
    references. Hardcoded [ebp-0xNN] offsets are forbidden.
    """

    @abstractmethod
    def emit(self, layout, config: TemplateConfig) -> str:
        """Emit payload-specific assembly.

        Returns a string of assembly text with a comment header.
        All [ebp-0xNN] references must come from layout.slot(name).ebp_ref.
        """

    def probe_slots(self, config: TemplateConfig) -> list[str]:
        """Discover which slot names emit() references by running it
        against a RecordingLayout.  Returns names in first-access order.
        """
        from ..stack_alloc import RecordingLayout
        rec = RecordingLayout()
        self.emit(rec, config)
        seen: set[str] = set()
        ordered: list[str] = []
        for name in rec.accessed:
            if name not in seen:
                seen.add(name)
                ordered.append(name)
        return ordered

    def cheatsheet(self, config: TemplateConfig) -> list[tuple[str, str]]:
        """Return attacker-side operational commands as (description, command) pairs.

        Override in subclasses to provide template-specific setup instructions.
        Default returns an empty list.
        """
        return []
