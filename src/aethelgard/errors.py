"""Stable local error taxonomy for diagnostics and support workflows."""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

ErrorSeverity = Literal["info", "warning", "error", "critical"]

EXIT_INTERNAL_ERROR: Final[int] = 1
EXIT_READINESS_FAILED: Final[int] = 2
EXIT_PREFLIGHT_BLOCKED: Final[int] = 3
EXIT_REVIEW_APPLY_ERROR: Final[int] = 4
EXIT_C_SCRM_ERROR: Final[int] = 5
EXIT_ML_ERROR: Final[int] = 6
EXIT_DELIVERY_PROFILE_ERROR: Final[int] = 7
EXIT_PILOT_PRODUCT_ERROR: Final[int] = 8
EXIT_PRIVACY_GUARD_BLOCKED: Final[int] = 9
EXIT_CONFIG_ERROR: Final[int] = 10
EXIT_DEPENDENCY_MISSING: Final[int] = 11


class ErrorCode(StrEnum):
    """Allowlisted machine-readable error codes for local support."""

    DOC_PARSE_FAILED = "DOC_PARSE_FAILED"
    UNSUPPORTED_FILE_TYPE = "UNSUPPORTED_FILE_TYPE"
    OCR_REQUIRED = "OCR_REQUIRED"
    DB_INIT_FAILED = "DB_INIT_FAILED"
    DB_SCHEMA_MISMATCH = "DB_SCHEMA_MISMATCH"
    QUESTIONNAIRE_PARSE_FAILED = "QUESTIONNAIRE_PARSE_FAILED"
    OUTPUT_WRITE_FAILED = "OUTPUT_WRITE_FAILED"
    READINESS_FAILED = "READINESS_FAILED"
    PRIVACY_GUARD_BLOCKED = "PRIVACY_GUARD_BLOCKED"
    CONFIG_ERROR = "CONFIG_ERROR"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    INTERNAL_ERROR = "INTERNAL_ERROR"


ERROR_EXIT_CODES: Final[dict[ErrorCode, int]] = {
    ErrorCode.DOC_PARSE_FAILED: EXIT_PILOT_PRODUCT_ERROR,
    ErrorCode.UNSUPPORTED_FILE_TYPE: EXIT_PILOT_PRODUCT_ERROR,
    ErrorCode.OCR_REQUIRED: EXIT_PILOT_PRODUCT_ERROR,
    ErrorCode.DB_INIT_FAILED: EXIT_PILOT_PRODUCT_ERROR,
    ErrorCode.DB_SCHEMA_MISMATCH: EXIT_PILOT_PRODUCT_ERROR,
    ErrorCode.QUESTIONNAIRE_PARSE_FAILED: EXIT_PILOT_PRODUCT_ERROR,
    ErrorCode.OUTPUT_WRITE_FAILED: EXIT_PILOT_PRODUCT_ERROR,
    ErrorCode.READINESS_FAILED: EXIT_READINESS_FAILED,
    ErrorCode.PRIVACY_GUARD_BLOCKED: EXIT_PRIVACY_GUARD_BLOCKED,
    ErrorCode.CONFIG_ERROR: EXIT_CONFIG_ERROR,
    ErrorCode.DEPENDENCY_MISSING: EXIT_DEPENDENCY_MISSING,
    ErrorCode.INTERNAL_ERROR: EXIT_INTERNAL_ERROR,
}

ALL_ERROR_CODES: Final[tuple[ErrorCode, ...]] = tuple(ErrorCode)


class AethelgardDiagnosticError(RuntimeError):
    """Error with local/private detail and a redacted shareable surface."""

    __slots__ = (
        "error_code",
        "phase",
        "remediation_hint",
        "safe_message",
        "safe_to_share",
        "severity",
        "technical_detail",
    )

    def __init__(
        self,
        *,
        error_code: ErrorCode,
        severity: ErrorSeverity,
        phase: str,
        safe_message: str,
        technical_detail: str = "",
        remediation_hint: str = "",
        safe_to_share: bool = False,
    ) -> None:
        super().__init__(safe_message)
        self.error_code = error_code
        self.severity = severity
        self.phase = phase
        self.safe_message = safe_message
        self.technical_detail = technical_detail
        self.remediation_hint = remediation_hint
        self.safe_to_share = safe_to_share

    def to_local_dict(self) -> dict[str, object]:
        """Serialize with private technical detail for local-only debug output."""
        return {
            "error_code": self.error_code.value,
            "severity": self.severity,
            "phase": self.phase,
            "safe_message": self.safe_message,
            "technical_detail": self.technical_detail,
            "remediation_hint": self.remediation_hint,
            "safe_to_share": self.safe_to_share,
        }

    def to_shareable_dict(self) -> dict[str, object]:
        """Serialize without private technical detail for redacted support output."""
        return {
            "error_code": self.error_code.value,
            "severity": self.severity,
            "phase": self.phase,
            "safe_message": self.safe_message,
            "remediation_hint": self.remediation_hint,
            "safe_to_share": self.safe_to_share,
        }


def exit_code_for_error(error_code: ErrorCode) -> int:
    """Return the stable CLI exit code for an error code."""
    return ERROR_EXIT_CODES.get(error_code, EXIT_INTERNAL_ERROR)
