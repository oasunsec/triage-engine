import os

__all__ = ["__version__", "adopt_legacy_environment"]
__version__ = "3.0.0"


def adopt_legacy_environment() -> int:
    """Honor settings written for the old name (TRIAGE_*) unless CORROBORA_* is set."""
    adopted = 0
    for key, value in list(os.environ.items()):
        if key.startswith("TRIAGE_") and ("CORROBORA_" + key[7:]) not in os.environ:
            os.environ["CORROBORA_" + key[7:]] = value
            adopted += 1
    return adopted


adopt_legacy_environment()
