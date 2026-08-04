# SPDX-License-Identifier: MIT
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Optional

import yaml

from pydantic import BaseModel, Field, TypeAdapter, ValidationError


# See https://google.github.io/oss-fuzz/getting-started/new-project-guide/#language
class TargetLanguage(Enum):
    C = "c"
    CPP = "c++"
    GO = "go"
    RUST = "rust"
    PYTHON = "python"
    JVM = "jvm"  # Java, Kotlin, Scala and other JVM-based languages
    SWIFT = "swift"
    JAVASCRIPT = "javascript"
    LUA = "lua"


# See https://google.github.io/oss-fuzz/getting-started/new-project-guide/#sanitizers
class TargetSanitizer(Enum):
    ASAN = "address"
    MSAN = "memory"
    UBSAN = "undefined"
    # Dropping this and defaulting to "address" breaks javascript builds:
    # oss-fuzz's `compile` rejects any sanitizer other than "none"/"coverage".
    NONE = "none"


# See https://google.github.io/oss-fuzz/getting-started/new-project-guide/#architectures
class TargetArch(Enum):
    X86_64 = "x86_64"
    I386 = "i386"


# See https://google.github.io/oss-fuzz/getting-started/new-project-guide/#fuzzing_engines-optional
class FuzzingEngine(Enum):
    LIBFUZZER = "libfuzzer"
    AFL = "afl"
    HONGGFUZZ = "honggfuzz"
    CENTIPEDE = "centipede"


class TargetConfig(BaseModel):
    """Configuration for an OSS-Fuzz target project.

    See https://google.github.io/oss-fuzz/getting-started/new-project-guide/
    """

    # Required fields
    language: TargetLanguage = Field(
        ...,
        description="Programming language the project is written in.",
    )

    main_repo: Optional[str] = Field(
        default=None,
        description="Path to source code repository hosting the code, e.g. https://path/to/main/repo.git",
    )

    base_os_version: str = Field(
        default="legacy",
        description=(
            "OS the project's base-builder image is pinned to (e.g. "
            "'ubuntu-24-04'). Used to select a matching base-runner image so "
            "the runtime glibc/ABI matches the build toolchain. 'legacy' means "
            "unspecified and maps to the floating ':latest' runner tag."
        ),
    )

    # Optional fields with defaults based on OSS-Fuzz documentation
    sanitizers: list[TargetSanitizer] = Field(
        default=[TargetSanitizer.ASAN, TargetSanitizer.UBSAN],
        description="list of sanitizers to use. Defaults to address and undefined.",
    )

    architectures: list[TargetArch] = Field(
        default=[TargetArch.X86_64],
        description="list of architectures to fuzz on. Defaults to x86_64.",
    )

    fuzzing_engines: list[FuzzingEngine] = Field(
        default=[
            FuzzingEngine.LIBFUZZER,
            FuzzingEngine.AFL,
            FuzzingEngine.HONGGFUZZ,
            FuzzingEngine.CENTIPEDE,
        ],
        description="list of fuzzing engines to use. Defaults to all supported engines.",
    )

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "TargetConfig":
        """Parse Target config from YAML string."""
        data = yaml.safe_load(yaml_content)
        return cls.from_dict(data)

    @classmethod
    def from_yaml_file(cls, filepath: Path) -> "TargetConfig":
        """Parse Target config from YAML file."""
        with open(filepath.resolve(), "r") as f:
            return cls.from_yaml(f.read())

    @classmethod
    def from_dict(cls, data: dict) -> "TargetConfig":
        """Parse Target config from dictionary."""
        return cls.model_validate(data)

    @classmethod
    def validated_fields(cls, data: dict) -> tuple[dict[str, Any], list[str]]:
        """Validate each declared field independently.

        Returns ``(values, warnings)``: only the fields that were present and
        valid, plus a message for each one dropped. Absent fields are omitted
        rather than reported. Lenient counterpart to ``from_dict`` -- use that
        when the whole document must be valid.

        Field-level type and ``Field()`` constraints are enforced; model-level
        ``field_validator``/``model_validator`` hooks are not, since each field is
        validated in isolation. Add any such hook to ``from_dict``'s path too.
        """
        values: dict[str, Any] = {}
        warnings: list[str] = []
        for name, field in cls.model_fields.items():
            if data.get(name) is None:
                continue
            try:
                values[name] = TypeAdapter(
                    Annotated[field.annotation, field]
                ).validate_python(data[name])
            except ValidationError as exc:
                warnings.append(
                    f"ignoring invalid '{name}' ({_first_error(exc)}); "
                    "falling back to the framework default"
                )
        return values, warnings


def _first_error(exc: ValidationError) -> str:
    """Summarize a ValidationError as its first underlying message."""
    errors = exc.errors()
    if not errors:
        return str(exc)
    return str(errors[0].get("msg", exc))
