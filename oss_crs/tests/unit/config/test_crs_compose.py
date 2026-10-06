# SPDX-License-Identifier: MIT
"""Unit tests for oss_crs.src.config.crs_compose module."""

import pytest
from pydantic import ValidationError
from oss_crs.src.config.crs_compose import (
    CRSSource,
    CRSComposeConfig,
    ResourceConfig,
    CRSEntry,
    LLMConfig,
    remove_keys,
)


class TestCRSSource:
    """Tests for CRSSource - verifies mutual exclusivity of source types."""

    def test_url_source_requires_ref(self):
        """URL-based source must include a ref."""
        # Valid
        source = CRSSource(url="https://github.com/org/repo.git", ref="main")
        assert source.url and source.ref

        # Invalid - missing ref
        with pytest.raises(ValidationError, match="'ref' is required"):
            CRSSource(url="https://github.com/org/repo.git")

    def test_local_path_is_standalone(self):
        """local_path cannot be combined with url/ref."""
        # Valid
        source = CRSSource(local_path="/path/to/crs")
        assert source.local_path

        # Invalid - combined with url
        with pytest.raises(ValidationError, match="cannot be combined"):
            CRSSource(
                local_path="/path", url="https://github.com/org/repo.git", ref="main"
            )

    def test_must_specify_source(self):
        """Must provide either url or local_path."""
        with pytest.raises(ValidationError, match="Either 'url' or 'local_path'"):
            CRSSource()


class TestResourceConfig:
    """Tests for ResourceConfig validation."""

    def test_valid_resource_config(self):
        """Standard resource configs should work."""
        config = ResourceConfig(cpuset="0-3", memory="16G")
        assert config.cpuset == "0-3"
        assert config.memory == "16G"

    def test_rejects_invalid_cpuset(self):
        """Invalid cpuset format should be rejected."""
        with pytest.raises(ValidationError, match="Invalid cpuset"):
            ResourceConfig(cpuset="invalid", memory="8G")

    def test_rejects_invalid_memory(self):
        """Invalid memory format should be rejected."""
        with pytest.raises(ValidationError, match="Invalid memory"):
            ResourceConfig(cpuset="0", memory="invalid")

    def test_llm_budget_must_be_positive(self):
        """llm_budget must be > 0 if specified."""
        # Valid
        config = ResourceConfig(cpuset="0", memory="8G", llm_budget=100)
        assert config.llm_budget == 100

        # Invalid
        with pytest.raises(ValidationError):
            ResourceConfig(cpuset="0", memory="8G", llm_budget=0)


class TestCRSEntry:
    """Tests for CRSEntry model."""

    def test_additional_env_defaults_to_empty(self):
        """additional_env should default to empty dict, even if None."""
        entry = CRSEntry(cpuset="0-3", memory="8G", additional_env=None)
        assert entry.additional_env == {}

    def test_additional_env_rejects_invalid_key(self):
        with pytest.raises(ValidationError, match="invalid env var key"):
            CRSEntry(
                cpuset="0-3",
                memory="8G",
                additional_env={"BAD-KEY": "value"},
            )


class TestLLMConfig:
    """Tests for LLMConfig mode selection and validation."""

    def test_accepts_internal_mode_with_config_path(self, tmp_path):
        litellm_file = tmp_path / "litellm.yaml"
        litellm_file.write_text("model_list: []\n")
        config = LLMConfig(
            litellm={
                "mode": "internal",
                "internal": {"config_path": str(litellm_file)},
            }
        )
        assert config.litellm.mode.value == "internal"

    def test_accepts_external_mode_with_env_sources(self):
        config = LLMConfig(
            litellm={
                "mode": "external",
                "external": {
                    "url_env": "LITELLM_URL",
                    "key_env": "LITELLM_API_KEY",
                },
            }
        )
        assert config.litellm.mode.value == "external"

    def test_rejects_external_without_oneof_sources(self):
        with pytest.raises(ValidationError, match="exactly one of 'url' or 'url_env'"):
            LLMConfig(
                litellm={
                    "mode": "external",
                    "external": {
                        "key_env": "LITELLM_API_KEY",
                    },
                }
            )

    def test_backward_compatible_old_litellm_config_shape(self, tmp_path):
        litellm_file = tmp_path / "litellm.yaml"
        litellm_file.write_text("model_list: []\n")
        data = {
            "run_env": "local",
            "docker_registry": "local",
            "oss_crs_infra": {"cpuset": "0-1", "memory": "8G"},
            "llm_config": {"litellm_config": str(litellm_file)},
            "dummy-crs": {
                "cpuset": "2-3",
                "memory": "8G",
                "source": {"local_path": "/tmp/dummy-crs"},
            },
        }
        config = CRSComposeConfig.from_dict(data)
        assert config.llm_config is not None
        assert config.llm_config.litellm.mode.value == "internal"

        with pytest.raises(ValidationError, match="exactly one of 'key' or 'key_env'"):
            LLMConfig(
                litellm={
                    "mode": "external",
                    "external": {
                        "url": "https://litellm.example.com",
                    },
                }
            )


class TestCRSComposeConfigEntryNames:
    """Tests for CRS entry name validation at config load time."""

    @staticmethod
    def _compose_data(crs_name: str) -> dict:
        return {
            "run_env": "local",
            "docker_registry": "local",
            "oss_crs_infra": {"cpuset": "0-1", "memory": "8G"},
            crs_name: {
                "cpuset": "2-3",
                "memory": "8G",
                "source": {"local_path": "/tmp/dummy-crs"},
            },
        }

    @pytest.mark.parametrize(
        "crs_name",
        [
            "crs-libfuzzer",
            "CRS-Name",
            "myLocalCRS",
            "42-directed",
            "atlantis-multilang-given_fuzzer",
            "a",
            "A",
            "a" * 128,
        ],
    )
    def test_valid_crs_entry_names_are_accepted(self, crs_name):
        config = CRSComposeConfig.from_dict(self._compose_data(crs_name))

        assert crs_name in config.crs_entries

    @pytest.mark.parametrize(
        "crs_name",
        [
            "../evil",
            "..",
            ".",
            "crs/name",
            r"crs\name",
            "crs.name",
            "crs name",
            "crs;inject",
            "_starts-with-underscore",
            "-starts-with-hyphen",
            "a" * 129,
        ],
    )
    def test_invalid_crs_entry_names_are_rejected(self, crs_name):
        with pytest.raises(ValidationError, match="CRS entry names must start"):
            CRSComposeConfig.from_dict(self._compose_data(crs_name))


class TestRelativePathResolution:
    """Relative paths in a compose file resolve against the file's directory."""

    COMPOSE_YAML = """\
run_env: local
docker_registry: local
oss_crs_infra:
  cpuset: "0-1"
  memory: 8G
my-crs:
  cpuset: "2-3"
  memory: 8G
  source:
    local_path: ../crs/my-crs
llm_config:
  litellm:
    mode: internal
    internal:
      config_path: ../config/litellm-config.yaml
"""

    @pytest.fixture
    def layout(self, tmp_path):
        compose_dir = tmp_path / "compose"
        compose_dir.mkdir()
        (tmp_path / "config").mkdir()
        litellm_file = tmp_path / "config" / "litellm-config.yaml"
        litellm_file.write_text("model_list: []\n")
        compose_file = compose_dir / "compose.yaml"
        compose_file.write_text(self.COMPOSE_YAML)
        return tmp_path, compose_file, litellm_file

    def test_from_yaml_file_resolves_against_compose_dir(self, layout, monkeypatch):
        root, compose_file, litellm_file = layout
        # Run from an unrelated directory to prove the CWD is not used.
        other = root / "elsewhere"
        other.mkdir()
        monkeypatch.chdir(other)

        config = CRSComposeConfig.from_yaml_file(compose_file)

        assert config.crs_entries["my-crs"].source.local_path == str(
            (root / "crs" / "my-crs").resolve()
        )
        assert config.llm_config.litellm.internal.config_path == str(
            litellm_file.resolve()
        )

    def test_legacy_litellm_config_key_resolves_against_compose_dir(
        self, layout, monkeypatch
    ):
        root, compose_file, litellm_file = layout
        compose_file.write_text(
            self.COMPOSE_YAML.split("llm_config:")[0]
            + "llm_config:\n  litellm_config: ../config/litellm-config.yaml\n"
        )
        monkeypatch.chdir(root)

        config = CRSComposeConfig.from_yaml_file(compose_file)

        assert config.llm_config.litellm.internal.config_path == str(
            litellm_file.resolve()
        )

    def test_absolute_paths_unchanged(self, tmp_path):
        litellm_file = tmp_path / "litellm.yaml"
        litellm_file.write_text("model_list: []\n")
        data = {
            "run_env": "local",
            "docker_registry": "local",
            "oss_crs_infra": {"cpuset": "0-1", "memory": "8G"},
            "llm_config": {
                "litellm": {
                    "mode": "internal",
                    "internal": {"config_path": str(litellm_file)},
                }
            },
            "my-crs": {
                "cpuset": "2-3",
                "memory": "8G",
                "source": {"local_path": "/tmp/dummy-crs"},
            },
        }
        config = CRSComposeConfig.from_dict(data, base_dir=tmp_path / "unrelated")

        assert config.crs_entries["my-crs"].source.local_path == "/tmp/dummy-crs"
        assert config.llm_config.litellm.internal.config_path == str(litellm_file)

    def test_from_dict_without_base_dir_uses_cwd(self, tmp_path, monkeypatch):
        (tmp_path / "litellm.yaml").write_text("model_list: []\n")
        monkeypatch.chdir(tmp_path)
        data = {
            "run_env": "local",
            "docker_registry": "local",
            "oss_crs_infra": {"cpuset": "0-1", "memory": "8G"},
            "llm_config": {"litellm_config": "litellm.yaml"},
            "my-crs": {
                "cpuset": "2-3",
                "memory": "8G",
                "source": {"local_path": "crs"},
            },
        }
        config = CRSComposeConfig.from_dict(data)

        assert config.crs_entries["my-crs"].source.local_path == str(
            (tmp_path / "crs").resolve()
        )
        assert config.llm_config.litellm.internal.config_path == str(
            (tmp_path / "litellm.yaml").resolve()
        )

    def test_missing_relative_config_path_reports_both_candidates(
        self, layout, monkeypatch
    ):
        root, compose_file, litellm_file = layout
        litellm_file.unlink()
        monkeypatch.chdir(root)

        with pytest.raises(ValidationError, match="is not an existing file") as exc:
            CRSComposeConfig.from_yaml_file(compose_file)
        # Compose-relative candidate, then CWD-relative candidate.
        assert str(root / "config" / "litellm-config.yaml") in str(exc.value)
        assert str(root.parent / "config" / "litellm-config.yaml") in str(exc.value)

    def test_falls_back_to_cwd_relative_paths(self, tmp_path, monkeypatch):
        """Repo-root-style paths keep working when run from that root."""
        example_dir = tmp_path / "example" / "foo"
        example_dir.mkdir(parents=True)
        litellm_file = example_dir / "litellm-config.yaml"
        litellm_file.write_text("model_list: []\n")
        crs_dir = tmp_path / "crs" / "my-crs"
        (crs_dir / "oss-crs").mkdir(parents=True)
        (crs_dir / "oss-crs" / "crs.yaml").write_text("name: my-crs\n")
        compose_file = example_dir / "compose.yaml"
        compose_file.write_text(
            self.COMPOSE_YAML.replace("../crs/my-crs", "./crs/my-crs").replace(
                "../config/litellm-config.yaml",
                "./example/foo/litellm-config.yaml",
            )
        )
        monkeypatch.chdir(tmp_path)

        config = CRSComposeConfig.from_yaml_file(compose_file)

        assert config.crs_entries["my-crs"].source.local_path == str(crs_dir.resolve())
        assert config.llm_config.litellm.internal.config_path == str(
            litellm_file.resolve()
        )

    def test_compose_relative_wins_over_cwd_relative(self, tmp_path, monkeypatch):
        compose_dir = tmp_path / "compose"
        compose_dir.mkdir()
        (compose_dir / "litellm-config.yaml").write_text("model_list: []\n")
        cwd = tmp_path / "cwd"
        cwd.mkdir()
        (cwd / "litellm-config.yaml").write_text("model_list: []\n")
        compose_file = compose_dir / "compose.yaml"
        compose_file.write_text(
            self.COMPOSE_YAML.replace(
                "../config/litellm-config.yaml", "./litellm-config.yaml"
            )
        )
        monkeypatch.chdir(cwd)

        config = CRSComposeConfig.from_yaml_file(compose_file)

        assert config.llm_config.litellm.internal.config_path == str(
            (compose_dir / "litellm-config.yaml").resolve()
        )

    def test_local_path_fallback_requires_crs_yaml(self, tmp_path, monkeypatch):
        """A bare directory in the CWD is not mistaken for the CRS."""
        compose_dir = tmp_path / "compose"
        compose_dir.mkdir()
        (tmp_path / "my-crs").mkdir()  # no oss-crs/crs.yaml
        compose_file = compose_dir / "compose.yaml"
        compose_file.write_text(
            self.COMPOSE_YAML.split("llm_config:")[0].replace("../crs/my-crs", "my-crs")
        )
        monkeypatch.chdir(tmp_path)

        config = CRSComposeConfig.from_yaml_file(compose_file)

        assert config.crs_entries["my-crs"].source.local_path == str(
            (compose_dir / "my-crs").resolve()
        )


class TestRemoveKeys:
    """Tests for remove_keys - verifies recursive key removal."""

    def test_removes_keys_recursively(self):
        """Should remove specified keys at all nesting levels."""
        data = {
            "keep": 1,
            "remove": 2,
            "nested": {
                "keep": 3,
                "remove": 4,
                "deeper": {"remove": 5},
            },
            "list": [{"keep": 6, "remove": 7}],
        }

        result = remove_keys(data, ["remove"])

        assert result == {
            "keep": 1,
            "nested": {
                "keep": 3,
                "deeper": {},
            },
            "list": [{"keep": 6}],
        }

    def test_preserves_structure_with_no_matching_keys(self):
        """Structure should be unchanged if no keys match."""
        data = {"a": {"b": {"c": 1}}}
        result = remove_keys(data, ["x", "y"])
        assert result == data
