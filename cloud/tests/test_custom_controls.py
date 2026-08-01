"""Tests for the custom controls module."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
import yaml

from cloud.core import Status
from cloud.custom_controls import (
    _run_check,
    load_custom_controls,
    run_custom_controls,
)


class TestRunCheck:
    """Test the _run_check function which executes control commands."""

    def test_simple_command_succeeds(self):
        """Should execute simple commands successfully."""
        rc, output = _run_check("echo hello")
        assert rc == 0
        assert "hello" in output

    def test_command_with_args(self):
        """Should handle commands with multiple arguments."""
        rc, output = _run_check("echo one two three")
        assert rc == 0
        assert "one" in output and "two" in output and "three" in output

    def test_command_nonzero_exit_code(self):
        """Should capture non-zero exit codes."""
        rc, output = _run_check("false")
        assert rc == 1

    def test_command_not_found(self):
        """Should return 127 for command not found."""
        rc, output = _run_check("nonexistent_command_xyz_12345")
        assert rc == 127
        assert "not found" in output.lower()

    def test_command_timeout(self):
        """Should timeout after 30 seconds."""
        rc, output = _run_check("sleep 60")
        assert rc == 124
        assert "timed out" in output.lower()

    def test_empty_command(self):
        """Should reject empty commands."""
        rc, output = _run_check("")
        assert rc == 1
        assert "empty" in output.lower()

    def test_shell_metacharacters_become_literal_args(self):
        """Shell metacharacters are passed as literal arguments (safe, not injected)."""
        # Pipe character becomes a literal argument to echo, not a shell pipe
        rc, output = _run_check("echo hello | cat")
        assert rc == 0
        # Output contains the literal '|' and 'cat' as echo arguments
        assert "|" in output and "cat" in output

    def test_command_injection_attempt_is_safe(self):
        """Injection attempts are safe: semicolons become literal arguments."""
        # The semicolon and subsequent tokens are arguments to echo, not shell commands
        rc, output = _run_check("echo test; rm -rf /")
        assert rc == 0
        # 'rm' is NOT executed; it's just printed by echo
        assert ";" in output and "rm" in output

    def test_shell_redirection_becomes_literal_arg(self):
        """Shell redirections become literal arguments (no file created)."""
        rc, output = _run_check("echo hello > /tmp/pagerwesi_test_xyz.txt")
        assert rc == 0
        # The '>' is a literal argument, not redirection
        assert ">" in output

    def test_stderr_captured_on_failure(self):
        """Should capture stderr when command fails."""
        rc, output = _run_check("ls /nonexistent/path/xyz")
        assert rc != 0
        assert len(output) > 0  # Should have error message


class TestLoadCustomControls:
    """Test loading custom controls from YAML files."""

    def test_valid_controls_file(self, tmp_path):
        """Should load valid custom controls file."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({
                "version": 1,
                "controls": [
                    {
                        "id": "CUSTOM-TEST-001",
                        "title": "Test Control",
                        "check": "echo pass",
                        "expect": 0,
                    }
                ],
            })
        )
        controls = load_custom_controls(controls_file)
        assert len(controls) == 1
        assert controls[0]["id"] == "CUSTOM-TEST-001"

    def test_rejects_missing_version(self, tmp_path):
        """Should reject controls file without version field."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({"controls": []})
        )
        with pytest.raises(ValueError, match="version"):
            load_custom_controls(controls_file)

    def test_rejects_wrong_version(self, tmp_path):
        """Should reject controls file with wrong version."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({"version": 2, "controls": []})
        )
        with pytest.raises(ValueError, match="version"):
            load_custom_controls(controls_file)

    def test_rejects_missing_controls_list(self, tmp_path):
        """Should reject when controls is not a list."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({"version": 1, "controls": {"key": "value"}})
        )
        with pytest.raises(ValueError, match="controls must be a list"):
            load_custom_controls(controls_file)

    def test_rejects_malformed_control(self, tmp_path):
        """Should reject control that is not a dict."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({"version": 1, "controls": ["string_not_dict"]})
        )
        with pytest.raises(ValueError, match="control must be a mapping"):
            load_custom_controls(controls_file)

    def test_rejects_missing_required_keys(self, tmp_path):
        """Should reject control missing required keys."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({
                "version": 1,
                "controls": [
                    {
                        "id": "CUSTOM-TEST-001",
                        "title": "Test Control",
                        # Missing "check"
                    }
                ],
            })
        )
        with pytest.raises(ValueError, match="missing keys"):
            load_custom_controls(controls_file)

    def test_rejects_invalid_control_id_format(self, tmp_path):
        """Should reject control with invalid ID format."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({
                "version": 1,
                "controls": [
                    {
                        "id": "INVALID-ID",  # Missing -NNN suffix
                        "title": "Test Control",
                        "check": "echo test",
                    }
                ],
            })
        )
        with pytest.raises(ValueError, match="must match CUSTOM-XXX-NNN"):
            load_custom_controls(controls_file)

    def test_multiple_controls(self, tmp_path):
        """Should load multiple controls."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({
                "version": 1,
                "controls": [
                    {
                        "id": "CUSTOM-TEST-001",
                        "title": "Control 1",
                        "check": "echo 1",
                    },
                    {
                        "id": "CUSTOM-TEST-002",
                        "title": "Control 2",
                        "check": "echo 2",
                    },
                ],
            })
        )
        controls = load_custom_controls(controls_file)
        assert len(controls) == 2


class TestRunCustomControls:
    """Test executing custom controls."""

    def test_runs_passing_control(self, tmp_path):
        """Should execute and mark passing control."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({
                "version": 1,
                "controls": [
                    {
                        "id": "CUSTOM-TEST-001",
                        "title": "Check echo",
                        "check": "echo pass",
                        "expect": 0,
                    }
                ],
            })
        )
        args = SimpleNamespace(control=[], mode="audit")
        findings = run_custom_controls(controls_file, args)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS
        assert findings[0].control_id == "CUSTOM-TEST-001"

    def test_runs_failing_control(self, tmp_path):
        """Should execute and mark failing control."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({
                "version": 1,
                "controls": [
                    {
                        "id": "CUSTOM-TEST-001",
                        "title": "Check false",
                        "check": "false",
                        "expect": 0,
                    }
                ],
            })
        )
        args = SimpleNamespace(control=[], mode="audit")
        findings = run_custom_controls(controls_file, args)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_filters_by_control_id(self, tmp_path):
        """Should only run controls matching filter."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({
                "version": 1,
                "controls": [
                    {
                        "id": "CUSTOM-TEST-001",
                        "title": "Control 1",
                        "check": "echo 1",
                    },
                    {
                        "id": "CUSTOM-TEST-002",
                        "title": "Control 2",
                        "check": "echo 2",
                    },
                ],
            })
        )
        args = SimpleNamespace(control=["CUSTOM-TEST-001"], mode="audit")
        findings = run_custom_controls(controls_file, args)
        assert len(findings) == 1
        assert findings[0].control_id == "CUSTOM-TEST-001"

    def test_handles_missing_expect_field(self, tmp_path):
        """Should default expect to 0 if missing."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({
                "version": 1,
                "controls": [
                    {
                        "id": "CUSTOM-TEST-001",
                        "title": "Check",
                        "check": "echo pass",
                        # No expect field
                    }
                ],
            })
        )
        args = SimpleNamespace(control=[], mode="audit")
        findings = run_custom_controls(controls_file, args)
        assert findings[0].status == Status.PASS  # echo passes with exit 0

    def test_handles_exception_in_execution(self, tmp_path):
        """Should catch execution errors and report them."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({
                "version": 1,
                "controls": [
                    {
                        "id": "CUSTOM-TEST-001",
                        "title": "Bad Command",
                        "check": "nonexistent_command_xyz",
                    }
                ],
            })
        )
        args = SimpleNamespace(control=[], mode="audit")
        findings = run_custom_controls(controls_file, args)
        assert len(findings) == 1
        # Command not found is a FAIL (exit 127), not an ERROR
        assert findings[0].status == Status.FAIL
        assert "not found" in findings[0].evidence.lower()

    def test_preserves_optional_fields(self, tmp_path):
        """Should preserve optional fields in findings."""
        controls_file = tmp_path / "controls.yaml"
        controls_file.write_text(
            yaml.dump({
                "version": 1,
                "controls": [
                    {
                        "id": "CUSTOM-TEST-001",
                        "title": "Test",
                        "check": "echo pass",
                        "severity": "critical",
                        "target": "os:linux",
                        "remediation": "Fix this now",
                    }
                ],
            })
        )
        args = SimpleNamespace(control=[], mode="audit")
        findings = run_custom_controls(controls_file, args)
        assert findings[0].severity.value == "critical"
        assert findings[0].resource == "os:linux"
        assert findings[0].remediation == "Fix this now"
