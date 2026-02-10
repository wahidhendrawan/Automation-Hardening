import sys
from unittest.mock import patch, MagicMock
from cloud.main import main

def test_main_import_error(capsys):
    """Test that ImportError is handled when a module is missing."""
    with patch('sys.argv', ['main.py', 'azure']):
        # Explicitly mock ImportError for better determinism as suggested in code review
        with patch('cloud.main.importlib.import_module', side_effect=ImportError("No module named 'azure_harden'")):
            main()
            captured = capsys.readouterr()
            assert "[*] Starting hardening check for AZURE..." in captured.out
            assert "[!] Could not import module azure_harden. Make sure azure_harden.py exists." in captured.out

def test_main_missing_run_audit(capsys):
    """Test that the case where run_audit is missing from the module is handled."""
    mock_module = MagicMock(spec=[]) # Ensure it doesn't have run_audit

    with patch('sys.argv', ['main.py', 'aws']):
        with patch('cloud.main.importlib.import_module', return_value=mock_module):
            main()
            captured = capsys.readouterr()
            assert "[!] Module aws_harden does not have a run_audit function." in captured.out

def test_main_success(capsys):
    """Test the success path where the module is imported and run_audit is called."""
    mock_module = MagicMock()

    with patch('sys.argv', ['main.py', 'aws']):
        with patch('cloud.main.importlib.import_module', return_value=mock_module):
            main()
            mock_module.run_audit.assert_called_once()
            captured = capsys.readouterr()
            assert "[*] Starting hardening check for AWS..." in captured.out

def test_main_generic_exception(capsys):
    """Test that generic exceptions during import are handled."""
    with patch('sys.argv', ['main.py', 'aws']):
        with patch('cloud.main.importlib.import_module', side_effect=Exception("Unexpected error")):
            main()
            captured = capsys.readouterr()
            assert "[!] Error: Unexpected error" in captured.out
