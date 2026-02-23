"""Tests for disassembler backend abstraction."""
from __future__ import annotations

from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from src.mcp.disassembler import (
    DisassemblerClient,
    GhidraDisassemblerClient,
    IDAMCPClient,
    BinaryNinjaMCPClient,
    get_disassembler,
    _BACKEND_MAP,
)
from src.mcp.ghidra import DecompiledFunction, FunctionEntry


# ---------------------------------------------------------------------------
# Abstract interface tests
# ---------------------------------------------------------------------------

def test_cannot_instantiate_abstract():
    with pytest.raises(TypeError):
        DisassemblerClient()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# Factory tests
# ---------------------------------------------------------------------------

class TestGetDisassembler:
    def test_default_is_ghidra(self):
        config = {"mcp": {}}
        client = get_disassembler(config)
        assert isinstance(client, GhidraDisassemblerClient)

    def test_explicit_ghidra(self):
        config = {"mcp": {"backend": "ghidra", "ghidra": {"host": "localhost", "port": 8765}}}
        client = get_disassembler(config)
        assert isinstance(client, GhidraDisassemblerClient)

    def test_ida_backend(self):
        config = {"mcp": {"backend": "ida", "ida": {"host": "localhost", "port": 8767}}}
        client = get_disassembler(config)
        assert isinstance(client, IDAMCPClient)

    def test_binja_backend(self):
        config = {"mcp": {"backend": "binja", "binja": {"host": "localhost", "port": 8768}}}
        client = get_disassembler(config)
        assert isinstance(client, BinaryNinjaMCPClient)

    def test_unknown_backend_raises(self):
        config = {"mcp": {"backend": "angr"}}
        with pytest.raises(ValueError, match="Unknown disassembler backend"):
            get_disassembler(config)

    def test_backend_name_property(self):
        config = {"mcp": {}}
        client = get_disassembler(config)
        assert client.backend_name == "Ghidra"

    def test_all_backends_in_map(self):
        assert "ghidra" in _BACKEND_MAP
        assert "ida" in _BACKEND_MAP
        assert "binja" in _BACKEND_MAP


# ---------------------------------------------------------------------------
# GhidraDisassemblerClient interface conformance
# ---------------------------------------------------------------------------

class TestGhidraDisassemblerClient:
    def setup_method(self):
        self.client = GhidraDisassemblerClient(host="localhost", port=8765)

    def test_backend_name(self):
        assert self.client.backend_name == "Ghidra"

    def test_decompile_delegates(self):
        mock_fn = DecompiledFunction(
            address="0x401000", name="sub_401000", pseudocode="int fn() { return 0; }"
        )
        with patch.object(self.client._ghidra, "decompile", return_value=mock_fn):
            result = self.client.decompile("0x401000")
            assert result.address == "0x401000"
            assert result.name == "sub_401000"

    def test_list_functions_delegates(self):
        mock_funcs = [FunctionEntry(address="0x401000", name="main", size=100)]
        with patch.object(self.client._ghidra, "list_functions", return_value=mock_funcs):
            result = self.client.list_functions(limit=10)
            assert len(result) == 1
            assert result[0].address == "0x401000"

    def test_rename_function_delegates(self):
        with patch.object(self.client._ghidra, "rename_function", return_value=True):
            result = self.client.rename_function("0x401000", "my_func")
            assert result is True

    def test_set_comment_delegates(self):
        with patch.object(self.client._ghidra, "set_comment", return_value=True):
            result = self.client.set_comment("0x401000", "This is main")
            assert result is True

    def test_ping_delegates(self):
        with patch.object(self.client._ghidra, "ping", return_value=True):
            assert self.client.ping() is True

    def test_auto_apply_signatures_delegates(self):
        with patch.object(
            self.client._ghidra, "auto_apply_signatures", return_value={"matched": 42}
        ):
            result = self.client.auto_apply_signatures()
            assert result["matched"] == 42

    def test_decompile_all_delegates(self):
        mock_funcs = [
            DecompiledFunction(address="0x401000", name="fn1", pseudocode="void fn1();")
        ]
        with patch.object(self.client._ghidra, "decompile_all", return_value=mock_funcs):
            result = self.client.decompile_all(limit=10)
            assert len(result) == 1


# ---------------------------------------------------------------------------
# IDA stub tests
# ---------------------------------------------------------------------------

class TestIDAMCPClient:
    def setup_method(self):
        self.client = IDAMCPClient(host="localhost", port=8767)

    def test_backend_name(self):
        assert self.client.backend_name == "IDA Pro"

    def test_decompile_stub(self):
        with patch.object(
            self.client._client,
            "invoke_tool",
            return_value={"name": "my_func", "pseudocode": "void my_func() {}"},
        ):
            fn = self.client.decompile("0x401000")
            assert fn.address == "0x401000"
            assert fn.name == "my_func"

    def test_ping_stub(self):
        with patch.object(self.client._client, "ping", return_value=False):
            assert self.client.ping() is False


# ---------------------------------------------------------------------------
# Binary Ninja stub tests
# ---------------------------------------------------------------------------

class TestBinaryNinjaMCPClient:
    def setup_method(self):
        self.client = BinaryNinjaMCPClient(host="localhost", port=8768)

    def test_backend_name(self):
        assert self.client.backend_name == "Binary Ninja"

    def test_decompile_stub(self):
        with patch.object(
            self.client._client,
            "invoke_tool",
            return_value={"name": "binja_func", "hlil": "int binja_func() { return 0; }"},
        ):
            fn = self.client.decompile("0x401000")
            assert fn.address == "0x401000"
            assert fn.name == "binja_func"

    def test_ping_stub(self):
        with patch.object(self.client._client, "ping", return_value=False):
            assert self.client.ping() is False
