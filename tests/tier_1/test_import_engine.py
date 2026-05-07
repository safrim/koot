import pytest
import os
import json
from koot.plugins.import_engine.reader import DataReader
from koot.plugins.import_engine.translator import SchemaTranslator
from koot.plugins.import_engine.plugin import ImportEnginePlugin

class MockBus:
    def __init__(self):
        self.vaulted = []
    def dispatch(self, domain, action, **kwargs):
        self.vaulted.append(kwargs['payload'])
        return "OK"

def test_data_reader_csv():
    raw = "login,pass\nuser1,secret1"
    parsed = DataReader.parse(raw, "csv")
    assert len(parsed) == 1
    assert parsed[0]["login"] == "user1"

def test_schema_translator():
    source = {"login": {"user": "bob"}, "pword": "123"}
    mapping = {"username": "login.user", "password": "pword"}
    
    result = SchemaTranslator.translate(source, mapping)
    assert result["content"]["username"] == "bob"
    assert result["content"]["password"] == "123"

def test_full_engine_orchestration(tmp_path):
    mapping_dir = tmp_path / "mappings"
    mapping_dir.mkdir()
    
    # Setup mock template
    template = {"format": "csv", "map": {"title": "name", "password": "pwd"}}
    with open(mapping_dir / "test_csv.json", "w") as f:
        json.dump(template, f)
        
    bus = MockBus()
    engine = ImportEnginePlugin(bus, mapping_dir=str(mapping_dir))
    
    raw_data = "name,pwd\nGithub,supersecret"
    result = engine.process_import("test_csv", raw_data)
    
    assert result["vaulted"] == 1
    assert bus.vaulted[0]["content"]["title"] == "Github"
    assert bus.vaulted[0]["content"]["password"] == "supersecret"