"""Parser/executor tests; these do not connect to Oracle or apply migrations."""
import importlib.util
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('asset_migration_runner',ROOT/'db/apply_asset_migration.py')
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

def test_reviewed_migration_blocks_are_not_split_on_internal_semicolons():
    ops=list(runner.parse_script((ROOT/'db/V010_asset_admin.sql').read_text()))
    blocks=[value for kind,value in ops if kind=='plsql']
    assert len(blocks)==4
    assert 'SESSION_USER' in blocks[0] and "<> 'CS_OWNER'" in blocks[0]
    procedures=[block for block in blocks if block.startswith('CREATE PROCEDURE')]
    assert len(procedures)==2
    assert all('SAVEPOINT' in block and 'ROLLBACK TO' in block and 'cs_security.assert_actor' in block for block in procedures)
    assert all(block.rstrip().endswith('END;') for block in blocks)
    assert [kind for kind,value in ops].count('show_errors')==2
    assert len([value for kind,value in ops if kind=='sql'])==2
    assert ops[0][0]=='on_error_rollback'

def test_grant_script_preserves_owner_guard_and_only_execute_grants():
    ops=list(runner.parse_script((ROOT/'db/grants_asset_admin.sql').read_text()))
    assert [value for kind,value in ops if kind=='sql']==['GRANT EXECUTE ON sp_save_server TO cs_app','GRANT EXECUTE ON sp_save_ip TO cs_app']
    assert 'SESSION_USER' in next(value for kind,value in ops if kind=='plsql')

@pytest.mark.parametrize('sql',[
    "INSERT INTO schema_migration VALUES ('a;b');",
    "INSERT INTO schema_migration VALUES ('a''b;c');",
    'INSERT INTO schema_migration VALUES (1 /* ; */);',
    'INSERT INTO schema_migration VALUES (1 -- ;\n);',
])
def test_sql_terminators_respect_quotes_and_comments(sql):
    assert runner.sql_end(sql)==len(sql)-1
    assert len(list(runner.parse_script(sql)))==1

@pytest.mark.parametrize('script',['BEGIN NULL; END;','SET DEFINE ON','@unreviewed.sql','DROP TABLE app_user;','/'])
def test_unknown_directives_and_missing_block_separator_fail_closed(script):
    with pytest.raises(ValueError):list(runner.parse_script(script))
