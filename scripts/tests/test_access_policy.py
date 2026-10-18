from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'wg-relay-remote.sh'
SOURCE = SCRIPT.read_text().split("<<'ACCESS_POLICY_PY'\n", 1)[1].split('\nACCESS_POLICY_PY', 1)[0]
ENGINE = {'__name__': 'access_policy_test'}
exec(compile(SOURCE, str(SCRIPT) + ':access-policy', 'exec'), ENGINE)


class AccessPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'peers').mkdir()
        (self.root / 'peer-forwards').mkdir()
        for n, address in [('server', '10.99.0.2'), ('laptop', '10.99.0.3'), ('phone', '10.99.0.4')]:
            (self.root / 'peers' / (n + '.conf')).write_text('[Peer]\nAllowedIPs = ' + address + '/32\n')
        for n, protocol, port in [('rdp-tcp', 'tcp', 3389), ('rdp-udp', 'udp', 3389), ('web', 'tcp', 8081)]:
            (self.root / 'peer-forwards' / (n + '.conf')).write_text(
                f'PROTOCOL={protocol}\nSOURCE_ADDRESSES=10.99.0.3\nTARGET_ADDRESS=10.99.0.2\nTARGET_PORT={port}\n')
        self.state = ENGINE['load'](self.root)

    def change(self, **request):
        self.state = ENGINE['change'](self.state, request)
        return self.state

    def group(self, n, presets=None, groups=None, **other):
        return self.change(action='group-create', name=n, preset_names=presets or [], group_names=groups or [], **other)

    def assign(self, peer='laptop', presets=None, groups=None):
        return self.change(action='assign', peer_name=peer, preset_names=presets or [], group_names=groups or [])

    def test_migration_is_read_only_and_idempotent(self):
        self.assertFalse((self.root / 'access-policy.json').exists())
        original = ENGINE['resolve'](self.state)
        self.assertEqual(list(original['10.99.0.3']), ['rdp-tcp', 'rdp-udp', 'web'])
        ENGINE['save'](self.root, self.state)
        first = ENGINE['load'](self.root)
        ENGINE['save'](self.root, first)
        self.assertEqual(first, ENGINE['load'](self.root))
        self.assertEqual(original, ENGINE['resolve'](first))

    def test_shared_nested_groups_and_direct_grants_survive_removal(self):
        self.group('rdp', ['rdp-tcp', 'rdp-udp'])
        self.group('home', ['web'], ['rdp'])
        self.group('admin', groups=['rdp'])
        self.assign(presets=['web'], groups=['home', 'admin'])
        effective = ENGINE['resolve'](self.state)['10.99.0.3']
        self.assertEqual(len(effective['rdp-tcp']), 2)
        self.assign(presets=['web'], groups=['admin'])
        self.assertEqual(set(ENGINE['resolve'](self.state)['10.99.0.3']), {'web', 'rdp-tcp', 'rdp-udp'})
        self.assign(presets=['web'])
        self.assertEqual(list(ENGINE['resolve'](self.state)['10.99.0.3']), ['web'])

    def test_empty_group_and_missing_references(self):
        self.group('empty')
        self.assign(groups=['empty'])
        self.assertEqual(ENGINE['resolve'](self.state)['10.99.0.3'], {})
        for request in [dict(action='group-create', name='missing', group_names=['absent']),
                        dict(action='group-create', name='missing', preset_names=['absent']),
                        dict(action='assign', peer_name='laptop', preset_names=[], group_names=['absent'])]:
            with self.assertRaisesRegex(ValueError, '見つかりません'):
                ENGINE['change'](self.state, request)

    def test_cycles_and_self_reference_are_rejected(self):
        self.group('a')
        self.group('b', groups=['a'])
        for children in [['a'], ['b']]:
            with self.assertRaisesRegex(ValueError, '循環'):
                self.change(action='group-update', current_name='a', name='a', preset_names=[], group_names=children)

    def test_self_target_error_contains_reference_path(self):
        self.group('rdp', ['rdp-tcp'])
        self.group('home', groups=['rdp'])
        with self.assertRaisesRegex(ValueError, 'server → home → rdp → rdp-tcp'):
            self.assign(peer='server', groups=['home'])

    def test_referenced_deletion_and_atomic_rename(self):
        self.group('rdp', ['rdp-tcp'])
        self.group('home', groups=['rdp'])
        self.assign(groups=['home'])
        for request, ref in [(dict(action='group-delete', name='rdp'), 'グループ: home'),
                             (dict(action='group-delete', name='home'), 'Peer: laptop'),
                             (dict(action='preset-delete', name='rdp-tcp'), 'グループ: rdp')]:
            with self.assertRaisesRegex(ValueError, ref):
                ENGINE['change'](self.state, request)
        self.change(action='group-update', current_name='rdp', name='remote', preset_names=['rdp-tcp'], group_names=[])
        self.assertEqual(self.state['groups']['home']['group_names'], ['remote'])
        self.change(action='preset-update', current_name='rdp-tcp', name='remote-tcp', protocol='tcp', target_address='10.99.0.2', target_port=3390)
        self.assertEqual(self.state['groups']['remote']['preset_names'], ['remote-tcp'])
        self.assertEqual(set(ENGINE['resolve'](self.state)['10.99.0.3']), {'remote-tcp'})

    def test_group_rename_updates_peer_assignment(self):
        self.group('empty')
        self.assign(groups=['empty'])
        self.change(action='group-update', current_name='empty', name='new', preset_names=[], group_names=[])
        self.assertEqual(self.state['assignments']['10.99.0.3']['group_names'], ['new'])

    def test_preview_detects_destination_changes_and_shared_grants(self):
        self.group('rdp', ['rdp-tcp'])
        self.assign(groups=['rdp'])
        before = copy.deepcopy(self.state)
        self.change(action='preset-update', current_name='rdp-tcp', name='rdp-tcp', protocol='tcp', target_address='10.99.0.2', target_port=3390)
        preview = ENGINE['preview'](before, self.state)
        self.assertEqual(preview['changes'][0]['added'][0]['target_port'], 3390)
        self.assertEqual(preview['changes'][0]['removed'][0]['target_port'], 3389)
        before = copy.deepcopy(self.state)
        self.assign(presets=['rdp-tcp'], groups=['rdp'])
        self.assertEqual(ENGINE['preview'](before, self.state)['changes'], [])

    def test_group_bulk_creation_is_atomic_and_validated(self):
        before = copy.deepcopy(self.state)
        new = dict(name='game', protocol='udp', target_address='10.99.0.2', target_port=27015)
        with self.assertRaises(ValueError):
            self.group('game', new_presets=[new, dict(new, target_port=0)])
        self.assertEqual(before, self.state)
        self.group('game', new_presets=[new])
        self.assertEqual(self.state['groups']['game']['preset_names'], ['game'])

    def test_deep_nesting_has_no_python_recursion_limit(self):
        self.state['groups'] = {f'g{i}': {'preset_names': [], 'group_names': [f'g{i+1}']} for i in range(1100)}
        self.state['groups']['g1100'] = {'preset_names': ['web'], 'group_names': []}
        self.assign(groups=['g0'])
        self.assertEqual(len(ENGINE['resolve'](self.state)['10.99.0.3']['web'][0]), 1102)

    def test_legacy_assignment_preserves_groups(self):
        self.group('rdp', ['rdp-tcp'])
        self.assign(groups=['rdp'])
        request = ENGINE['legacy_request'](self.state, ['assign-source', '10.99.0.3', 'web'])
        self.state = ENGINE['change'](self.state, request)
        self.assertEqual(self.state['assignments']['10.99.0.3']['group_names'], ['rdp'])
        self.assertEqual(set(ENGINE['resolve'](self.state)['10.99.0.3']), {'web', 'rdp-tcp'})

    def engine(self, operation, request):
        encoded = base64.b64encode(json.dumps(request).encode()).decode()
        return subprocess.run(['python3', '-', str(self.root), operation, encoded], input=SOURCE,
                              text=True, capture_output=True)

    def test_stale_revision_and_preview_do_not_write(self):
        request = dict(action='group-create', name='empty', preset_names=[], group_names=[])
        before = {p.name: p.read_bytes() for p in (self.root / 'peer-forwards').glob('*')}
        preview = self.engine('preview', request)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        result = self.engine('apply', dict(request, revision='old'))
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)['error'], 'conflict')
        self.assertFalse((self.root / 'access-policy.json').exists())
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.root / 'peer-forwards').glob('*')})
        revision = json.loads(preview.stdout)['revision']
        self.assertEqual(self.engine('apply', dict(request, revision=revision)).returncode, 0)
        self.assertIn('empty', ENGINE['load'](self.root)['groups'])

    def shell_transaction(self, request, firewall, fail_save=False):
        source = SCRIPT.read_text().rsplit('main "$@"', 1)[0]
        source = source.replace('readonly STATE_DIR="${WG_DIR}/relay.d"',
                                'readonly STATE_DIR=' + __import__('shlex').quote(str(self.root)))
        if fail_save:
            source = source.replace("        atomic_write(directory / (n + '.conf'), text)",
                                    "        atomic_write(directory / (n + '.conf'), text)\n        raise OSError('injected storage failure')")
        encoded = base64.b64encode(json.dumps(request).encode()).decode()
        setup = '\nensure_initialized() { :; }\nfirewall_sync() { ' + firewall + '; }\n'
        return subprocess.run(['bash', '-s', '--', encoded], input=source + setup +
                              '\naccess_policy_command apply "$1"\n', text=True, capture_output=True)

    def test_firewall_failure_rolls_back_migration_and_presets(self):
        request = dict(action='group-create', name='game', new_presets=[
            dict(name='game', protocol='udp', target_address='10.99.0.2', target_port=27015)],
            revision=ENGINE['revision'](self.state))
        before = {p.name: p.read_bytes() for p in (self.root / 'peer-forwards').glob('*')}
        # 初回反映だけを失敗させ、復元の再同期は成功させる。
        firewall = 'if [ ! -f "${STATE_DIR}/fail-once" ]; then touch "${STATE_DIR}/fail-once"; return 1; fi; return 0'
        result = self.shell_transaction(request, firewall)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.root / 'peer-forwards').glob('*')})
        self.assertFalse((self.root / 'access-policy.json').exists())
        self.assertFalse((self.root / '.access-transaction').exists())

    def test_partial_storage_write_rolls_back_all_files(self):
        request = dict(action='group-create', name='empty', revision=ENGINE['revision'](self.state))
        before = {p.name: p.read_bytes() for p in (self.root / 'peer-forwards').glob('*')}
        result = self.shell_transaction(request, 'return 0', fail_save=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['error'], 'apply_failed')
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.root / 'peer-forwards').glob('*')})
        self.assertFalse((self.root / 'access-policy.json').exists())
        self.assertFalse((self.root / '.access-transaction').exists())

    def test_firewall_failure_restores_existing_group_policy(self):
        self.group('home', ['web'])
        self.assign(groups=['home'])
        ENGINE['save'](self.root, self.state)
        before = ENGINE['load'](self.root)
        request = dict(action='group-update', current_name='home', name='home',
                       preset_names=['rdp-tcp'], group_names=[], revision=ENGINE['revision'](before))
        result = self.shell_transaction(request,
            'if [ ! -f "${STATE_DIR}/fail-once" ]; then touch "${STATE_DIR}/fail-once"; return 1; fi; return 0')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before, ENGINE['load'](self.root))

    def test_service_hook_does_not_wait_for_parent_lock(self):
        import shlex
        source = SCRIPT.read_text().rsplit('main "$@"', 1)[0]
        source = source.replace('readonly STATE_DIR="${WG_DIR}/relay.d"', 'readonly STATE_DIR=' + shlex.quote(str(self.root)))
        source = source.replace('readonly LOCK_FILE="/run/lock/wg-relay.lock"', 'readonly LOCK_FILE=' + shlex.quote(str(self.root / 'lock')))
        fixture = '''
require_root() { :; }
require_commands() { :; }
firewall_sync() { touch "${STATE_DIR}/hook-synced"; }
flock() { echo 'unexpected recursive lock' >&2; return 1; }
systemctl() { (main firewall-sync); }
relay_systemctl restart wg-quick@wg0
'''
        result = subprocess.run(['bash', '-s'], input=source + fixture, text=True, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'hook-synced').exists())
        self.assertFalse((self.root / 'lock.service-owner').exists())

    def test_restore_failure_keeps_backup_and_reports_it(self):
        request = dict(action='group-create', name='empty', revision=ENGINE['revision'](self.state))
        result = self.shell_transaction(request, 'return 1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('復元に失敗', result.stderr)
        self.assertEqual(json.loads(result.stdout)['error'], 'partial_failure')
        self.assertEqual(json.loads(result.stdout)['rollback'], 'failed')
        self.assertTrue((self.root / '.access-transaction').is_dir())

    def test_successful_transaction_persists_and_cleans_backup(self):
        request = dict(action='group-create', name='empty', revision=ENGINE['revision'](self.state))
        result = self.shell_transaction(request, 'return 0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['ok'])
        self.assertIn('empty', ENGINE['load'](self.root)['groups'])
        self.assertFalse((self.root / '.access-transaction').exists())

    def test_restart_recovery_restores_uncommitted_files(self):
        import shutil
        backup = self.root / '.access-transaction'
        backup.mkdir()
        shutil.copytree(self.root / 'peer-forwards', backup / 'peer-forwards')
        original = (self.root / 'peer-forwards/web.conf').read_bytes()
        (self.root / 'peer-forwards/web.conf').write_text('corrupted')
        (self.root / 'access-policy.json').write_text('{}')
        source = SCRIPT.read_text().rsplit('main "$@"', 1)[0].replace(
            'readonly STATE_DIR="${WG_DIR}/relay.d"',
            'readonly STATE_DIR=' + __import__('shlex').quote(str(self.root)))
        result = subprocess.run(['bash', '-s'], input=source +
                                '\nfirewall_sync() { return 0; }\nrecover_access_policy\n', text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'peer-forwards/web.conf').read_bytes(), original)
        self.assertFalse((self.root / 'access-policy.json').exists())
        self.assertFalse(backup.exists())


if __name__ == '__main__':
    unittest.main()
