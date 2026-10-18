from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from dashboard.cli import CliError, parser, run


class AccessCliTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock(base_url='http://127.0.0.1:8080')
        self.client.request.return_value = {'revision': 'revision-one', 'changes': []}

    def call(self, args, body):
        with patch('dashboard.cli.input_object', return_value=body):
            return run(parser().parse_args(args), self.client)

    def test_group_dry_run_uses_same_api_without_changes(self):
        self.call(['access-group', 'create', '--input', '-', '--dry-run'],
                  {'name': 'home', 'preset_names': [], 'group_names': ['remote']})
        self.client.request.assert_called_once_with('/api/wireguard/access-preview', method='POST', body={
            'action': 'group-create', 'current_name': 'home', 'name': 'home',
            'preset_names': [], 'group_names': ['remote']})

    def test_real_change_requires_origin_key_and_preview_revision(self):
        base = ['access-group', 'create', '--input', '-']
        for flags, body, code in [([], {'name': 'home'}, 'confirmation_required'),
                                  (['--confirm', self.client.base_url], {'name': 'home'}, 'idempotency_key_required'),
                                  (['--confirm', self.client.base_url, '--idempotency-key', 'group-key-0001'], {'name': 'home'}, 'input_error')]:
            with patch.dict('os.environ', {}, clear=True), self.assertRaises(CliError) as caught:
                self.call(base + flags, body)
            self.assertEqual(caught.exception.code, code)
        self.client.request.assert_not_called()

    def test_group_update_delete_and_peer_assignment(self):
        confirmation = ['--confirm', self.client.base_url, '--idempotency-key', 'access-key-0001']
        for command, body, path, method, action in [
            (['access-group', 'update'], {'name': 'new', 'current_name': 'old', 'revision': 'one'}, '/api/wireguard/access-groups/old', 'PUT', 'group-update'),
            (['access-group', 'delete'], {'name': 'old', 'revision': 'one'}, '/api/wireguard/access-groups/old', 'DELETE', 'group-delete'),
            (['peer-access', 'set'], {'peer_name': 'laptop', 'preset_names': [], 'group_names': ['home'], 'revision': 'one'}, '/api/wireguard/peers/laptop/access', 'PUT', 'assign')]:
            self.call(command + ['--input', '-'] + confirmation, body)
            args = self.client.request.call_args
            self.assertEqual(args.args[0], path)
            self.assertEqual(args.kwargs['method'], method)
            self.assertEqual(args.kwargs['body']['action'], action)
            self.assertEqual(args.kwargs['idempotency_key'], 'access-key-0001')

    def test_dry_run_rejects_change_confirmation(self):
        with self.assertRaises(CliError):
            self.call(['peer-access', 'set', '--input', '-', '--dry-run', '--confirm', self.client.base_url],
                      {'peer_name': 'laptop'})
        self.client.request.assert_not_called()


if __name__ == '__main__':
    unittest.main()
