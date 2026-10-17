import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('deployer', Path(__file__).resolve().parents[2] / 'deploy/deploy.py')
deployer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployer)


class DeploymentTests(unittest.TestCase):
    def archive(self, root, sha='a' * 40, unsafe=None):
        archive = root / 'build.tar.gz'
        with tarfile.open(archive, 'w:gz') as output:
            for name, content in [('index.html', b'<html>tested build</html>'), ('version.txt', sha.encode())]:
                member = tarfile.TarInfo(name)
                member.size = len(content)
                output.addfile(member, io.BytesIO(content))
            if unsafe:
                output.addfile(unsafe)
        return archive

    def setup_site(self, root):
        initial = root / 'initial'
        initial.mkdir()
        (initial / 'index.html').write_text('original')
        (root / 'current').symlink_to(initial)
        return {'root': str(root), 'health_url': 'http://localhost/'}

    def test_success_switches_release_and_preserves_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.setup_site(root)
            with patch.object(deployer, 'health'):
                deployer.deploy_site(config, self.archive(root), 'a' * 40)
            self.assertEqual((root / 'current').resolve(), root / ('a' * 40))
            self.assertEqual((root / 'previous').resolve(), root / 'initial')

    def test_failed_health_restores_previous_site(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.setup_site(root)
            with patch.object(deployer, 'health', side_effect=RuntimeError('unhealthy')):
                with self.assertRaises(RuntimeError):
                    deployer.deploy_site(config, self.archive(root), 'a' * 40)
            self.assertEqual((root / 'current').resolve(), root / 'initial')

    def test_wrong_commit_never_switches_site(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.setup_site(root)
            with self.assertRaises(ValueError):
                deployer.deploy_site(config, self.archive(root, sha='b' * 40), 'a' * 40)
            self.assertEqual((root / 'current').resolve(), root / 'initial')

    def test_rejects_traversal_absolute_paths_and_links(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE), ('link', tarfile.SYMTYPE), ('hardlink', tarfile.LNKTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                unsafe = tarfile.TarInfo(name)
                unsafe.type = kind
                unsafe.linkname = '/etc/passwd'
                archive = self.archive(root, unsafe=unsafe)
                with self.assertRaises(ValueError):
                    deployer.extract_site(archive, root / 'output')

    def test_failed_api_switch_rolls_back_original_image(self):
        config = {'root': '/unused'}
        with patch.object(deployer, 'compose', side_effect=['container', '', '', '', '']) as compose, \
             patch.object(deployer.subprocess, 'check_output', return_value='sha256:original\n'), \
             patch.object(deployer.subprocess, 'run'), \
             patch.object(deployer, 'health', side_effect=[None, RuntimeError('bad new API'), None]):
            with self.assertRaises(RuntimeError):
                deployer.deploy_api(config, Path('/archive'), 'a' * 40)
            self.assertEqual(compose.call_args_list[-1].args[1], 'sha256:original')

    def test_candidate_failure_does_not_replace_live_api(self):
        with patch.object(deployer, 'compose', side_effect=['container', '', '']) as compose, \
             patch.object(deployer.subprocess, 'check_output', return_value='sha256:original\n'), \
             patch.object(deployer.subprocess, 'run'), \
             patch.object(deployer, 'health', side_effect=RuntimeError('bad candidate')):
            with self.assertRaises(RuntimeError):
                deployer.deploy_api({}, Path('/archive'), 'a' * 40)
            self.assertTrue(compose.call_args_list[-1].kwargs['candidate'])
            self.assertEqual(compose.call_count, 3)


if __name__ == '__main__':
    unittest.main()
