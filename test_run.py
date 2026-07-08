import unittest
import tempfile
import shutil
import os
import vibeshield

class TestVibeShield(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _create_file(self, name, content):
        path = os.path.join(self.tmpdir, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return path

    def test_1_secrets_tp(self):
        path = self._create_file("tp1.py", 'api_key = "sk_live_abc123"\n')
        findings = vibeshield.scan_file(path)
        self.assertTrue(any(f.rule == "Rule 1" for f in findings))

    def test_2_secrets_tn(self):
        path_basic = self._create_file("tn1_basic.py", 'import os\napi_key = os.environ.get("STRIPE_KEY")\n')
        findings_basic = vibeshield.scan_file(path_basic)
        self.assertFalse(any(f.rule == "Rule 1" for f in findings_basic))

        path_get = self._create_file("tn1_get.py", 'import os\napi_key = os.environ.get("sk_live_123")\n')
        findings_get = vibeshield.scan_file(path_get)
        self.assertFalse(any(f.rule == "Rule 1" for f in findings_get), "Failed to exempt os.environ.get call")

        path_getenv = self._create_file("tn1_getenv.py", 'import os\napi_key = os.getenv("sk_live_123")\n')
        findings_getenv = vibeshield.scan_file(path_getenv)
        self.assertFalse(any(f.rule == "Rule 1" for f in findings_getenv), "Failed to exempt os.getenv call")

        path_sub = self._create_file("tn1_sub.py", 'import os\napi_key = os.environ["sk_live_123"]\n')
        findings_sub = vibeshield.scan_file(path_sub)
        self.assertFalse(any(f.rule == "Rule 1" for f in findings_sub), "Failed to exempt os.environ subscript")

        path_ann = self._create_file("tn1_ann.py", 'import os\napi_key: str = os.getenv("sk_live_123")\n')
        findings_ann = vibeshield.scan_file(path_ann)
        self.assertFalse(any(f.rule == "Rule 1" for f in findings_ann), "Failed to exempt annotated environment assignment")

    def test_3_ci_tp(self):
        path = self._create_file("tp2.py", 'import os\nuser_input = "test"\nos.system(f"ls {user_input}")\n')
        findings = vibeshield.scan_file(path)
        self.assertTrue(any(f.rule == "Rule 2" for f in findings))

    def test_4_ci_tn(self):
        path = self._create_file("tn2.py", 'import subprocess\nsubprocess.run(["ls", "-la"])\n')
        findings = vibeshield.scan_file(path)
        self.assertFalse(any(f.rule == "Rule 2" for f in findings))

    def test_5_eval_tp(self):
        path = self._create_file("tp3.py", 'user_input = "1+1"\neval(user_input)\n')
        findings = vibeshield.scan_file(path)
        self.assertTrue(any(f.rule == "Rule 3" for f in findings))

    def test_6_eval_tn(self):
        path = self._create_file("tn3.py", 'import ast\nsafe_string = "[1, 2, 3]"\nast.literal_eval(safe_string)\n')
        findings = vibeshield.scan_file(path)
        self.assertFalse(any(f.rule == "Rule 3" for f in findings))

    def test_7_lazy_exc_tp(self):
        path = self._create_file("tp4.py", 'try:\n    pass\nexcept:\n    pass\n')
        findings = vibeshield.scan_file(path)
        self.assertTrue(any(f.rule == "Rule 4" for f in findings))

    def test_8_lazy_exc_tn(self):
        path = self._create_file("tn4.py", 'import logging\ntry:\n    pass\nexcept Exception as e:\n    logging.error(e)\n')
        findings = vibeshield.scan_file(path)
        self.assertFalse(any(f.rule == "Rule 4" for f in findings))

if __name__ == '__main__':
    unittest.main()
