import unittest
import os
import sys

# Need to append v1.0.6 to sys path to import octopus_verifier
sys.path.insert(0, os.path.abspath('v1.0.6'))

from octopus_verifier import ProjectProfiler

class TestOctopus(unittest.TestCase):
    def test_project_profiler_init(self):
        # Create a dummy python file in current dir
        with open("dummy_test.py", "w") as f:
            f.write("import os\nimport sys\n")
            
        profiler = ProjectProfiler(".")
        self.assertEqual(profiler.target_path, os.path.abspath("."))
        
        os.remove("dummy_test.py")

if __name__ == '__main__':
    unittest.main()
