import unittest
from cutoff_client import cutoff_arguments

class CutoffArguments(unittest.TestCase):
    def test_exact_date_and_filter(self):
        self.assertEqual(cutoff_arguments('1700002000;-;blob:none'), ['--shallow-since=2023-11-14T22:46:40+00:00', '--filter=blob:none'])
    def test_exclusions_are_ordered_and_preserve_full_names(self):
        self.assertEqual(cutoff_arguments('-;cut-new,refs/tags/cut-old;full'), ['--shallow-exclude=cut-new', '--shallow-exclude=refs/tags/cut-old'])
    def test_combined_controls(self):
        self.assertEqual(cutoff_arguments('1700002000;cut-new;tree:0'), ['--shallow-since=2023-11-14T22:46:40+00:00','--shallow-exclude=cut-new','--filter=tree:0'])
    def test_invalid_or_unbounded_arguments_are_rejected(self):
        for value in ['-;-;full','0;-;full','-1;-;full','2147483648;-;full','1700002000;HEAD;full','1700002000;cut-new;bad','1700002000;cut-new;full;extra','-;'+','.join(['cut-old']*5)+';full','-;cut-old\n--upload-pack=x;full','x'*513]:
            with self.subTest(value=value), self.assertRaises(ValueError):cutoff_arguments(value)

if __name__=='__main__':unittest.main()
