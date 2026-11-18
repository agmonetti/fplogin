import runpy
import unittest
from pathlib import Path

judge = runpy.run_path(str(Path(__file__).with_name('s3-deadline.py')))['judge']
DAEMON = '''tick 1
arm 2 101 30000
enter 3 102
fire 4 101
disarm 5 101
stop 6 101
exit 7 102
tick 8
end 9
'''
PAM = DAEMON.replace('fire 4 101\ndisarm 5 101\nstop 6 101',
                     'pam_timeout 4 102\npam_return 5 102 9\ndisarm 6 101')


class DeadlineTest(unittest.TestCase):
    def test_orders(self):
        self.assertEqual(judge(DAEMON, 101, 102), 'DAEMON_DEADLINE_FIRST')
        self.assertTrue(judge(PAM, 101, 102).startswith('PAM_BACKSTOP_FIRST'))

    def test_inconclusive(self):
        for bad in (DAEMON.replace('fire 4 101\n',''), DAEMON.replace('101 30000','101 1000'),
                    DAEMON.replace('enter 3','enter 6'), DAEMON.replace('stop 6','stop 8'), DAEMON.replace('enter 3 102','enter 3 103'),
                    DAEMON.replace('fire 4', 'pam_timeout 3 102\nfire 4'), DAEMON + 'arm 10 101 30000\n',
                    DAEMON.replace('end 9',''), PAM.replace('pam_timeout 4 102\n',''), DAEMON + 'lost events',
                    DAEMON.replace('tick 8', 'finger map cleanup failed\ntick 8')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                judge(bad, 101, 102)


if __name__ == '__main__':
    unittest.main()
