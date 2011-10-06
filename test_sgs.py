import unittest
import shutil
import os
import logging
import threading
import sys
from cStringIO import StringIO
import subprocess

# redirect logging to stdout and to a stream to be checked
# use a class to allow unittest to suppress stdout
logstream = StringIO()
class LogHandler(logging.Handler):
    def emit(self, record):
        msg = record.name + '-' + record.levelname + ': ' + record.getMessage()
        print msg
        logstream.write(msg + '\n')

logging.getLogger().setLevel(logging.INFO)
logging.getLogger().addHandler(LogHandler())


from sample_serve import listen_address, listen_port, server_key
from sample_serve import users, repositories
from stupid_git_server import Server, create_data_pump

def run_and_serve_command(server, command):
    out_buffer = StringIO()
    child = subprocess.Popen(command,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    pump = create_data_pump('stdout->buffer', child.stdout.read, out_buffer.write, lambda:None)
    if server: server.handle_request()
    retcode = child.wait()
    pump.join()
    lst = out_buffer.getvalue().split('\n')
    if len(lst) and not lst[-1]: del lst[-1]
    return retcode, lst
    
    

class TestBase(object):
    testing_playground = 'testing_playground'
    clone1 = 'test_repo1'
    clone2 = 'test_repo2'
    def setUp(self):
        logstream.truncate()
        shutil.rmtree(self.testing_playground, True)
        os.makedirs(self.testing_playground)
        self.old_working_directory = os.getcwd()
        os.chdir(self.testing_playground)
        self.server = Server(listen_address, listen_port, server_key,
                users, repositories, False)
        
    def tearDown(self):
        self.server.server_close()
        os.chdir(self.old_working_directory)
        shutil.rmtree(self.testing_playground)
        logstream.truncate()
        
        

class Test_successful_operations(TestBase, unittest.TestCase):
    def test_correct_playground(self):
        self.assertTrue(os.getcwd().endswith(self.testing_playground),
                'Oh god, oh man, oh god, oh man, ' +
                'we are running tests in the wrong place, ' +
                'important information might have been destroyed!!!11') 
                
    def test_clone_empty1(self):
        result, output = run_and_serve_command(self.server, 
                'git clone ssh://localhost:27015/test_repo')
        self.assertEqual(result, 0)
        self.assertListEqual(output[-2:], 
                ['warning: repository \'test_repo\' doesn\'t exist, creating.',
                 'warning: You appear to have cloned an empty repository.'])
        

if __name__ == '__main__':
    unittest.main()
