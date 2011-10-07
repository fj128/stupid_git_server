import unittest
import shutil
import os, stat, sys
from os import path as os_path
import logging
from cStringIO import StringIO
import subprocess
from subprocess import check_call

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

def retry_rm_readonly(func, path, exc_info):
    # path contains the path of the file that couldn't be removed
    # let's just assume that it's read-only and unlink it.
    os.chmod(path, stat.S_IWRITE)
    os.unlink(path)

def rmtree(path):
    if os_path.exists(path):
        shutil.rmtree(path, onerror=retry_rm_readonly)
        
def run_and_serve_command(server, command, expected_result = 0):
    out_buffer = StringIO()
    child = subprocess.Popen(command,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    pump = create_data_pump('stdout->buffer', child.stdout.read, out_buffer.write, lambda:None)
    if server: server.handle_request()
    res = child.wait()
    pump.join()
    if res != expected_result:
        print 'Git returned %d: %r' % (res, out_buffer.getvalue())
        assert False
    lst = out_buffer.getvalue().split('\n')
    if len(lst) and not lst[-1]: del lst[-1]
    return lst


class TestBase(object):
    testing_playground = 'testing_playground'
    clone1 = 'test_repo1'
    clone2 = 'test_repo2'
    def setUp(self):
        logstream.truncate()
        rmtree(self.testing_playground)
        print os.getcwd()
        os.makedirs(self.testing_playground)
        self.old_working_directory = os.getcwd()
        os.chdir(self.testing_playground)
        self.base_directory = os.getcwd()
        self.server = Server(listen_address, listen_port, server_key,
                users, repositories, False)
        
    def tearDown(self):
        self.server.server_close()
        os.chdir(self.old_working_directory)
        rmtree(self.testing_playground)
        logstream.truncate()
    
    def assertListEndsWith(self, lst1, lst2, msg=None):
        return self.assertListEqual(lst1[-len(lst2):], lst2, msg)
        
def get_repo_creation_message(repo_name):
    return ['warning: repository \'%s\' doesn\'t exist, creating.' % repo_name,
            'warning: don\'t forget that your first push must be `git push --all`.',
            'warning: You appear to have cloned an empty repository.']

class Test_successful_operations(TestBase, unittest.TestCase):
    def test_correct_playground(self):
        self.assertTrue(os.getcwd().endswith(self.testing_playground),
                'Oh god, oh man, oh god, oh man, ' +
                'we are running tests in the wrong place, ' +
                'important information might have been destroyed!!!11') 

    def test_with_extension(self):
        output = run_and_serve_command(self.server, 
                'git clone ssh://localhost:27015/test_repo.git')
        self.assertListEndsWith(output, get_repo_creation_message('test_repo')) 

    def test_with_extension2(self):
        self.server.configure(self.server.users, {'test_repo.git1' : ['test_user']})
        output = run_and_serve_command(self.server, 
                'git clone ssh://localhost:27015/test_repo.git1')
        self.assertListEndsWith(output, get_repo_creation_message('test_repo.git1')) 

    def test_clone_empty(self):
        file_name = 'testfile.txt'
        contents = 'testline\ntestline2\n'

        output = run_and_serve_command(self.server, 
                'git clone ssh://localhost:27015/test_repo')
        self.assertListEndsWith(output, get_repo_creation_message('test_repo')) 
        
        os.chdir('test_repo')
        with open(file_name, 'w') as f:
            f.write(contents)
        check_call('git add ' + file_name)
        check_call('git commit -am "yo"')
        output = run_and_serve_command(self.server, 
                'git push --all')
        self.assertListEndsWith(output, [' * [new branch]      master -> master']) 

        os.chdir(self.base_directory)
        output = run_and_serve_command(self.server, 
                'git clone ssh://localhost:27015/test_repo clone1')
        with open('clone1/' + file_name, 'r') as f:
            self.assertEqual(f.read(), contents)

    def test_push(self):
        file_name = 'testfile.txt'
        contents = 'testline\ntestline2\n'
        
        check_call('git init testrepo')
        os.chdir('testrepo')
        with open(file_name, 'w') as f:
            f.write(contents)
        check_call('git add ' + file_name)
        check_call('git commit -am "yo"')
        check_call('git remote add origin ssh://localhost:27015/test_repo')
        output = run_and_serve_command(self.server, 
                'git push --all')
        self.assertListEndsWith(output, [
                "warning: repository 'test_repo' doesn't exist, creating.",
                'To ssh://localhost:27015/test_repo',
                ' * [new branch]      master -> master'])
        
        os.chdir(self.base_directory)
        output = run_and_serve_command(self.server, 
                'git clone ssh://localhost:27015/test_repo clone1')
        with open('clone1/' + file_name, 'r') as f:
            self.assertEqual(f.read(), contents)
            
class Test_error_recovery(TestBase, unittest.TestCase):
    nonexistent_pub_key = 'AAAAB3NzaC1yc2EAAAADAQABAAAAgQC2GVRnNff5RjWqeR8F8ZqZkslZZZZZZZZZZZZTB2zTs088JK/xZxz6u2CztMRDN7FK2Y0jVVktMWTlIB6PhMCs+IYVjo1vdEKuSfifVaInA+lPUwHOju+P76bf9NxFKYGWDxjx8Nuad4kKXz8lYJmC2BpocUftmvBHMfKY7kf/IQ=='        
    
    def test_wrong_config(self):
        with self.assertRaises(AssertionError) as assertion:
            self.server.configure(users, { 'test_repo' : ['not_a_user'] })
        self.assertEqual(assertion.exception.message, "Unknown user 'not_a_user' in repository 'test_repo'")
    def test_nonexistent_repo(self):
        output = run_and_serve_command(self.server, 
                'git clone ssh://localhost:27015/nonexistent_repo', 128)
        self.assertIn("fatal: Repository doesn't exist: 'nonexistent_repo'", output) 
    def test_nonexistent_user(self):
        self.server.configure({'test_user' : self.nonexistent_pub_key },
                self.server.repositories)
        output = run_and_serve_command(self.server, 
                'git clone ssh://localhost:27015/test_repo', 128)
        self.assertIn('Permission denied (publickey).', map(str.strip, output)) 
        

if __name__ == '__main__':
    unittest.main()
