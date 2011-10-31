import os, sys
from os import path as os_path
import subprocess
import SocketServer
import re
#from os import path as os_path
from cStringIO import StringIO
import paramiko
import base64
import threading
from binascii import hexlify
from contextlib import contextmanager
import traceback
import logging.handlers
from Queue import Queue, Empty as Queue_Empty

_log_hex_dump = False
log = logging.getLogger('sgs')
log_initialized = False

def init_logging(path='stupid_git_server.log', level=logging.DEBUG,
        log_hex_dump=False, stderr_level=logging.INFO, namespace='sgs'):
    '''Initialize both my and paramiko's logging facilities. My logging goes
    under 'sgs' (unless overriden by `namespace`), paramiko's is redirected to
    'sgs.paramiko.*' on a per-transport basis, but it is possible that there is
    some stuff that can happen before a transport is created, that goes to the
    default 'paramiko.*'.

    If `path` is None then logs to stderr, otherwise to 'sgs.log' using a
    RotatingFileHandler.

    `use_hex_dump=True` tells paramiko to log hex dumps of protocol traffic at
    DEBUG level.

    Specifying `stderr_level` adds sys.stderr as a logging target with the
    specified log level, unless it's already the target due to `path` being
    None.
    '''
    global _log_hex_dump
    _log_hex_dump = log_hex_dump
    
    path = os_path.abspath(path)

    formatter = logging.Formatter(
            '%(levelname)-.3s [%(asctime)s.%(msecs)03d] thr=%(_threadid)-2d %(name)s: %(message)s',
            '%Y%m%d-%H:%M:%S')

    filt = paramiko.util._pfilter # adds _threadid to all messages

    handlers = []

    if path:
        handler = logging.handlers.RotatingFileHandler(
                path,
                maxBytes=200000,
                backupCount=3,
                encoding='utf-8')
        handler.setLevel(level)
        handler.addFilter(filt)
        handler.setFormatter(formatter)
        handlers.append(handler)

    if not handlers or stderr_level:
        handler = logging.StreamHandler(sys.stdout)
        if stderr_level is None: stderr_level = level
        handler.setLevel(stderr_level)
        handler.addFilter(filt)
        handler.setFormatter(formatter)
        handlers.append(handler)

    def install_handlers(name):
        logger = logging.getLogger(name)
        assert not len(logger.handlers), 'Logger %r already has handlers installed!' % name
        for handler in handlers:
            logger.addHandler(handler)
        logger.setLevel(min(level, stderr_level))
        return logger
    install_handlers('paramiko')
    
    global log, log_initialized
    log = install_handlers(namespace)
    log_initialized = True


class ExecRequestError(Exception):
    def __init__(self, message, original_exception_str=None):
        Exception.__init__(self, message)
        self.original_exception_str = original_exception_str

@contextmanager
def intercept_error(s):
    try:
        yield
    except:
        raise ExecRequestError(s, traceback.format_exc())


def create_data_pump(name, source_read, target_write, target_close):
    '''Windows API makes it really painful or impossible to use polling
    with pipes. So I just create 3 additional threads per POpen.'''
    def pump():
        log.debug('Pump started: %r' % name)
        while True:
            s = source_read(10000000)
            if not s: break
            log.debug('%s pumping: %r' % (name, s))
            target_write(s)
        log.debug('Pump terminated peacefully: %r' % name)
        target_close()
    thread = threading.Thread(target=pump)
    thread.setDaemon(True)
    thread.start()
    return thread

def execute_command(channel, command):
    # we should close our write end of the channel only after
    # _both_ stdout and stderr were closed.
    channel_shutdown_write2_semaphore = threading.Semaphore(value=1)
    def channel_shutdown_write2():
        if not channel_shutdown_write2_semaphore.acquire(False):
            # this is the second decrement!
            log.debug('channel_%d.shutdown_write()' % channel.chanid)
            channel.shutdown_write()

    child = subprocess.Popen(command,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    pump_in = create_data_pump('channel.recv -> child.stdin.write',
            channel.recv,
            child.stdin.write,
            child.stdin.close)

    pump_out = create_data_pump('child.stdout.read -> channel.sendall',
            # can't use child.stdout.read because it blocks even when there _is_ data ready!
            lambda n: os.read(child.stdout.fileno(), n),
            channel.sendall,
            channel_shutdown_write2)

    pump_out_err = create_data_pump('child.stderr.read -> channel.sendall_stderr',
            lambda n: os.read(child.stderr.fileno(), n),
            channel.sendall_stderr,
            channel_shutdown_write2)

    retcode = child.wait()
    log.debug('child returned %d, sending exit status and waiting for pumps' % retcode)
    # wait until all remaining data is sent.
    pump_out.join()
    pump_out_err.join()
    channel.send_exit_status(retcode)
    channel.close()
    # now the inbound pump should die
    pump_in.join()
    log.debug('Executed %r: %d' % (command, retcode))
    return retcode


def parse_public_key(s):
    parts = s.split(None, 2)
    if parts[0] == 'ssh-rsa':
        key_part = parts[1]
    else:
        key_part = parts[0]
    return paramiko.RSAKey(data=base64.decodestring(key_part))


class TransportServer(paramiko.ServerInterface):
    '''Allows a single `exec` ssh call, saves authorized
    user name, channel, and command'''
    def __init__(self, key_to_user, request_queue):
        self.key_to_user = key_to_user
        self.request_queue = request_queue
        self.cached_auth_key = None # be paranoid -- prevent auth attempts with different keys.

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_publickey(self, username, key):
        log.info('Auth attempt with key: ' + hexlify(key.get_fingerprint()))
        if self.cached_auth_key and self.cached_auth_key != key:
            log.error('User tries to use a different key, rejecting.')
            return paramiko.AUTH_FAILED
        real_username = self.key_to_user.get(key)
        if real_username:
            log.info('Allowing %r' % real_username)
            self.username = real_username
            self.cached_auth_key = key
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'publickey'

    def check_channel_exec_request(self, channel, command):
        log.info('exec request on channel_%d: %r' % (channel.chanid, command))
        self.request_queue.put((channel, self.username, command))
        return True

class CustomTransport(paramiko.Transport):
    def __init__(self, sock, request_queue):
        paramiko.Transport.__init__(self, sock)
        self.request_queue = request_queue
    def run(self):
        log.info('transport thread starting')
        try:
            paramiko.Transport.run(self)
        finally:
            self.request_queue.put((None, None, None))
            log.info('transport thread terminating')
    


class RequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        log.info('Request from %s:%d' % self.client_address)
        request_queue = Queue() 
        self.transport = transport = CustomTransport(self.request, request_queue)
        try:
            transport.set_log_channel('sgs.transport')
            transport.add_server_key(self.server.server_key)
            if _log_hex_dump: transport.set_hexdump(True)
            transport_server = TransportServer(self.server.key_to_user, request_queue)
            transport.start_server(server=transport_server)
            while transport.active:
                log.debug('waiting for exec request.')
                try:
                    channel, username, command = request_queue.get(timeout = 30.0)
                except Queue_Empty:
                    log.error('no valid exec request received!')
                    break
                
                if channel is None:
                    log.info('got None instead of exec request, transport has terminated.')
                    break
                    
                self.channel = channel
                try:
                    command = self.prepare_git_cmd(command, username)
                    execute_command(channel, command)
                    # The other side is expected to terminate connection, doing it ourselves
                    # would make it unhappy.
                except ExecRequestError, exc:
                    log.error(exc.message)
                    if exc.original_exception_str:
                        detailed = 'Original exception: ' + exc.original_exception_str
                    else:
                        detailed = ('Traceback (most recent call last):\n' + 
                                ''.join(traceback.format_tb(sys.exc_info()[2]))) 
                    log.error(detailed)
                    channel.send_stderr('fatal: %s\n' % exc.message)
                    break
        finally:
            transport.close()
            log.info('Request handler terminated')

    _git_commands = {
            'git-upload-pack' : 'git upload-pack',
            'git-receive-pack' : 'git receive-pack',
            }

    _fname_str = '([a-zA-Z0-9_]+[a-zA-Z0-9_.-]*)'
    _parse_cmd_rx = re.compile(r'^(?P<command>[a-z-]+) ' +
            "'" + r'/*(?P<path>' + _fname_str + "(/" + _fname_str + r')*)' + "'$")

    def prepare_git_cmd(self, s, username):
        with intercept_error('Invalid command: %r' % s):
            cmd, path = self._parse_cmd_rx.match(s).group('command', 'path')
            cmd = self._git_commands[cmd]
        path = path.strip()
        if path.endswith('.git'):
            path = path[:-4]

        repository = self.server.repositories.get(path)
        if not repository:
            raise ExecRequestError('Repository doesn\'t exist: %r' % path)
        if username not in repository:
            raise ExecRequestError('User %r is not allowed to access repository %r' % (username, path))

        fullpath = os_path.join(self.server.base_directory, 'repositories', path)
        if not os.path.exists(fullpath):
            msg = 'repository %r doesn\'t exist, creating.' % path
            log.warning(msg)
            self.channel.send_stderr('warning: %s\n' % msg)
            if 'upload-pack' in cmd:
                self.channel.send_stderr('warning: don\'t forget that your first push must be `git push --all`.\n')

            with intercept_error('Failed to create repository directory, check server logs.'):
                os.makedirs(fullpath, 0o750)

            with intercept_error('Failed to execute git init, check server logs.'):
                child = subprocess.Popen(
                    args='git init --bare ' + fullpath,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
                output = child.communicate('')
            log.info('Git init: %r' % output[0])
            if child.returncode:
                raise ExecRequestError('git init returned %d' % child.returncode)
        return "%s %s" % (cmd, fullpath)

ServerType = SocketServer.TCPServer

class Server(ServerType):
    def __init__(self, listen_address, listen_port, server_key, users, repositories,
           auto_init_logging = True):

        if auto_init_logging and not log_initialized:
            init_logging()
        self.base_directory = os.getcwd()
        self.configure(users, repositories)            
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.server_key = paramiko.RSAKey.from_private_key(StringIO(server_key))

        # check that all users mentioned in repositories are valid.
        # ...
        ServerType.__init__(self, (listen_address, listen_port), RequestHandler)
        
    def configure(self, users, repositories):
        self.users = users
        self.repositories = repositories
        self.key_to_user = key_to_user = {}
        for name, key in users.iteritems():
            key = parse_public_key(key)
            assert key not in key_to_user, ("Same keys for users %r and %r" % 
                    tuple(sorted((name, key_to_user[key]))))  
            key_to_user[key] = name
        for rep_name, rep_users in repositories.iteritems():
            for user in rep_users:
                assert user in users, 'Unknown user %r in repository %r' % (user, rep_name)  
        


    def serve_forever(self):
        log.info('Server.serve_forever()')
        ServerType.serve_forever(self)


