from stupid_git_server import Server

# Put YOUR OWN private server key here.
server_key = '''
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCh7IXrGYqmRfaGzg8ITRQv2TAgUhamcgRL465/gtdlsiiO1gWo
IE5EAdiNfeTLkJjAjVz9EREF8+fkuwb3k5kLqs2nvd7Hxbnr7WMCGe9zHpWLZONQ
Q9jezNlKXvltTmYi27XYJ/k6av7Qa/VjrXBkiXU3+xmnALMDeNg0vE9kNwIDAQAB
AoGBAJPtYOrHCsOcZvwAg/sxb5/G6xCb7dVhlEtAVcpn3iAqAqN7Iu/Vk6rNhOi+
eqb+Eo7Wln0belHV4aQ0uMi1LrrlqqVJUbCoeLjcVU+7XT+Vx7LK4C5UyaiWDSDu
hAF9Aeg1QeNej7JhMLAz6GCHPjnlO63hozpscAS8c5tL8jIBAkEA02vjR/KxUSwX
rDt3Yfaody5elG49spNmLrY1b40WsUmZMPp57wAwthAIbcJNqy/wgG/DKM2weXGd
c8sQTR+hSQJBAMQQ21yl7BB+osVEXEN6Yv7wpdM/4GZXrh4c040pXMQ6nfRwAkYp
z+Tx/ZvanAfd7ynEYfN428fK1Z2k6rIsWX8CQGDbZFxpyuItGQtGkwLGRZeUHrBR
cOKGtKFhyEk6kdLWrN/LYGEl7Sr7XWErSvnKFJxCl13yHY8FheSueuFaREECQC7A
Qj4+RiLMv21AVqu0ZCScJz5PDef5YkhF4V/YjAkyXPWrO6+VSsAxv6JJJ0ls7xlL
fXu7xtRGFlenulrP3msCQQC16pLGaeKZcW9xATfO+xU5uPwJZAgQR9Sg7WmFrFub
m67AC7e0OnEUuIH8JNLzF21M0uCmYO4tOyJVd1Huanii
-----END RSA PRIVATE KEY-----
'''

listen_address = '127.0.0.1' # allow connections from localhost only!
# listen_address = '' # uncomment to allow connections from all interfaces

listen_port = 27015

# Add users and their public keys. 
users = {
        'test_user' : 'AAAAB3NzaC1yc2EAAAADAQABAAAAgQC2GVRnNff5RjWqeR8F8ZqZkslDsW6Fqqe3cwGTB2zTs088JK/xZxz6u2CztMRDN7FK2Y0jVVktMWTlIB6PhMCs+IYVjo1vdEKuSfifVaInA+lPUwHOju+P76bf9NxFKYGWDxjx8Nuad4kKXz8lYJmC2BpocUftmvBHMfKY7kf/IQ==',        
        'nonexistent_user' : 'AAAAB3NzaC1yc2EAAAADAQABAAAAgQC2GVRnNff5RjWqeR8F8ZqZkslDsW6Fqqe3cwGTB2zTs088JK/xZxz6u2CztMRDN7FK2Y0jVVktMWTlIB6PhMCs+IYVjo1vdEKuSfifVaInA+lPUwHOju+P76bf9NxFKYGWDxjx8Nuad4kKXz8lYJmC2BpocUftmvBHMfKY7kf/ZQ==',        
        }

# Add repositories and lists of users that are allowed full access.
# Repositiories will be stored in $PWD/repositories, '.git' extension 
# (since they will be created as bare) must _not_ be specified here. 
repositories = {
        'test_repo' : ['test_user'],
        'test_repo1' : ['nonexistent_user'],
        }

if __name__ == '__main__':
    server = Server(
            listen_address,
            listen_port,
            server_key,
            users,
            repositories
            )
    #print 'waiting for single request'
    #server.handle_request()
    server.serve_forever()

