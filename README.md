# whosthere
A ssh server that knows who you are.

## Try it (it's harmless)

```
ssh whoami.filippo.io
```

## How it works

When it tries to authenticate via public key, ssh sends the server all your public keys, one by one, until the server accepts one. One can take advantage of this to enumerate all the client's installed public keys.

On the other hand, GitHub allows everyone to download users' public keys (which is very handy at times). Ben Cox took advantage of that and [built a dataset of all GitHub public keys](https://blog.benjojo.co.uk/post/auditing-github-users-keys).

This is a pretty vanilla `golang.org/x/crypto/ssh` Go server that will advertise `(publickey,keyboard-interactive)` authentication. It won't accept any public key, but it will take a note of them. Once the client is done with public keys, it will try `keyboard-interactive`, which the server will accept without sending any challenge, so that no user interaction is required.

Then it just lets you open a shell+PTY, uses the public keys and Ben's database to find your username, asks the GitHub API your real name, prints all that and close the terminal.

All the interesting bits are in [server.go](https://github.com/FiloSottile/whosthere/blob/master/src/ssherver/server.go).

## How do I stop it?

If this behavior is problematic for you, you can tell ssh not to present your public keys to the server by default.

Add these lines at the end of your `~/.ssh/config` (after other "Host" directives)

```
Host *
    PubkeyAuthentication no
    IdentitiesOnly yes
```

And then specify what keys should be used for each host

```
Host example.com
    PubkeyAuthentication yes
    IdentityFile ~/.ssh/id_rsa
    # IdentitiesOnly yes # Enable ssh-agent (PKCS11 etc.) keys
```

If you want you can use different keys so that they can't be linked together

```
Host github.com
    PubkeyAuthentication yes
    IdentityFile ~/.ssh/github_id_rsa
```


## Configuration

To run whosthere requires some setup.


### `config.yml`

A config.yml file is read for configuration.  Below is an example:

    HostKey : |
        -----BEGIN RSA PRIVATE KEY-----
        ** You can get this from an existing RSA/DSA keypair **
        -----END RSA PRIVATE KEY-----
    UserAgent : "whosthere-changeme"
    GitHubID : "Client ID"
    GitHubSecret : "Client Secret"
    MySQL : "user:password@/dbname"
    Listen: ":2222"


### MySQL Configuration

The code looks for a MySQL server to query against.  This can be populated from GitHub as described [here](https://blog.benjojo.co.uk/post/auditing-github-users-keys)

I created the following table and it seems to work:

    CREATE TABLE keystore (
    id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(255) CHARACTER SET utf8,
    `N` TEXT CHARACTER SET utf8
    );
