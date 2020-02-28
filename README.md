# whoami.filippo.io
An ssh server that knows who you are.

## Try it (it's harmless)

```
ssh whoami.filippo.io
```

ED25519 key fingerprint is `SHA256:qGAqPqtlvFBCt4LfMME3IgJqZWlcrlBMxNmGjhLVYzY`.  
RSA key fingerprint is `SHA256:O6zDQjQws92wQSA41wXusKquKMuugPVM/oBZXNmfyvI`.

## How it works

When ssh tries to authenticate via public key, it sends the server all your public keys, one by one, until the server accepts one. One can take advantage of this to enumerate all the client's installed public keys.

On the other hand, GitHub allows everyone to download users' public keys (which is very handy at times). Ben Cox took advantage of that and [built a dataset of all GitHub public keys](https://blog.benjojo.co.uk/post/auditing-github-users-keys).

This is a pretty vanilla `golang.org/x/crypto/ssh` Go server that will advertise `(publickey,keyboard-interactive)` authentication. It won't accept any public key, but it will take a note of them. Once the client is done with public keys, it will try `keyboard-interactive`, which the server will accept without sending any challenge, so that no user interaction is required.

Then it just lets you open a shell+PTY, uses the public keys and Ben's database to find your username, asks the GitHub API your real name, prints all that and closes the terminal.  

All the interesting bits are in [server.go](https://github.com/FiloSottile/whosthere/blob/master/server.go).

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
