# whoami.filippo.io
知道你是谁的ssh服务器.

## Try it (it's harmless)

```
ssh whoami.filippo.io
```

ED25519钥匙指纹是`SHA256:qGAqPqtlvFBCt4LfMME3IgJqZWlcrlBMxNmGjhLVYzY`.  
RSA钥匙指纹是`SHA256:O6zDQjQws92wQSA41wXusKquKMuugPVM/oBZXNmfyvI`.

## 运行原理

当ssh尝试通过公钥进行身份验证时，它会逐个向服务器发送您的所有公钥，直到服务器接受一个为止。可以利用这一点枚举所有客户端安装的公钥.

另一方面，GitHub允许每个人下载用户的公钥（这有时非常方便）。Ben Cox利用了这一点[构建了一个包含所有GitHub公钥的数据集](https://blog.benjojo.co.uk/post/auditing-github-users-keys).

这是一种很基础的`golang.org/x/crypto/ssh` Go服务器，将公布`（公钥，键盘交互）`身份验证。它不会接受任何公钥，但会记录它们。一旦客户端使用了公钥，它将尝试“键盘交互”，服务器将接受它而不发送任何质询，因此不需要用户交互.

然后，它只允许您打开一个shell+PTY，使用公钥和Ben的数据库来查找您的用户名，向GitHub API询问您的真实姓名，打印所有内容并关闭终端.  

所有有趣的部分都在 [server.go](https://github.com/FiloSottile/whosthere/blob/master/server.go).

## 如何停止它？

如果这种行为对您来说有问题，您可以告诉ssh默认情况下不要向服务器提供您的公钥.

将这些行添加到`~/.ssh/config`之后 (在其他 "Host" 指令之后)

```
Host *
    PubkeyAuthentication no
    IdentitiesOnly yes
```

然后指定每个主机应使用哪些密钥

```
Host example.com
    PubkeyAuthentication yes
    IdentityFile ~/.ssh/id_rsa
    # IdentitiesOnly yes # Enable ssh-agent (PKCS11 etc.) keys
```

如果需要，可以使用不同的键，使它们不能链接在一起

```
Host github.com
    PubkeyAuthentication yes
    IdentityFile ~/.ssh/github_id_rsa
```
