'use strict';

var assert  = require("assert");

var { AESEncrypt, AESDecrypt, RSAEncrypt, RSADecrypt, EncryptedCommunicationBrowser } = require('../src/securehttp');

const KEY = 'xxxxxxxxxxxxxxxx';

const MESSAGE = 'hello world';

const PUBKEY = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBVAczL3sjEVewm0+XWo/g1Qbq
M9veVKmETH37CqJrTB/TEg9t/HyRtPCUCnx6sj0xyQPTBRrKZn4D69zqNiRwBOPz
a6E8QhmUPTtRam4nFbUMj7n797gcrUpT2GSdA94Ags3xB0ucCHi/nWEZyfUxGZjb
6L3+3NgPoCQknwoV8wIDAQAB
-----END PUBLIC KEY-----`

const PRIVKEY = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDBVAczL3sjEVewm0+XWo/g1QbqM9veVKmETH37CqJrTB/TEg9t
/HyRtPCUCnx6sj0xyQPTBRrKZn4D69zqNiRwBOPza6E8QhmUPTtRam4nFbUMj7n7
97gcrUpT2GSdA94Ags3xB0ucCHi/nWEZyfUxGZjb6L3+3NgPoCQknwoV8wIDAQAB
AoGAZ/g1qwxU76YK/7p20lHs4KAQCPH8w5PKWpD8i37LnGKjFtM2oxLPN1kUrLj6
+s1SZazSNrEfGEyIZrl45Chb7UcZu2B8ZNve7LpZAPrhkGXv48OJioTsVGYpBEYG
viTcrBKHfNT9XfkDwSNR9y4mPDf92vpUYboNox9IcFESzPECQQDf9PDsDnd7zgzZ
CGDCnWeVqS/+nEZtZckTlrzsajj/9UmvnvUgHS/o6eQZQPTroB74FMujLL9HShNI
F75Mm+7LAkEA3P06ZW009rqvKf3g1E6sHEQvOp7rCD3grLbVSQ8Y9wogYDTZqON8
VvrmawIBHfMkdlLCcU/+QsrWajIZkMOoeQJAHHSb0/J2ngVtPnpBCRlE2xA3J+ul
SysepF2HvaY1fdglt6nDzYPH3ZkyQT8un22l4bGKuj3qQ92Wm5dgt40shwJBALJT
sgzo3EWBjhovoX8RYTeKGiaO2RCUhjo5a9GB2l53kHqyCzaLI+o4mzmcq3QUocbN
r9SqfX4+mlmlxhWYndkCQQCuA/8YrkMrQIZWlErBRldtV1gqoToyexsJjxAuLP0d
XM5dHfZ/oq/dqXCUN/iMRG1qxaA7qT4kYb+n6Nb3JYxG
-----END RSA PRIVATE KEY-----`

RSADecrypt(PRIVKEY, 'ftgeBaOm9Rgx3NY4LTqKcfVuY7N6QmgJrB9yC+wjSrvnFvWshX6VBAOVUf9938jAWUZPtCaHnTcc69Y3Cnb+zmTnijV231KpPOoGRUWAZdA+fT19sa9HOFYlIQq4EmjBMbsn19db69jUoIb5c0yxCsLOKXyL7DoYzEM600Tbo6U=')

assert.equal(MESSAGE, RSADecrypt(PRIVKEY, 'ftgeBaOm9Rgx3NY4LTqKcfVuY7N6QmgJrB9yC+wjSrvnFvWshX6VBAOVUf9938jAWUZPtCaHnTcc69Y3Cnb+zmTnijV231KpPOoGRUWAZdA+fT19sa9HOFYlIQq4EmjBMbsn19db69jUoIb5c0yxCsLOKXyL7DoYzEM600Tbo6U='))

assert.equal(MESSAGE, RSADecrypt(PRIVKEY, 'pQDDd2O4SvH2GACwZ1pN4N/xWcR1M2Jh420tZLr/wObEMhg7f8UU+gau2TNZ4Q9XnX6zXuA0flEor/BaE0WbM9UcXgt9/8UDuz90WrFLL1R850NRn6gPoctY0etCgOK87vVpeC0WN9bOjKrXkfOhWxRTKKSL0viFSgzYsH9O0OU='))

assert.equal(MESSAGE, AESDecrypt(KEY, 'DBE7+U2DiYbeIsHtFt7a3w=='))

assert.equal(MESSAGE, AESDecrypt(KEY, AESEncrypt(KEY, MESSAGE)))

assert.equal(MESSAGE, RSADecrypt(PRIVKEY, RSAEncrypt(PUBKEY, MESSAGE)))

assert.equal(false, AESEncrypt('a', MESSAGE))
assert.equal(false, AESDecrypt('a', MESSAGE))
assert.equal('', AESDecrypt(KEY, '#DBE7+U2DiYbeIsHtFt7a3w==#'))

var ecb = new EncryptedCommunicationBrowser(PUBKEY);
assert.equal(32, ecb.AESKey.length)
assert.ok(ecb.PublicKey === PUBKEY)
assert.equal(false, ecb.browserEncrypt())
assert.equal(false, ecb.browserEncrypt("a"))
assert.equal(false, ecb.browserEncrypt(123))
assert.equal(false, ecb.browserEncrypt(null))
assert.equal(false, ecb.browserEncrypt(["a",]))
assert.equal(false, ecb.browserEncrypt({}))
assert.equal(false, ecb.browserEncrypt({}, ''))
assert.equal(false, ecb.browserEncrypt({}, []))
assert.equal(false, ecb.browserEncrypt({}, 123))
assert.equal(false, ecb.browserEncrypt({}, null))
assert.equal("object", typeof ecb.browserEncrypt({a:1,b:2,c:3}, 'a'))
var msg = {a:1}
var ed = ecb.browserEncrypt(msg,'a');
var ek = RSADecrypt(PRIVKEY, ed.key);
var en = AESDecrypt(ek, ed.value)
assert.ok(typeof ed === 'object')
assert.equal(32, ek.length)
assert.notEqual('', en)
assert.doesNotThrow(() => JSON.parse(en), SyntaxError)
assert.equal(msg.a, JSON.parse(en).a)
