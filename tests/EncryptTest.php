<?php

namespace Tests;

use Encrypt\AES_OpenSsl;
use Encrypt\Rc4;
use Encrypt\Rsa_OpenSsl;

class EncryptTest extends TestCase
{

    public function testAesOpenssl()
    {
        $data = 'my message';
        $d    = is_array($data) ? json_encode($data) : $data;
        var_dump("d\t$d");
        $key = 'secret key 123';
        //数据很小，尤其是16字节一下ecb，数据量大的用cbc
//        $method = 'AES-128-ECB';
//        $method = 'AES-256-ECB';
//        $method = 'AES-128-CBC';
        $method = 'AES-256-CBC';
        var_dump("method\t$method");
        $aes = new AES_OpenSsl($key, $method);
        $aes->setIv(str_repeat(1, 16));

        //en
        $enc = $aes->encrypt($d);
        var_dump("enc\t$enc\n");

        //de
        $deEncData = $aes->decrypt($enc);
        var_dump("deEncData\t$deEncData\n");
        $this->assertEquals('my message', $deEncData);
    }

    public function testRc4()
    {
        $key        = "0123456789abcdef";
        $plaintext  = "Hello World!#*.&@()+-";
        $cipherText = Rc4::rc4($key, $plaintext);
        $decrypted  = Rc4::rc4($key, $cipherText);
        echo "\n" . $decrypted . " - " . $plaintext . "\n";

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testRc4CStyle()
    {
        $key        = "0123456789abcdef";
        $plaintext  = "Hello World!#*.&@()+-";
        $cipherText = Rc4::rc4CStyle($key, $plaintext);
        $decrypted  = Rc4::rc4CStyle($key, $cipherText);
        echo "\n" . $decrypted . " - " . $plaintext . "\n";

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testRasOpenssl()
    {
        $key = Rsa_OpenSsl::makePubPriKey();
//        var_dump($key);

        $rsa  = new Rsa_OpenSsl($key['publicKey'], $key['privateKey']);
        $data = "hello中国";
        //公钥加密
        $encPub = $rsa->publicEncrypt($data);
        var_dump("encPub\t$encPub");
        //私钥解密
        $dePri = $rsa->privateDecrypt($encPub);
        var_dump("dePri\t$dePri");

        //私钥加密
        $encPri = $rsa->privateEncrypt($data);
        var_dump("encPri\t$encPri");
        //公钥解密
        $dePub = $rsa->publicDecrypt($encPri);
        var_dump("dePub\t$dePub");

    }
}
