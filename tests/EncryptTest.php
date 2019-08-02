<?php

namespace Tests;

use Encrypt\AES_OpenSsl;

class EncryptTest extends TestCase{

    public function testAesOpenssl(){
        $data = [1,2,3, time()];
        $d = json_encode($data);
        $key = 'abc#123';
        $aes = new AES_OpenSsl($key);

        //en
        $enc = $aes->encrypt($d);
        var_dump($enc);

        //de
        $deEncData = $aes->decrypt($enc);
        var_dump($deEncData);

        $this->assertEquals(1, json_decode($deEncData, 1)[0]);
    }
}
