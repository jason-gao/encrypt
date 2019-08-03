<?php

namespace Encrypt;

use Encrypt\Exception\ExtensionNotExistException;

class Common{

    public static function checkOpenSSl()
    {
        if (!extension_loaded('openssl')) {
            throw new ExtensionNotExistException('openssl extension not install!!');
        }
    }

    public static function mustString($str){
        if(!is_string($str)){
            throw new NotStringException('must be string type!!');
        }
    }

    public static function getCurTime(){
        $d = date('Y-m-d H:i:s');

        return $d;
    }
}