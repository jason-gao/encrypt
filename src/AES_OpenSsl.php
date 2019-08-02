<?php

namespace Encrypt;

use Encrypt\Exception\ExtensionException;

class AES_OpenSsl
{
    private $method;

    private $secret_key;

    private $iv;

    private $options;

    public function __construct($key, $method = 'AES-128-ECB', $iv = '', $options = 0)
    {
        $this->checkEnv();
        $this->secret_key = isset($key) ? $key : 'json-gao';
        $this->method     = $method;
        $this->iv         = $iv;
        $this->options    = $options;
    }

    private function checkEnv()
    {
        if (!extension_loaded('openssl')) {
            throw new ExtensionException('openssl extension not install!!');
        }
    }

    public function encrypt($data)
    {
        return openssl_encrypt($data, $this->method, $this->secret_key, $this->options, $this->iv);
    }

    public function decrypt($data)
    {
        return openssl_decrypt($data, $this->method, $this->secret_key, $this->options, $this->iv);
    }
}