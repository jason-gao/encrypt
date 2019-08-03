<?php

namespace Encrypt;

use Encrypt\Exception\CipherMethodNotSupportException;

class AES_OpenSsl
{
    private $method;

    private $secret_key;

    private $iv;

    private $options;

    public function __construct($key = 'json-gao', $method = 'AES-128-ECB', $options = 0)
    {
        Common::checkOpenSSl();
        $this->secret_key = $key;
        $methods          = openssl_get_cipher_methods();
        if (!in_array($method, $methods)) {
            throw new CipherMethodNotSupportException("cipher [$method] not support, support methods: " . implode("\t", $methods));
        }
        $this->method = $method;
        $ivLen        = openssl_cipher_iv_length($method);
        $this->iv     = openssl_random_pseudo_bytes($ivLen);
        if (!$this->iv) {
            $this->iv = '';
        }
        $this->options = $options;
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