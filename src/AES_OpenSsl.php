<?php

namespace Encrypt;

use Encrypt\Exception\CipherMethodNotSupportException;
use Encrypt\Exception\IvLenInvalidException;

class AES_OpenSsl
{
    private $method;

    private $secret_key;

    private $iv;

    private $ivLen = 0;

    private $options;

    public function __construct($key = 'json-gao', $method = 'AES-128-ECB', $options = 0)
    {
        Common::checkOpenSSl();
        $this->secret_key = $key;
        $methods          = openssl_get_cipher_methods();
        if (!in_array($method, $methods)) {
            throw new CipherMethodNotSupportException("cipher [$method] not support, support methods: " . implode("\t", $methods));
        }
        $this->method  = $method;
        $this->ivLen   = openssl_cipher_iv_length($method);
        $this->options = $options;
    }

    public function setIv($iv)
    {
        if ($iv) {
            $this->checkIv($iv);
            $this->iv = $iv;
        }
    }

    public function getIv()
    {
        if ($this->iv) {
            return $this->iv;
        } else {
            $this->iv = openssl_random_pseudo_bytes($this->ivLen);
        }
        $this->checkIv($this->iv);

        return $this->iv ? $this->iv : '';
    }

    private function checkIv($iv)
    {
        $ivLen = strlen($iv);
        if ($ivLen != $this->ivLen) {
            throw new IvLenInvalidException("method {$this->method}, iv length invalid, expect[{$this->ivLen}], actual[{$ivLen}]");
        }

    }

    public function encrypt($data)
    {
        return openssl_encrypt($data, $this->method, $this->secret_key, $this->options, $this->getIv());
    }

    public function decrypt($data)
    {
        return openssl_decrypt($data, $this->method, $this->secret_key, $this->options, $this->getIv());
    }
}