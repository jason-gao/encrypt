<?php

namespace Encrypt;

/**
 * Class Rsa_OpenSsl
 * @package Encrypt
 *
 *
 * -----BEGIN PUBLIC KEY-----
 * MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5I2oHJF0y6lU1SX6dU5o
 * lMQVFxtTZTPkz7Ww536/2VpRgJ4h1G4cVFiCnka4NnXuH4eHTgcVb2cEMqpAE27R
 * ivn0OrBwkY2OHhTkfMvHCq/ZhX1XmrwhwcfAtKsn1PNzyj1M2jpBnCcxEdRb10in
 * /l45+UKTi3sLVr5EdZdMkZ5qo4M0QkOtWhLQ+LvEYEGyauQpD777OApiUQpPZnzf
 * i0B1LuNGvtmXPOXUnpl4T8L6BtdrFrnn5/K+Wj6Lo1DpN5qFYddiY55XhKCuPLxg
 * s/HT8+/Fr2OeOcTzQ4Grxo7LOIy/vVHTMj2BZ0gMj8DN9YfHQYMndUhPf0e7Y+dy
 * LQIDAQAB
 * -----END PUBLIC KEY-----
 *
 *
 *
 * -----BEGIN PRIVATE KEY-----
 * MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDkjagckXTLqVTV
 * Jfp1TmiUxBUXG1NlM+TPtbDnfr/ZWlGAniHUbhxUWIKeRrg2de4fh4dOBxVvZwQy
 * qkATbtGK+fQ6sHCRjY4eFOR8y8cKr9mFfVeavCHBx8C0qyfU83PKPUzaOkGcJzER
 * 1FvXSKf+Xjn5QpOLewtWvkR1l0yRnmqjgzRCQ61aEtD4u8RgQbJq5CkPvvs4CmJR
 * Ck9mfN+LQHUu40a+2Zc85dSemXhPwvoG12sWuefn8r5aPoujUOk3moVh12JjnleE
 * oK48vGCz8dPz78WvY545xPNDgavGjss4jL+9UdMyPYFnSAyPwM31h8dBgyd1SE9/
 * R7tj53ItAgMBAAECggEAWGtdIEA9mRTXVuascHl3CCabqibOKpba7Gh0Gfr1KZdB
 * dKq4l8BJgXAEiEr/tUIGb3g1JkCjUEfgXeFzjJEQy91LWPEte4Hx+z1F7+m+BSpm
 * 0rfdDmW+AYPPz5VvgXj10MXKV5q2Cz02RJmNNkpLg6LcdswE3K8rgdF2FrAD1Uli
 * +KNkvHBReEYsshKlPqzZEvxkKIrK8v5hLDc8ljV1Jx1CDe+oRa8v/mN7MJLhYg9Z
 * rTjODWkhIZhOJ1lrD2EyyEJFbwsip5i+azrLJKf2D16RBXq2yqYrY3zHu9w6mVVw
 * ky99OokaxFvVJ4KUTuj4RgtiFxVTUQv1Uq+DALJpAQKBgQD0ecDDp/ZukKn1nKAN
 * EDMyVT/2Oe4ytydTsNVzAzkTkQoRk9rIWk/f3hlifzT0WV0xf8z6dCkBSQsCNUtI
 * f34ZfM8Wz19XgIz2iMsOSvzlu1b7G/woulF/8Lv5wpP2IEuuPToKlQ0nAKGnRG08
 * 2FInie5ovRmZscX/ogiLq/bkzQKBgQDvU8JtDN9E9cy6E9ck2iSDrkYAgJEd01Nq
 * R9VLZmom2EhE6zTboqPe70rYOSOsPXkm7c2u86IZyP7MkMpyKfCOPu8T2OE8hD4g
 * 8tsneOAbUZLTeLLtx8QMNw+GffXdAxgFIFFkDsetsY1gvHQQ3iGeNhacgh24l27H
 * 1KK/CJnC4QKBgEc/5KohHXUDvETUrOChxAn7RnTgVUd6kX+Wnd6zJcNKFgEhcjXJ
 * /FVmSUengytjkAGJGZg0mm7Bdu/h0FsErR+IfGJNdZ/u2yZOn78+o43gl2z/rvG/
 * u1jqNB6KUsz8hJH3Th8faYHgcTxqeNuuv+K+FDl6QyfD48yo0IzERWRRAoGBAKwv
 * d++bVjs4GQ47XguegqzWwnh0B3QM6bPKcLPpwC+oZf5ntsTac8neIdwE6BxwseyH
 * JPddQ+AHUwJ8nZqbf/3nW3zNCefPQR/VekUg2yPsgZVx/lHC6tLa/mmF0FEte6ec
 * g9JYK+NUneHeVCcamddJFOWPW7DGCqbs3hZRKschAoGAN33G0RsgP/rfO6ktbWA3
 * MIX1IqVVJQGtNXnPvPQkgdSvQCdeS8sWpEZSayIrB9bXW4fe5j/T7L2yXSptcs5z
 * fBUwQOG1KFA8fnsJbu9mH54JZo154vFrMBRvxQp/5QhvBZx3+JkjyyTMLrsZ+BSf
 * 39spS38RvoMXVUkMhABsy4g=
 * -----END PRIVATE KEY-----
 */
class Rsa_OpenSsl
{

    private $privateKey = '';

    private $publicKey = '';

    private $base64 = true;

    public function __construct($publicKey = '', $privateKey = '', $base64 = true)
    {
        Common::checkOpenSSl();
        $this->setPublicKey($publicKey);
        $this->setPrivateKey($privateKey);
        $this->setBase64($base64);
    }

    public static function makePubPriKey()
    {
        Common::checkOpenSSl();
        $resource = openssl_pkey_new();
        openssl_pkey_export($resource, $privateKey);
        $detail    = openssl_pkey_get_details($resource);
        $publicKey = $detail['key'];

        return [
            'publicKey'  => $publicKey,
            'privateKey' => $privateKey,
            'time'       => Common::getCurTime()
        ];
    }

    public function setPublicKey($key)
    {
        $this->publicKey = $key;
    }

    public function setPrivateKey($key)
    {
        $this->privateKey = $key;
    }

    public function setBase64($base64)
    {
        $this->base64 = $base64;
    }

    public function getBase64()
    {
        return $this->base64;
    }

    public function getPublicKey()
    {
        return $this->publicKey;
    }

    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    //公钥加密
    public function publicEncrypt($data)
    {
        openssl_public_encrypt($data, $encrypted, $this->getPublicKey());

        return $encrypted ? ($this->getBase64() ? base64_encode($encrypted) : $encrypted) : false;
    }

    //私钥解密
    public function privateDecrypt($encrypted)
    {
        openssl_private_decrypt($this->getBase64() ? base64_decode($encrypted) : $encrypted, $decrypted, $this->getPrivateKey());

        return $decrypted ? $decrypted : false;
    }

    //私钥加密
    public function privateEncrypt($data)
    {
        openssl_private_encrypt($data, $encrypted, $this->getPrivateKey());

        return $encrypted ? ($this->getBase64() ? base64_encode($encrypted) : $encrypted) : false;
    }

    //公钥解密
    public function publicDecrypt($encrypted)
    {
        openssl_public_decrypt($this->getBase64() ? base64_decode($encrypted) : $encrypted, $decrypted, $this->getPublicKey());

        return $decrypted ? $decrypted : false;
    }


}