<?php

declare(strict_types=1);

namespace Conia\Chuck\Util;

use ValueError;

class Crypt
{
    protected static function isCcmGcm(string $cipherAlgo): bool
    {
        return strpos($cipherAlgo, 'ccm') !== false ||
            strpos($cipherAlgo, 'gcm') !== false;
    }

    public static function encrypt(
        string $data,
        string $key,
        string $cipherAlgo = 'aes-256-gcm',
        int $taglen = 16
    ): string|false {
        if (!in_array($cipherAlgo, openssl_get_cipher_methods())) {
            throw new ValueError("Cipher algorithm '$cipherAlgo' is not available");
        }

        $cipherAlgo = strtolower($cipherAlgo);
        $ivlen = openssl_cipher_iv_length($cipherAlgo);
        $iv = openssl_random_pseudo_bytes($ivlen);
        $tag = ''; // Passed as reference and filled by openssl_encrypt

        if (self::isCcmGcm($cipherAlgo)) {
            $encrypted = openssl_encrypt($data, $cipherAlgo, $key, 0, $iv, $tag, '', $taglen);
        } else {
            $encrypted = openssl_encrypt($data, $cipherAlgo, $key, 0, $iv);
        }

        $cipherText = $iv . $tag . $encrypted;

        return $cipherText;
    }

    public static function decrypt(
        string $cipherText,
        string $key,
        string $cipherAlgo = 'aes-256-gcm',
        int $taglen = 16
    ): string|false {
        if (!in_array($cipherAlgo, openssl_get_cipher_methods())) {
            throw new ValueError("Cipher algorithm '$cipherAlgo' is not available");
        }

        $ivlen = openssl_cipher_iv_length($cipherAlgo);
        $iv = substr($cipherText, 0, $ivlen);

        if (self::isCcmGcm($cipherAlgo)) {
            $tag = substr($cipherText, $ivlen, $taglen);
            $encrypted = substr($cipherText, $ivlen + $taglen);

            return openssl_decrypt($encrypted, $cipherAlgo, $key, 0, $iv, $tag);
        }

        $encrypted = substr($cipherText, $ivlen);

        return openssl_decrypt($encrypted, $cipherAlgo, $key, 0, $iv);
    }
}
