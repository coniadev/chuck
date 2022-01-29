<?php

declare(strict_types=1);

namespace Chuck;

class Token
{
    protected string $token;
    protected string $secret;

    public function __construct(string $secret, string $token = null)
    {
        $this->secret = $secret;

        if ($token === null) {
            $this->token = bin2hex(random_bytes(16));
        } else {
            $this->token = $token;
        }
    }

    public function get(): string
    {
        return $this->token;
    }

    public function hash(): string
    {
        return hash_hmac('sha256', $this->token, $this->secret);
    }
}
