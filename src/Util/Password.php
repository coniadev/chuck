<?php

declare(strict_types=1);

namespace Chuck\Util;

use Chuck\ConfigInterface;


class Password
{
    public function __construct(
        protected string $algo = PASSWORD_ARGON2ID,
        protected float $entropy = 40.0,
    ) {
    }

    public static function fromConfig(ConfigInterface $config): self
    {
        $entropy = $config->get('minimum_password_entropy');
        $algo = $config->get('password_algorithm');
        $pw = new self($algo, $entropy);

        return $pw;
    }

    public function strongEnough(string $password): bool
    {
        if (Strings::entropy($password) < $this->entropy) {
            return false;
        }

        return true;
    }

    public function valid(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public function encrypt(string $password): string
    {
        return password_hash($password, $this->algo);
    }
}
