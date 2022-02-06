<?php

declare(strict_types=1);

namespace Chuck\Util;

use Chuck\ConfigInterface;

const CHUCK_DEFAULT_PW_ENTROPY = 40.0;


class Password
{
    public function __construct(
        protected string|int|null $algo = PASSWORD_ARGON2ID,
        protected float $entropy = CHUCK_DEFAULT_PW_ENTROPY,
    ) {
    }

    public static function fromConfig(ConfigInterface $config): self
    {
        $entropy = $config->get('minimum_password_entropy', CHUCK_DEFAULT_PW_ENTROPY);
        $algo = $config->get('password_algorithm', PASSWORD_ARGON2ID);
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

    public function hash(string $password): string
    {
        return password_hash($password, $this->algo);
    }
}
