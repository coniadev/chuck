<?php

declare(strict_types=1);

namespace Chuck\Util;

use Chuck\ConfigInterface;

const CHUCK_DEFAULT_PW_ENTROPY = 40.0;


class Password
{
    public function __construct(
        protected string|int|null $algo = null,
        protected float $entropy = CHUCK_DEFAULT_PW_ENTROPY,
    ) {
        if ($this->algo === null) {
            $this->algo = self::hasArgon2() ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        }
    }

    public static function fromConfig(ConfigInterface $config): self
    {
        $entropy = $config->get('password.entropy', CHUCK_DEFAULT_PW_ENTROPY);
        $defaultAlgo = self::hasArgon2() ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        $algo = $config->get('password.algorithm', $defaultAlgo);
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

    public static function hasArgon2(): bool
    {
        return in_array('argon2id', password_algos());
    }
}
