<?php

declare(strict_types=1);

namespace Chuck\Model;

interface AuthInterface
{
    public static function user();
    public static function permissions();
    public static function logout();

    public static function authenticate(
        array $features,
        string $email,
        string $password,
        bool $remember,
        bool $initSession,
    );

    public static function addSuperuser(array $params): array;
}
