<?php

declare(strict_types=1);

namespace Chuck\Model;

use PDO;

use Chuck\ConfigInterface;
use Chuck\RequestInterface;


abstract class Model
{
    protected static RequestInterface $request;
    protected static ConfigInterface $config;


    public static function init(RequestInterface $request): void
    {
        self::$request = $request;
        self::$config = $request->config;
    }

    public static function db(int $fetchMode = PDO::FETCH_ASSOC): Database
    {
        static $db = null;

        if ($db === null) {
            $db = new Database(self::$request, $fetchMode);
        }

        return $db;
    }

    public static function encode(int $id): string
    {
        return self::db()->encode($id);
    }

    public static function encodeList(
        array $list,
        $key,
        bool $asUid = false
    ): iterable {
        return self::db()->encodeList($list, $key, $asUid);
    }

    public static function decode(string $uid): int
    {
        return self::db()->decode($uid);
    }

    public static function toArray(?iterable $list): array
    {
        if (is_array($list)) {
            return $list;
        }

        try {
            return iterator_to_array($list);
        } catch (\TypeError $e) {
            return [];
        }
    }

    public static function hashsecret(): string
    {
        return self::$request->config->get('hashsecret');
    }
}
