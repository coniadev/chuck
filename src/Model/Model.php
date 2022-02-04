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

    public function encode(int $id): string
    {
        return $this->hash->encode($id);
    }

    public function encodeList(
        iterable $list,
        array|string $hashKey,
        bool $asUid = false
    ): \Generator {
        if (is_array($hashKey)) {
            foreach ($list as $item) {
                foreach ($hashKey as $hk) {
                    $item[$hk] = $this->hash->encode($item[$hk]);
                }
                yield $item;
            }
        } else {
            if ($asUid) {
                $targetKey = 'uid';
            } else {
                $targetKey = $hashKey;
            }

            foreach ($list as $item) {
                $item[$targetKey] = $this->hash->encode($item[$hashKey]);
                yield $item;
            }
        }
    }

    public function decode(string $uid): int
    {
        return $this->hash->decode($uid);
    }
}
