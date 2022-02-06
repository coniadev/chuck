<?php

declare(strict_types=1);

namespace Chuck\Util;

class Arrays
{
    public static function groupBy(array $data, mixed $key): array
    {
        $result = [];

        foreach ($data as $val) {
            $result[$val[$key]][] = $val;
        }

        return $result;
    }

    public static function isAssoc(array $arr): bool
    {
        if ([] === $arr) {
            return false;
        }

        return array_keys($arr) !== range(0, count($arr) - 1);
    }
}
