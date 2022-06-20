<?php

declare(strict_types=1);

namespace Chuck\Util;


class Json
{
    public static function encode(
        mixed $data,
        int $flags = JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    ): string {
        if ($data instanceof \Traversable) {
            return json_encode(iterator_to_array($data), $flags);
        }

        return json_encode($data, $flags);
    }
}
