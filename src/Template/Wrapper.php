<?php

declare(strict_types=1);

namespace Chuck\Template;

use \Traversable;


class Wrapper
{
    /**
     * @param mixed|null $value
     *
     * @psalm-param TValue|null $value
     */
    public static function wrap(mixed $value): mixed
    {
        if (is_string($value)) {
            return new Value($value);
        } elseif (is_numeric($value)) {
            return $value;
        } elseif (is_array($value)) {
            return new ArrayValue($value);
        } elseif ($value instanceof Traversable) {
            return new IteratorValue($value);
        } elseif (is_object($value) && method_exists($value, '__toString')) {
            return new Value((string)$value);
        } else {
            return $value;
        }
    }
}
