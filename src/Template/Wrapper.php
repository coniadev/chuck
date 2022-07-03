<?php

declare(strict_types=1);

namespace Chuck\Template;

use \Traversable;
use \Stringable;


class Wrapper
{
    public static function wrap(mixed $value): mixed
    {
        if (is_string($value)) {
            return new Value($value);
        } elseif ($value instanceof ValueInterface) {
            // Don't wrap already wrapped values again
            return $value;
        } elseif (is_numeric($value)) {
            return $value;
        } elseif (is_array($value)) {
            return new ArrayValue($value);
        } elseif ($value instanceof Traversable) {
            return new IteratorValue($value);
        } elseif ($value instanceof Stringable) {
            return new Value($value);
        } else {
            return $value;
        }
    }
}
