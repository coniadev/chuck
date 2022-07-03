<?php

declare(strict_types=1);

namespace Chuck\Template;

use \ArrayIterator;


/**
 * Copied from https://github.com/vimeo/psalm/blob/4.x/tests/Template/ClassTemplateExtendsTest.php
 *
 * @template TKey as array-key
 * @template TValue
 * @template-extends ArrayIterator<TKey, TValue>
 */
class ArrayValue extends ArrayIterator implements ValueInterface
{
    private array $array;

    public function __construct(array $array, int $flags = 0)
    {
        parent::__construct($array, $flags);

        $this->array = $array;
    }

    public function current(): mixed
    {
        $value = parent::current();

        return Wrapper::wrap($value);
    }

    public function raw(): array
    {
        return $this->array;
    }
}
