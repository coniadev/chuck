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
class ArrayValue extends ArrayIterator
{
    public function current(): mixed
    {
        $value = parent::current();

        return Wrapper::wrap($value);
    }
}
