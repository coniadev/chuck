<?php

declare(strict_types=1);

namespace Chuck\Template;

use \IteratorIterator;

/**
 * Copied from https://psalm.dev/r/ea5148ab32
 * Referenced in https://github.com/vimeo/psalm/issues/4513
 *
 * @template-covariant TKey
 * @template-covariant TValue
 * @template TIterator as \Traversable<TKey, TValue>
 *
 * @template-extends IteratorIterator<TKey, TValue, TIterator>
 */
class IteratorValue extends IteratorIterator
{
    public function current(): mixed
    {
        $value = parent::current();

        return Wrapper::wrap($value);
    }
}
