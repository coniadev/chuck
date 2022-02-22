<?php

declare(strict_types=1);

namespace Chuck\Body;


class Json implements Body
{
    public function __construct(
        protected mixed $data,
    ) {
    }

    public function __toString(): string
    {
        // If $context is of type 'object' it should be a Generator
        if ($this->data instanceof \Traversable) {
            return json_encode(iterator_to_array($this->data), JSON_UNESCAPED_SLASHES);
        }

        return json_encode($this->data, JSON_UNESCAPED_SLASHES);
    }

    public function emit(): void
    {
        echo (string)$this;
    }
}
