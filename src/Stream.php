<?php

declare(strict_types=1);

namespace Chuck;


class Stream
{
    protected callable $consumer;

    public function __construct(
        protected int $handle,
        callable $consumer
    ) {
        $this->consumer = $consumer;
    }

    public function consume(): void
    {
        ($this->consumer)($this->handle);
    }
}
