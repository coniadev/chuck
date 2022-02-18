<?php

declare(strict_types=1);

namespace Chuck;


class Stream
{
    protected object|string $consumer;

    public function __construct(
        protected int $handle,
        object|string $consumer
    ) {
        $this->consumer = $consumer;
    }

    public function consume(): void
    {
        if (is_callable($this->consumer)) {
            ($this->consumer)($this->handle);
        } else {
            throw new \ValueError('Stream consumer is not callable');
        }
    }

    public function __toString(): string
    {
        return 'TODO: naus mit';
    }
}
