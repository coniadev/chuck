<?php

declare(strict_types=1);

namespace Chuck\Body;


class Text implements Body
{
    public function __construct(protected string $text)
    {
    }

    public function __toString(): string
    {
        return $this->text;
    }

    public function emit(): void
    {
        echo $this->text;
    }
}
