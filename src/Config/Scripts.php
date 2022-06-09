<?php

declare(strict_types=1);

namespace Chuck\Config;


class Scripts
{
    use PathTrait;

    protected readonly array $dirs;

    public function __construct(array $values)
    {
        $this->dirs = array_map(
            fn ($dir) => $this->preparePath($dir),
            array_values($values),
        );
    }

    public function get(): array
    {
        return $this->dirs;
    }
}
