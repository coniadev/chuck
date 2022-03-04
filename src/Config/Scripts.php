<?php

declare(strict_types=1);

namespace Chuck\Config;


class Scripts extends AbstractPath
{
    protected readonly array $dirs;
    public function __construct(string $root, array $values)
    {
        $this->root = $root;
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
