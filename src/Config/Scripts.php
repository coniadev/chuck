<?php

declare(strict_types=1);

namespace Chuck\Config;


class Scripts
{
    use PathTrait;

    protected readonly array $dirs;

    public function __construct(
        protected readonly string $root,
        array $values,
        bool $debug = true
    ) {
        $this->dirs = array_map(
            fn ($dir) => $this->preparePath($dir, $debug),
            array_values($values),
        );
    }

    public function get(): array
    {
        return $this->dirs;
    }
}
