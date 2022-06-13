<?php

declare(strict_types=1);

namespace Chuck\Config;


class Scripts
{
    use PathTrait;

    protected array $dirs;

    public function __construct()
    {
        $ds = DIRECTORY_SEPARATOR;
        $this->dirs = [realpath(__DIR__ . $ds . '..' . $ds . '..' . $ds . 'bin')];
    }

    public function add(string $path): void
    {
        array_unshift($this->dirs, $this->preparePath($path));
    }

    public function get(): array
    {
        return $this->dirs;
    }
}
