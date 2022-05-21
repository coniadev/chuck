<?php

declare(strict_types=1);

namespace Chuck\Config;

use \ValueError;


class Templates
{
    use PathTrait;

    protected readonly array $dirs;

    public function __construct(
        protected readonly string $root,
        array $values,
        bool $debug = false
    ) {
        $dirs = [];

        foreach ($values as $id => $dir) {
            $preparedDir = $this->preparePath($dir, $debug);

            if (!is_dir($preparedDir)) {
                throw new ValueError("Template directory does not exists: $dir");
            }

            $dirs[$id] = $preparedDir;
        }

        $this->dirs = $dirs;
    }

    public function get(): array
    {
        return $this->dirs;
    }
}
