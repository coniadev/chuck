<?php

declare(strict_types=1);

namespace Chuck\Config;

use \ValueError;


class Templates extends AbstractPath
{
    protected readonly array $dirs;

    public function __construct(string $root, array $values)
    {
        $this->root = $root;

        $dirs = [];

        foreach ($values as $id => $dir) {
            $preparedDir = $this->preparePath($dir);

            if (!is_dir($dir)) {
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
