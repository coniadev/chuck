<?php

declare(strict_types=1);

namespace Conia\Chuck\Config;

use Conia\Chuck\Util\Path as PathUtil;
use ValueError;

class Scripts
{
    protected array $dirs;

    public function __construct()
    {
        $ds = DIRECTORY_SEPARATOR;
        $this->dirs = [realpath(__DIR__ . $ds . '..' . $ds . '..' . $ds . 'bin')];
    }

    protected function preparePath(string $path): string
    {
        $result = PathUtil::realpath($path);

        if (!PathUtil::isAbsolute($result)) {
            $result = realpath($result);
        }

        if ($result) {
            return $result;
        }

        throw new ValueError("Path does not exist: $path");
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
