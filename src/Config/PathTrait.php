<?php

declare(strict_types=1);

namespace Conia\Chuck\Config;

use \ValueError;
use Conia\Chuck\Util\Path as PathUtil;


trait PathTrait
{
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
}
