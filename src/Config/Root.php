<?php

declare(strict_types=1);

namespace Chuck\Config;

use \ValueError;
use Chuck\Util\Path;


class Root
{
    public function __construct(array $settings)
    {
        // The root directory of the project. The setting is mandatory.
        if (isset($settings['path.root'])) {
            $root = rtrim(Path::realpath($settings['path.root']), DIRECTORY_SEPARATOR);

            if (!Path::isAbsolute($root)) {
                throw new ValueError('Configuration error: root path must be an absolute path: ' . $root);
            }
        } else {
            throw new ValueError('Configuration error: root path not set');
        }
    }
}
