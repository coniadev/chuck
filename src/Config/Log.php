<?php

declare(strict_types=1);

namespace Chuck\Config;

use \ValueError;
use Chuck\Logger;


class Log
{
    use PathTrait;

    public readonly int $level;
    public readonly ?string $file;

    public function __construct(protected readonly string $root, array $values)
    {
        $this->level = $values['level'] ?? Logger::DEBUG;

        if ($values['file'] ?? null) {
            $file = $this->preparePath($values['file']);
        } else {
            $file = null;
        }

        if ($file) {
            if (!file_exists($file)) {
                touch($file);
            }

            if (!is_writable($file)) {
                throw new ValueError(
                    'Configuration error: logfile is not writable'
                );
            }
        }

        $this->file = $file;
    }
}
