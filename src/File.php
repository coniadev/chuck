<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Throwable;
use Conia\Chuck\Exception\RuntimeException;

class File
{
    public readonly string $name;

    public function __construct(
        string $name,
        public readonly string $tmpName,
        public readonly string $type,
        public readonly int $size,
        public readonly int $error,
    ) {
        $this->name = $this->getName($name);
    }

    /**
     * @param $array array{name: string, tmp_name: string, type: string, size: int, error: int}
     */
    public static function fromArray(array $array): self
    {
        if (isset($array['name']) && is_array($array['name'])) {
            throw new RuntimeException('Cannot read file. Could be a multi file upload.');
        }

        try {
            return new self(
                (string)$array['name'],
                (string)$array['tmp_name'],
                (string)$array['type'],
                (int)$array['size'],
                (int)$array['error'],
            );
        } catch (Throwable) {
            throw new RuntimeException('Cannot read file. Could be a wrong array format.');
        }
    }

    public function move(string $target, bool $force = true): string
    {
        if (!$this->isValid()) {
            throw new RuntimeException('Uploaded file is invalid. Cannot be moved');
        }

        // If target is a directory use the orginal file name
        if (is_dir($target)) {
            $target = rtrim($target, '\\/') . DIRECTORY_SEPARATOR . $this->name;
        }

        if (!$force && file_exists($target)) {
            throw new RuntimeException('File already exists');
        }

        if (move_uploaded_file($this->tmpName, $target)) {
            // move_uploaded_file will always fail when running in CLI
            // @codeCoverageIgnoreStart
            return $target;
            // @codeCoverageIgnoreEnd
        }

        if (PHP_SAPI === 'cli') {
            return $target;
        }

        // See move_uploaded_file comment above
        // @codeCoverageIgnoreStart
        throw new RuntimeException('Moving uploaded file failed');
        // @codeCoverageIgnoreEnd
    }

    public function isValid(): bool
    {
        return $this->error === UPLOAD_ERR_OK && file_exists($this->tmpName);
    }

    protected function getName(string $name): string
    {
        return basename(str_replace('\\', '/', $name));
    }
}
