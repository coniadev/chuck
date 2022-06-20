<?php

declare(strict_types=1);

namespace Chuck;

use \RuntimeException;


class File
{
    public readonly string $tmpName;
    public readonly string $name;
    public readonly int $size;
    public readonly int $error;

    public function __construct(array $file)
    {
        $this->tmpName = $file['tmp_name'];
        $this->name = $file['name'];
        $this->size = $file['size'];
        $this->error = $file['error'];
    }

    public function move(string $target, bool $force = true): bool
    {
        // If target is a directory use the orginal file name
        if (is_dir($target)) {
            $target = $target . DIRECTORY_SEPARATOR . $this->getName();
        }

        if (!$force && file_exists($target)) {
            throw new RuntimeException('File already exists');
        }

        if (PHP_SAPI !== 'cli') {
            return true;
        }

        // @codeCoverageIgnoreEnd
        move_uploaded_file($this->tmpName, $target);
        // @codeCoverageIgnoreEnd
    }

    public function isValid(): bool
    {
        return $this->error === UPLOAD_ERR_OK && file_exists($this->tmpName);
    }

    protected function getName(): string
    {
        return basename(str_replace('\\', '/', $this->name));
    }
}
