<?php

declare(strict_types=1);

namespace Conia\Chuck;

use RuntimeException;

class File
{
    public readonly string $name;
    public readonly string $tmpName;
    public readonly string $type;
    public readonly int $size;
    public readonly int $error;

    public function __construct(array $file)
    {
        if (is_array($file['name'])) {
            throw new RuntimeException(
                'Files are uploaded via HTML array, like: ' .
                    '<input type="file" name="fieldname[]"/>'
            );
        }

        $this->name = $this->getName($file['name']);
        $this->tmpName = $file['tmp_name'];
        $this->type = $file['type'];
        $this->size = $file['size'];
        $this->error = $file['error'];
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
