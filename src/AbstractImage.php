<?php

declare(strict_types=1);

namespace Chuck;


abstract class AbstractImage
{
    protected string $path;
    protected Image $image;

    public function url(bool $bust): string
    {
        return '';
    }

    public function path(): string
    {
        return $this->path;
    }

    public function delete(): bool
    {
        return unlink($this->path);
    }

    public function get(): Image
    {
        return $this->image;
    }
}
