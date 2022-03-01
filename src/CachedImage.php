<?php

declare(strict_types=1);

namespace Chuck;



class CachedImage extends AbstractImage
{
    public function __construct(protected string $path)
    {
        $this->image = new Image($path);
    }
}
