<?php

declare(strict_types=1);

namespace Conia\Chuck\Exception;

use Exception;

/** @psalm-api */
abstract class HttpError extends Exception implements ChuckException
{
    protected ?string $subTitle = null;

    public function getTitle(): string
    {
        return (string)$this->getCode() . ' ' . $this->getMessage();
    }
}
