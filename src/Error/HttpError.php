<?php

declare(strict_types=1);

namespace Chuck\Error;


abstract class HttpError extends \Exception
{
    protected ?string $subTitle = null;

    public function getTitle(): string
    {
        return (string)$this->getCode() . ' ' . $this->getMessage();
    }

    public static function withSubtitle(string $subTitle): self
    {
        /** @psalm-suppress UnsafeInstantiation */
        $exception = new static();
        $exception->subTitle  = $subTitle;

        return $exception;
    }

    public function getSubTitle(): ?string
    {
        return $this->subTitle;
    }
}
