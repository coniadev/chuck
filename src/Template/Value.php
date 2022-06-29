<?php

declare(strict_types=1);

namespace Chuck\Template;

use Symfony\Component\HtmlSanitizer\HtmlSanitizerConfig;
use Chuck\Util\Html;


class Value
{
    public function __construct(protected string $value)
    {
    }

    public function __toString(): string
    {
        return htmlspecialchars($this->value);
    }

    public function raw(): mixed
    {
        return $this->value;
    }

    public function clean(
        HtmlSanitizerConfig $config = null,
        bool $removeEmptyLines = true
    ): string {
        return Html::clean($this->value, $config, $removeEmptyLines);
    }

    public function empty(): bool
    {
        return empty($this->value);
    }
}
