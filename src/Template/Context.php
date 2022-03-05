<?php

declare(strict_types=1);

namespace Chuck\Template;

use Chuck\Util\Html;


class Context
{
    public function __construct(protected array $context)
    {
    }

    public function __get(string $name): mixed
    {
        return Wrapper::wrap($this->context[$name]);
    }

    public function escape(string $value): string
    {
        return htmlspecialchars($value);
    }

    public function e(string $value): string
    {
        return htmlspecialchars($value);
    }

    public function clean(array $extensions = []): string
    {
        return Html::clean($this->value, $extensions);
    }

    public function raw(string $name): mixed
    {
        return $this->context[$name];
    }

    public function url(string $value): string
    {
        return filter_var($value, FILTER_SANITIZE_URL);
    }
}
