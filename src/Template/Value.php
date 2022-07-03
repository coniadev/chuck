<?php

declare(strict_types=1);

namespace Chuck\Template;

use Symfony\Component\HtmlSanitizer\HtmlSanitizerConfig;
use Chuck\Error\{NoSuchProperty, NoSuchMethod};
use Chuck\Util\Html;


class Value implements ValueInterface
{
    public function __construct(protected mixed $value)
    {
    }

    public function raw(): mixed
    {
        return $this->value;
    }

    public function clean(
        HtmlSanitizerConfig $config = null,
        bool $removeEmptyLines = true
    ): string {
        return Html::clean((string)$this->value, $config, $removeEmptyLines);
    }

    public function empty(): bool
    {
        return empty((string)$this->value);
    }

    public function __toString(): string
    {
        return htmlspecialchars((string)$this->value);
    }

    public function __get(string $name): mixed
    {
        // TODO: should we wrap properties to auto escape?
        if (property_exists($this->value, $name)) {
            return $this->value->{$name};
        }

        throw new NoSuchProperty('Property does not exists on the wrapped value');
    }

    public function __set(string $name, mixed $value): void
    {
        if (property_exists($this->value, $name)) {
            $this->value->{$name} = $value;
            return;
        }

        throw new NoSuchProperty('Property does not exists on the wrapped value');
    }

    public function __call(string $name, array $args): mixed
    {
        if (is_callable([$this->value, $name])) {
            return $this->value->$name(...$args);
        }

        throw new NoSuchMethod('Method does not exists on the wrapped value');
    }
}
