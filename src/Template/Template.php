<?php

declare(strict_types=1);

namespace Chuck\Template;

use \ValueError;
use Chuck\Util\Html;


class Template
{
    protected ?string $layout = null;

    public function __construct(
        protected Engine $engine,
        protected string $moniker,
        protected array $context
    ) {
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

    public function layout(string $moniker): void
    {
        if ($this->layout === null) {
            $this->layout = $moniker;

            return;
        }

        throw new ValueError('Template error: layout already set');
    }

    public function hasLayout(): bool
    {
        return $this->layout !== null;
    }

    public function getLayout(): string
    {
        if ($this->layout !== null) {
            return $this->layout;
        }

        throw new ValueError('Template error: layout not set');
    }

    public function body(): string
    {
        return (string)$this->raw($this->engine->getBodyId($this->moniker));
    }

    public function begin(string $name): void
    {
        $this->engine->beginSection($name);
    }

    public function end(): void
    {
        $this->engine->endSection();
    }

    public function section(string $name): string
    {
        return $this->engine->getSection($name);
    }
}
