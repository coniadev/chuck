<?php

declare(strict_types=1);

namespace Conia\Chuck\Template;

use \RuntimeException;
use Symfony\Component\HtmlSanitizer\HtmlSanitizerConfig;
use Conia\Chuck\Util\Html;


class Template
{
    protected ?string $layout = null;

    public function __construct(
        protected Engine $engine,
        protected string $moniker,
        protected array $context
    ) {
    }

    public function context(array $values = []): array
    {
        return array_map(function ($item): mixed {
            return Wrapper::wrap($item);
        }, array_merge($this->context, $values));
    }

    public function escape(string $value): string
    {
        return htmlspecialchars($value);
    }

    public function e(string $value): string
    {
        return htmlspecialchars($value);
    }

    public function clean(
        string $value,
        HtmlSanitizerConfig $config = null,
        bool $removeEmptyLines = true,
    ): string {
        return Html::clean($value, $config, $removeEmptyLines);
    }

    public function raw(string $name): mixed
    {
        return $this->context[$name];
    }

    public function url(string $value): string
    {
        return filter_var($value, FILTER_SANITIZE_URL);
    }

    /**
     * Defines a layout template that will be wrapped around this instance.
     *
     * Typically it’s placed at the top of the file.
     */
    public function layout(string $moniker): void
    {
        if ($this->layout === null) {
            $this->layout = $moniker;

            return;
        } else {
            throw new RuntimeException('Template error: layout already set');
        }
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

        throw new RuntimeException('Template error: layout not set');
    }

    /**
     * Used in the layout template to get the content of the wrapped template
     */
    public function body(): string
    {
        return (string)$this->raw($this->engine->getBodyId($this->moniker));
    }

    /**
     * Includes another template into the current template
     *
     * If no context is passed it shares the context of the calling template.
     */
    public function insert(string $moniker, array $context = []): void
    {
        if (func_num_args() > 1) {
            echo $this->engine->render($moniker, $context);
        } else {
            echo $this->engine->render($moniker, $this->context);
        }
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

    public function hasSection(string $name): bool
    {
        return $this->engine->hasSection($name);
    }
}
