<?php

declare(strict_types=1);

namespace Conia\Chuck\Registry;

use Closure;

class Entry
{
    protected readonly string $paramName;
    protected array|Closure|null $args = null;
    protected bool $reify = true;

    public function __construct(
        readonly protected string $id,
        protected object|string $value,
        string $paramName,
    ) {
        $this->paramName = trim($paramName);

        if (!empty($this->paramName) && !str_starts_with('$', $this->paramName)) {
            throw RuntimeException("Registry::add's \$paramName parameter must start with a '$'");
        }
    }

    public function id(): string
    {
        return $this->id . $this->paramName;
    }

    public function shouldReify(): bool
    {
        return $this->reify;
    }

    public function getArgs(): array|Closure|null
    {
        return $this->args;
    }

    public function reify(bool $reify): self
    {
        $this->reify = $reify;

        return $this;
    }

    public function args(array|Closure $args): self
    {
        $this->args = $args;

        return $this;
    }

    public function value(): object|string
    {
        return $this->value;
    }

    public function update(object $value): void
    {
        $this->value = $value;
    }
}
