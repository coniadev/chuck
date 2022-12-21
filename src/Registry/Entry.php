<?php

declare(strict_types=1);

namespace Conia\Chuck;

class Entry
{
    protected array $args = [];
    protected bool $reify = false;
    protected bool $with = '';

    public function __construct(
        protected string $id,
        protected object|string|null $entry = null,
        protected string $with = '',
    ) {
        if (is_null($concrete)) {
            $concrete = $abstract;
        }

        $with = trim($with);

        if ($with && !str_starts_with('$', $with)) {
            throw RuntimeException("Registry::add's \$with parameter must start with a '$'");
        }
    }

    public function reify(): self
    {
        $this->reify = true;

        return $this;
    }

    public function args(array $args): self
    {
        $this->args = $args;

        return $this;
    }
}
