<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\Exception\ContainerException;

class Entry
{
    protected array|Closure|null $args = null;
    protected bool $asIs = false;
    protected bool $reify;

    /**
     * @param non-empty-string $id
     * */
    public function __construct(
        readonly protected string $id,
        protected mixed $value
    ) {
        $this->reify = $this->negotiateReify($value);
    }

    protected function negotiateReify(mixed $value): bool
    {
        if (is_string($value)) {
            if (!class_exists($value)) {
                return false;
            }
        } elseif ($value instanceof Closure) {
            return true;
        } else {
            if (is_scalar($value) || is_array($value) || is_object($value)) {
                return false;
            }
        }

        return true;
    }

    public function shouldReify(): bool
    {
        return $this->reify;
    }

    public function shouldReturnAsIs(): bool
    {
        return $this->asIs;
    }

    public function getArgs(): array|Closure|null
    {
        return $this->args;
    }

    public function reify(bool $reify = true): self
    {
        $this->reify = $reify;

        return $this;
    }

    public function asIs(bool $asIs = true): self
    {
        // An update call is unecessary
        if ($asIs) {
            $this->reify = false;
        }

        $this->asIs = $asIs;

        return $this;
    }

    public function args(array|Closure $args): self
    {
        if ($this->value instanceof Closure) {
            throw new ContainerException('Closure values in the registry cannot have arguments');
        }

        $this->args = $args;

        return $this;
    }

    public function value(): mixed
    {
        return $this->value;
    }

    public function update(mixed $value): void
    {
        $this->value = $value;
    }
}
