<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Closure;
use Conia\Chuck\Exception\ContainerException;

class RegistryEntry
{
    protected array|Closure|null $args = null;
    protected bool $asIs = false;
    protected bool $reify;
    protected mixed $instance = null;

    /**
     * @param non-empty-string $id
     * */
    public function __construct(
        readonly protected string $id,
        protected mixed $definition
    ) {
        $this->reify = $this->negotiateReify($definition);
    }

    protected function negotiateReify(mixed $definition): bool
    {
        if (is_string($definition)) {
            if (!class_exists($definition)) {
                return false;
            }
        } elseif ($definition instanceof Closure) {
            return true;
        } else {
            if (is_scalar($definition) || is_array($definition) || is_object($definition)) {
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
        if ($this->definition instanceof Closure) {
            throw new ContainerException('Closure definitions in the registry cannot have arguments');
        }

        $this->args = $args;

        return $this;
    }

    public function definition(): mixed
    {
        return $this->definition;
    }

    public function instance(): mixed
    {
        return $this->instance;
    }

    public function get(): mixed
    {
        return $this->instance ?? $this->definition;
    }

    public function set(mixed $instance): void
    {
        $this->instance = $instance;
    }
}
