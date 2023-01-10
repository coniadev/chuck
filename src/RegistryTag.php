<?php

declare(strict_types=1);

namespace Conia\Chuck;

class RegistryTag
{
    /**
     * @psalm-param non-empty-string $id
     * */
    public function __construct(
        readonly protected string $tag,
        readonly protected Registry $registry,
    ) {
    }

    public function has(string $id): mixed
    {
        return $this->registry->hasTagged($this->tag, $id);
    }

    public function entry(string $id): RegistryEntry
    {
        return $this->registry->taggedEntry($this->tag, $id);
    }

    public function get(string $id): mixed
    {
        return $this->registry->getTagged($this->tag, $id);
    }

    /**
     * @psalm-param non-empty-string $id
     */
    public function add(string $id, mixed $value = null): RegistryEntry
    {
        return $this->registry->addTagged($this->tag, $id, $value);
    }
}
