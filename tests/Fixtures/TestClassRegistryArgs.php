<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Config;

class TestClassRegistryArgs
{
    public function __construct(
        public readonly TestClass $tc,
        public readonly string $test,
        public readonly ?Config $config = null,
    ) {
    }

    public static function fromDefaults(): static
    {
        return new self(new TestClass(), 'fromDefaults', new Config('fromDefaults'));
    }

    public static function fromArgs(TestClass $tc, string $test, string $app): static
    {
        return new self($tc, $test, new Config($app));
    }
}
