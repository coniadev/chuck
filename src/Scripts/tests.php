<?php

declare(strict_types=1);

use NunoMaduro\Collision\Provider;
use Pest\Actions\ValidatesEnvironment;
use Pest\Console\Command as PestCommand;
use Pest\Support\Container;
use Pest\TestSuite;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Console\Output\OutputInterface;

class Tests extends Chuck\Cli\Command
{
    public static string $group = 'General';
    public static string $title = 'Run test suite';

    public function run(Chuck\ConfigInterface $config, string ...$args): void
    {
        $rootDir = $config->path('root');

        (new Provider())->register();

        $rootPath = getcwd();

        $testSuite = TestSuite::getInstance($rootDir);
        $output = new ConsoleOutput(ConsoleOutput::VERBOSITY_NORMAL, true);

        $container = Container::getInstance();
        $container->add(TestSuite::class, $testSuite);
        $container->add(OutputInterface::class, $output);

        ValidatesEnvironment::in($testSuite);

        exit($container->get(PestCommand::class)->run($_SERVER['argv']));
    }
}

return new Tests();
