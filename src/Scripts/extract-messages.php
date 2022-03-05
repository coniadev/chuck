<?php

declare(strict_types=1);

class ExtractMessages extends Chuck\Cli\Command
{
    public static string $group = 'I18N';
    public static string $title = 'Extract gettext() calls from source files';
    public static string $desc = '';

    protected function extract(
        string $dir,
        string $glob,
        string $pot,
        string $locale,
        bool $join = false
    ): void {
        $find =  " -type d \\( " .
            "-name node_modules -o -name Plugin " . // excluded
            "\\) -prune -false -o -name";

        passthru(
            "find $dir" . $find . " '$glob'" .
                "  | xargs xgettext --from-code=UTF-8 " .
                ($join ? ' --join-existing ' : '') .
                "-L $locale -o $pot"
        );
    }


    public function run(Chuck\ConfigInterface $config, string ...$args): void
    {
        $rootDir = $config->path()->root;
        $command = $args[0] ?? null;

        if ($command === 'theme') {
            $theme = "$rootDir/www/theme";
            $pot = "$theme/locale/theme.pot";
            passthru("mkdir -p $theme/locale");

            echo "Extract $theme\n";
            $this->extract("$theme/", '*.php', $pot, 'PHP');
        } else {
            $pot = "$rootDir/locale/elearn.pot";

            passthru("mkdir -p $rootDir/locale");

            echo "Extract $rootDir/Chuck";
            $this->extract("$rootDir/Chuck", '*.php', $pot, 'PHP');
        }
    }
}

return new ExtractMessages();
