<?php

declare(strict_types=1);

namespace Chuck\Database;

class Script
{
    protected $db;
    protected $script;
    protected $isTemplate;

    public function __construct(Database $db, string $script, bool $isTemplate)
    {
        $this->db = $db;
        $this->script = $script;
        $this->isTemplate = $isTemplate;
    }

    protected function evaluateTemplate(string $path, Args $args): string
    {
        extract($args->get());
        ob_start();

        /** @psalm-suppress UnresolvableInclude */
        include $path;

        return ob_get_clean();
    }

    /**
     * Removes all keys from $params which are not present
     * in the $script.
     *
     * PDO does not allow unused parameters.
     */
    protected function prepareTemplateVars(string $script, Args $args): array
    {
        // remove PostgreSQL blocks
        $script = preg_replace(Query::PATTERN_BLOCK, ' ', $script);
        // remove strings
        $script = preg_replace(Query::PATTERN_STRING, ' ', $script);
        // remove /* */ comments
        $script = preg_replace(Query::PATTERN_COMMENT_MULTI, ' ', $script);
        // remove single line comments
        $script = preg_replace(Query::PATTERN_COMMENT_SINGLE, ' ', $script);

        // match everything starting with : and a letter
        // exclude multiple colons, like type casts (::text)
        // (would not find a var if it is at the very beginning of script)
        if (preg_match_all(
            '/[^:]:[a-zA-Z][a-zA-Z0-9_]*/',
            $script,
            $result,
            PREG_PATTERN_ORDER
        )) {
            $argsArray = $args->get();
            $newArgs = [];

            foreach (array_unique($result[0]) as $arg) {
                $a = substr($arg, 2);
                $newArgs[$a] = $argsArray[$a];
            }

            return $newArgs;
        }

        return [];
    }

    public function invoke(mixed ...$argsArray): Query
    {
        $args = new Args($argsArray);

        if ($this->isTemplate) {
            if ($args->type() === ArgType::Positional) {
                throw new \InvalidArgumentException(
                    'Template queries `*.sql.php` allow named parameters only'
                );
            }

            $script = $this->evaluateTemplate($this->script, $args);

            // We need to wrap the result of the prepare call in an array
            // to get back to the format of ...$argsArray.
            $args = new Args([$this->prepareTemplateVars($script, $args)]);
        } else {
            $script = $this->script;
        }

        return new Query($this->db, $script, $args);
    }

    public function __invoke(mixed ...$args): Query
    {
        return $this->invoke(...$args);
    }
}