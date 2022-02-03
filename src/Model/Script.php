<?php

declare(strict_types=1);

namespace Chuck\Model;

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

    protected function evaluateTemplate(string $path, array $params): string
    {
        extract($params);
        ob_start();
        include $path;

        return ob_get_clean();
    }

    /**
     * Removes all keys from $params which are not present
     * in the $script.
     *
     * PDO does not allow unused parameters.
     */
    protected function prepareTemplateVars(string $script, array $params): array
    {
        // remove strings
        $script = preg_replace('/(["\'])(?:\\\1|.)*?\1/', ' ', $script);
        // remove /* */ comments
        $script = preg_replace('/\/\*([\s\S]*?)\*\//', ' ', $script);
        // remove single line comments
        $script = preg_replace('/--.*$/', ' ', $script);

        // match everything starting with : and a letter
        // exclude multiple colons, like type casts (::text)
        // (would not find a var if it is at the very beginning of script)
        if (preg_match_all(
            '/[^:]:[a-zA-Z][a-zA-Z0-9_]*/',
            $script,
            $result,
            PREG_PATTERN_ORDER
        )) {
            $newParams = [];

            foreach (array_unique($result[0]) as $param) {
                $p = substr($param, 2);
                $newParams[$p] = $params[$p];
            }

            return $newParams;
        }

        return [];
    }

    public function invoke(...$args): Query
    {
        if ($this->isTemplate) {
            $script = $this->evaluateTemplate($this->script, $args);
            $args = $this->prepareTemplateVars($script, $args);
        } else {
            $script = $this->script;
        }

        return new Query($this->db, $script, $args);
    }

    public function __invoke(...$args): Query
    {
        return $this->invoke(...$args);
    }
}
