<?php

declare(strict_types=1);

namespace Chuck;

class Util
{
    public function __construct(RequestInterface $request = null)
    {
        $this->request = $request;
    }

    public function clean(string $html, ?array $extensions = []): string
    {
        $builder = \HtmlSanitizer\SanitizerBuilder::createDefault();
        $builder->registerExtension(new Sanitizer\BlockExtension());
        $builder->registerExtension(new Sanitizer\HeadFootExtension());
        $builder->registerExtension(new Sanitizer\NavExtension());

        if (count($extensions) == 0) {
            $config = $this->request->config->get('sanitizer');
        } else {
            $config = ['extensions' => $extensions];
        }
        $sanitizer = $builder->build($config);

        // also remove empty lines
        return preg_replace(
            "/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/",
            PHP_EOL,
            $sanitizer->sanitize($html)
        );
    }

    public static function groupBy(array $data, mixed $key): array
    {
        $result = [];

        foreach ($data as $val) {
            if (array_key_exists($key, $val)) {
                $result[$val[$key]][] = $val;
            } else {
                $result[""][] = $val;
            }
        }

        return $result;
    }

    /**
     * Calculate entropy of a string
     */
    public static function entropy(string $str): float
    {
        $classes = [
            // lower case uncode characters
            '/\p{Ll}/',
            // upper case uncode characters
            '/\p{Lu}/',
            // unicode numbers
            '/\p{N}/',
        ];

        $size = 0.0;
        $str = trim($str);
        $len = strlen($str);
        $classCount = 0;

        foreach ($classes as $pattern) {
            $matches = [];
            if (preg_match_all($pattern, $str, $matches)) {
                $size += count(array_unique($matches[0]));
                $classCount += 1;
            }
        }

        // special characters
        $matches = [];
        foreach (str_split("/[ ,.?!\"£$%^&*()-_=+[]{};:'@#~<>/\\|`¬¦]/", 1) as $char) {
            if (strpos($str, $char) !== false) {
                $matches[] = $char;
            }
        }
        $foundSpecialChars = count(array_unique($matches));
        if ($foundSpecialChars > 0) {
            $classCount += 1;
            $size += $foundSpecialChars;
        }

        // Evaluate if its a simple string of chars next to each other
        //   Like: abcdef or 1234
        // This is only an approximation an should not add too much weight
        // If this is below certain thresholds
        $sumDiff = 1;
        $chars = str_split($str, 1);
        for ($i = 1; $i < count($chars); $i++) {
            $sumDiff += abs(mb_ord($chars[$i - 1]) - mb_ord($chars[$i]));
        }
        // probably something like acegik...
        if ($sumDiff <= 10) {
            $len -= 1;
        }
        // probably something like 12345 or aaabbb
        if ($sumDiff <= 2) {
            $len -= 1;
        }

        if ($classCount > 0) {
            $size += $classCount - 1;
        }

        if ($size === 0 || $len <= 0) {
            return 0;
        }
        return log($size, 2) * $len;
    }

    public function isInsideRootDir(string $path): bool
    {
        $config = $this->request->config;
        $root = $config->path('root');

        return str_starts_with($path, $root);
    }

    public static function realpath(string $path): string
    {
        $path = str_replace('//', '/', $path);
        $segments = explode('/', $path);
        $out = [];

        foreach ($segments as $segment) {
            if ($segment == '.') {
                continue;
            }

            if ($segment == '..') {
                array_pop($out);
                continue;
            }

            $out[] = $segment;
        }

        return implode('/', $out);
    }

    public static function isAssoc(array $arr): bool
    {
        if ([] === $arr) {
            return false;
        }

        return array_keys($arr) !== range(0, count($arr) - 1);
    }

    /**
     * Parses a string to a float
     *
     * This works for any kind of input, American or European style.
     */
    public static function parseFloat(string $value): float
    {
        $value = preg_replace('/\s/', '', $value);

        if (preg_match('/^[0-9.,]+$/', $value)) {
            $value = str_replace(',', '.', $value);

            // remove all dots but the last one
            $value = preg_replace('/\.(?=.*\.)/', '', $value);

            return floatval($value);
        }

        throw new \Exception(_('This is not a valid number'));
    }

    public static function parseCoordinatesFromString(string $data, string $seperator = '|'): array
    {
        return array_map(
            function ($b) {
                return floatval($b);
            },
            explode($seperator, $data)  // looks like there's no way to get a postgres array directly
        );
    }


    public static function getLocalizedDate(int $timestamp, string $locale): string
    {
        $formatter = new \IntlDateFormatter($locale, \IntlDateFormatter::MEDIUM, \IntlDateFormatter::NONE);
        return $formatter->format($timestamp);
    }

    public static function copyDirectoryRecursive(string $source, string $destination): void
    {
        if (is_dir($source)) {
            mkdir($destination, 0755, true);
            foreach ($iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($source, \RecursiveDirectoryIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::SELF_FIRST
                ) as $item) {
                if ($item->isDir()) {
                    mkdir($destination . DIRECTORY_SEPARATOR . $iterator->getSubPathname());
                } else {
                    copy($item->getRealPath(), $destination . DIRECTORY_SEPARATOR . $iterator->getSubPathname());
                }
            }
        }
    }
}
