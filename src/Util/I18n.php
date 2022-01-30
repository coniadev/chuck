
<?php

declare(strict_types=1);

namespace Chuck\Util;

class Strings
{
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

    public static function getLocalizedDate(int $timestamp, string $locale): string
    {
        $formatter = new \IntlDateFormatter(
            $locale,
            \IntlDateFormatter::MEDIUM,
            \IntlDateFormatter::NONE
        );

        return $formatter->format($timestamp);
    }
}
