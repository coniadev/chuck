<?php

declare(strict_types=1);

namespace Chuck\Util;

class I18n
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

        throw new \ValueError(_('This is not a valid number'));
    }

    public static function localizeDateTime(
        int $timestamp,
        string $locale,
        int $dateFormat = \IntlDateFormatter::MEDIUM,
        int $timeFormat = \IntlDateFormatter::MEDIUM,
        string $tz = null,
        int $calendar = null,
    ): string {
        $formatter = new \IntlDateFormatter(
            $locale,
            $dateFormat,
            $timeFormat,
            $tz,
            $calendar,
        );

        return $formatter->format($timestamp);
    }

    public static function localizeDate(
        int $timestamp,
        string $locale,
        int $dateFormat = \IntlDateFormatter::MEDIUM,
        string $tz = null,
        int $calendar = null,
    ): string {
        return self::localizeDateTime(
            $timestamp,
            $locale,
            $dateFormat,
            \IntlDateFormatter::NONE,
            $tz,
            $calendar,
        );
    }
}
