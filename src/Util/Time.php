<?php

declare(strict_types=1);

namespace Chuck\Util;

class Time
{
    public static function toIsoDateTime(int $timestamp): string
    {
        return (string)date('Y-m-d H:i:s', $timestamp);
    }

    public static function toIsoDate(int $timestamp): string
    {
        return (string)date('Y-m-d', $timestamp);
    }
}
