<?php

declare(strict_types=1);

namespace Chuck\Tests;


class Helpers
{
    public static function hasMemcached(): bool
    {
        if (!class_exists('\Memcache', false)) {
            return false;
        }

        $memcache = new Memcache();
        try {
            $memcache->connect('localhost', 11211) or die("Could not connect");

            $version = $memcache->getVersion();

            $bject = new stdClass;
            $bject->str_attr = 'Evil';
            $bject->int_attr = 666;

            if($memcache->set('key', $bject, null, 1)) {
                return true;
            }

            return false;
        } catch {
            return false;
        }
    }
}
