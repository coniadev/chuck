<?php

declare(strict_types=1);

namespace Chuck\Tests\Setup;


class Helper
{
    public static function memcachedExtensionLoaded(): bool
    {
        if (!class_exists('\Memcached', false)) {
            return false;
        }

        try {
            $memcache = new \Memcached();
            $memcache->addServer('localhost', 11211);

            if ($memcache->set('chuck_test_key', ['Evil', 666], 1)) {
                return true;
            }

            return false;
        } catch (\Exception) {
            return false;
        }


        return false;
    }

    public static function memcacheExtensionLoaded(): bool
    {
        if (!class_exists('\Memcache', false)) {
            return false;
        }

        $memcache = new \Memcache();

        try {
            if (!$memcache->connect('localhost', 11211)) {
                return false;
            }

            if ($memcache->set('chuck_test_key', ['Evil', 666], 0, 1)) {
                return true;
            }

            return false;
        } catch (\Exception) {
            return false;
        }
    }
}
