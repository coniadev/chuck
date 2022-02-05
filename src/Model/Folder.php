<?php

declare(strict_types=1);

namespace Chuck\Model;


class Folder
{
    protected $db;
    protected $folder;

    public function __construct(Database $db, string $folder)
    {
        $this->db = $db;
        $this->folder = $folder;
    }

    protected function scriptPath(string $key, bool $isTemplate): bool|string
    {
        $ext = $isTemplate ? '.php' : '';

        foreach ($this->db->getScriptDirs() as $path) {
            $result = $path . ds . $this->folder . ds . $key . '.sql' . $ext;

            if (file_exists($result)) {
                return $result;
            }
        }

        return false;
    }

    protected function readScript(string $key): bool|string
    {
        $script = $this->scriptPath($key, false);

        if ($script) {
            return file_get_contents($script);
        }

        return false;
    }

    protected function fromCache(
        \Chuck\Memcached $mc,
        string $key,
    ): string {
        $memKey = $this->db->getMemcachedPrefix() . '/' . $this->folder . '/' . $key;
        $stmt = $mc->get($memKey);

        if (!$stmt) {
            $stmt = file_get_contents($this->scriptPath($key, false));

            if ($stmt) {
                $mc->set(
                    $memKey,
                    $stmt,
                );
            }
        }

        return $stmt;
    }

    protected function getScript($key): Script
    {
        $mc = $this->db->getMemcached();

        if ($mc) {
            $stmt = $this->fromCache($mc, $key);
        } else {
            $stmt = $this->readScript($key);
        }

        if ($stmt) {
            return new Script($this->db, $stmt, false);
        }

        // If $stmt is not truthy until now,
        // assume the script is a dnyamic sql template
        $script = $this->scriptPath($key, true);

        if ($script) {
            return new Script($this->db, $script, true);
        }

        throw new \UnexpectedValueException('SQL script does not exist');
    }

    public function __get(string $key): Script
    {
        return $this->getScript($key);
    }

    public function __call(string $key, $args): Query
    {
        $script = $this->getScript($key);

        return $script->invoke(...$args);
    }
}
