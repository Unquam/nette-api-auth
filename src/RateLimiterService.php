<?php

declare(strict_types=1);

namespace Unquam\NetteApiAuth;

use Nette\Database\Explorer;

class RateLimiterService
{
    // database explorer instance
    private Explorer $database;

    // table name for rate limits
    private string $table;

    // max requests per window for test tokens
    private int $maxTest;

    // max requests per window for live tokens
    private int $maxLive;

    // window size in seconds
    private int $window;

    public function __construct(
        Explorer $database,
        string $table   = 'rate_limits',
        int $maxTest    = 60,
        int $maxLive    = 1000,
        int $window     = 60
    ) {
        $this->database = $database;
        $this->table    = $table;
        $this->maxTest  = $maxTest;
        $this->maxLive  = $maxLive;
        $this->window   = $window;
    }

    // check if key has exceeded the rate limit
    public function isExceeded(string $key, bool $isLive = false): bool
    {
        $max         = $isLive ? $this->maxLive : $this->maxTest;
        $windowStart = $this->getWindowStart();

        // cleanup old records occasionally (1% of requests)
        if (mt_rand(1, 100) === 1) {
            $this->cleanup();
        }

        $row = $this->database->table($this->table)
            ->where('key', $key)
            ->fetch();

        if (!$row) {
            try {
                // first request, create record
                $this->database->table($this->table)->insert([
                    'key'    => $key,
                    'hits'   => 1,
                    'window' => $windowStart,
                ]);
            } catch (\Nette\Database\UniqueConstraintViolationException $e) {
                // concurrent request already inserted, fetch and increment
                $row = $this->database->table($this->table)
                    ->where('key', $key)
                    ->fetch();

                if ($row) {
                    // check limit before incrementing to avoid wasted writes
                    if ($row->hits >= $max) {
                        return true;
                    }
                    $row->update(['hits' => $row->hits + 1]);
                    return false;
                }
            }

            return false;
        }

        // window expired, reset hits atomically — only the request that wins the
        // WHERE window < windowStart race gets hits=1; others fall through to the
        // normal increment path after a fresh fetch
        if ($row->window < $windowStart) {
            $affected = $this->database->query(
                'UPDATE ' . $this->table . ' SET hits = 1, `window` = ? WHERE `key` = ? AND `window` < ?',
                $windowStart,
                $key,
                $windowStart
            )->getRowCount();

            if ($affected > 0) {
                return false;
            }

            // another concurrent request already reset the window, re-fetch
            $row = $this->database->table($this->table)
                ->where('key', $key)
                ->fetch();

            if (!$row) {
                return false;
            }
        }

        // window still active, check hits
        if ($row->hits >= $max) {
            return true;
        }

        $row->update(['hits' => $row->hits + 1]);

        return false;
    }

    // delete rate limit records older than current window
    private function cleanup(): void
    {
        $this->database->table($this->table)
            ->where('`window` < ?', $this->getWindowStart())
            ->delete();
    }

    // get remaining requests for key
    public function remaining(string $key, bool $isLive = false): int
    {
        $max = $isLive ? $this->maxLive : $this->maxTest;

        $row = $this->database->table($this->table)
            ->where('key', $key)
            ->fetch();

        if (!$row || $row->window < $this->getWindowStart()) {
            return $max;
        }

        return max(0, $max - $row->hits);
    }

    // get window start datetime rounded to window size
    private function getWindowStart(): \DateTime
    {
        $now       = new \DateTime;
        $timestamp = (int) $now->format('U');
        $rounded   = $timestamp - ($timestamp % $this->window);

        return (new \DateTime)->setTimestamp($rounded);
    }
}