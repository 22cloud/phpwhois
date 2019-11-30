<?php

namespace phpwhois;
use TrueBV\Punycode;

class Whois
{
    /** @var string[] List of servers and handlers (loaded from servers.whois) */
    protected $rawdata = '';

    protected $keydata = [];

    /** @var bool Is recursion allowed? */
    protected $error = [];

    /** @var int Default WHOIS port */
    protected $port = 43;

    /** @var int Maximum number of retries on connection failure */
    protected $retry = 0;

    /** @var int Time to wait between retries */
    protected $sleep = 2;

    /** @var int Read buffer size (0 == char by char) */
    protected $buffer = 1024;

    /** @var int Communications timeout */
    protected $stimeout = 10;

    /** @var string[] Non UTF-8 servers */
    protected $NON_UTF8 = [];

    /** @var string[] List of Whois servers with special parameters */
    protected $WHOIS_PARAM = [];

    /** @var string[] TLD's that have special whois servers or that can only be reached via HTTP */
    protected $WHOIS_SPECIAL = [];

    /** @var string[] Handled gTLD whois servers */
    protected $WHOIS_GTLD_HANDLER = [];
    //日期格式
    protected $dateFormat = [];

    /**
     * @var string[] 到期过滤
     */
    protected $patternExpires = [
        '/expir(e|y|es|ation)/i',
        '/renew(al)?/i',
        '/paid\-till/i',
        '/validity/i',
        '/billeduntil/i'
    ];

    /**
     * @var string[] 注册时间过滤
     */
    protected $patternRegistered = [
        '/creat(ed|ion)/i',
        '/regist(ered|ration)/i',
        '/commencement/i',
        '/created/i'
    ];

    /**
     * @var string[] 更新时间过滤
     */
    protected $patternUpdated = [
        '/update(d)?/i',
        '/modif(y|ied|ication)/i',
        '/changed/i',
    ];

    /**
     * @var array 注册状态过滤
     */
    protected $patternStatusRegistered = [
        '/status$/i' => '/^ok/i',
    ];

    /**
     * @var string[] DNS服务过滤
     */
    protected $patternNServer = [
        '/nserver/i',
        '/name server/i'
    ];

    protected $patternEmail = [
        '/Registrant Contact Email/i','/^Registrant Email$/i'
    ];

    protected $patternRegistrant = [
        '/^Registrant$/i','/^Registrant Name$/i','/Registrant Organization/i'
    ];

    protected $patternRegistrar = [
        '/^Sponsoring Registrar$/i','/^Registrar$/i'
    ];

    /**
     * @var string[] Indicates that line is a comment
     */
    protected $patternComment = [
        '/^%/i',
    ];

    /**
     * @var string[] 行过滤
     */
    protected $patternRowSeparator = [
        '/(: )/i',
    ];

    /**
     * @var string[] 列过滤
     */
    protected $patternColSeparator = '/(\r\n|[\r\n])/';

    /** @var string[] Array to contain all query publiciables */
    public $query = [
        'tld'    => '',
        'domain' => '',
        'error'  => [],
        'server' => '',
        'found'  => '',
    ];

    /**
     * @param string $domain full domain name (without trailing dot)
     */
    public function __construct()
    {
        // Load DATA array
        $servers = require 'whois.servers.php';

        $this->NON_UTF8           = $servers['NON_UTF8'];
        $this->WHOIS_PARAM        = $servers['WHOIS_PARAM'];
        $this->WHOIS_SPECIAL      = $servers['WHOIS_SPECIAL'];
        $this->WHOIS_GTLD_HANDLER = $servers['WHOIS_GTLD_HANDLER'];
    }

    protected function safe_replace($string)
    {
        $string = str_replace(array(' ', "'", ",", '+', 'œ', 'Œ', '°',';',"'",'\\',"{",'}','https://','http://','www.'), '', $string);
        $string = str_replace(array('&', 'ç', 'Ç', 'ñ', 'Ñ', '＆'), array('and', 'c', 'c', 'n', 'n', 'and'), $string);
        $string = str_replace(array('ā', 'ǎ', 'à', 'À', 'â', 'Â', 'ä', 'Ä', 'á', 'Á'), 'a', $string);
        $string = str_replace(array('è', 'È', 'è', 'È', 'ê', 'Ê', 'ë', 'Ë', 'é', 'É', 'ě', 'ē'), 'e', $string);
        $string = str_replace(array('ì', 'Ì', 'í', 'Í', 'î', 'Î', 'ï', 'Ï', 'ī', 'ǐ'), 'i', $string);
        $string = str_replace(array('ò', 'Ò', 'ô', 'Ô', 'ó', 'Ó', 'ō', 'ǒ', 'ö', 'Ö'), 'o', $string);
        $string = str_replace(array('ǔ', 'ū', 'ǖ', 'ǘ', 'ǚ', 'ǜ', 'ü', 'ú', 'Ú', 'ü', 'Ü', 'ù', 'Ù', 'û', 'Û'), 'u', $string);

        $string = str_replace('%20', '', $string);
        $string = str_replace('%27', '', $string);
        $string = str_replace('%2527', '', $string);
        return $string;
    }

    public function lookup($domain,$server='')
    {
        $domain = $this->safe_replace($domain);
        $domain = (new Punycode())->encode($domain);

        $this->query['domain'] = $domain;
        /*
        '/^[a-z\d\.\-]*\.[a-z]{2,63}$/i',
        '/^[a-z\d\.\-]*\.xn--[a-z\d]{4,59}$/i',
        */
        // check $domain syntax and split full domain name on subdomain and TLDs
        if (
            preg_match('/^([a-z\d\.\-]+)\.([a-z]{2,63})$/ui', $domain, $matches)
            || preg_match('/^(xn\-\-[\p{L}\d\-]+)\.(xn\-\-(?:[a-z\d-]+\.?1?)+)$/ui', $domain, $matches)
        ) {
            $this->query['keyword'] = $matches[1];
            $this->query['tld']     = $matches[2];

        } else {
            $this->error[] = "Invalid $domain syntax";

            return false;
        }



        if (array_key_exists($this->query['tld'], $this->WHOIS_SPECIAL)) {
            $this->query['server'] = $this->WHOIS_SPECIAL[$this->query['tld']];
        } else {
            $this->error[] = 'server error!';
            return false;
        }

        if (file_exists($this->query['tld'] . '.php')) {
            $this->handler = $this->query['tld'];
        }

        $server = empty($server)?$this->query['server']:$server;
        /*
        if (isset($this->WHOIS_PARAM[$server])) {
            $this->query['server'] = $this->query['server'] . '?' . str_replace('$', $domain,
                    $this->WHOIS_PARAM[$server]);
        }*/

        if ('http://' === \mb_substr($server, 0, 7) ||
            'https://' === \mb_substr($server, 0, 8)
        ) {
            $url = str_replace('{domain}',$this->query['domain'],$server);


            $ch  = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
            curl_setopt($ch, CURLOPT_TIMEOUT, 60);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

            $this->rawdata = curl_exec($ch);

            if (curl_error($ch)) {
                $this->error[] = 'Connect failed to: ' . $server;
                return false;
            }

            curl_close($ch);

        } else {
            $ptr = @\fsockopen($server, 43, $errno, $errstr, $this->stimeout);

            if (!$ptr) {
                $this->error[] = $errstr;
                return false;
            }

            stream_set_timeout($ptr, 5); //5
            stream_set_blocking($ptr, 0);

            switch ($this->query['tld']) {
                case 'com':
                    $out = "domain ={$this->query['domain']}.\r\n";
                    break;
                case 'net':
                    $out = "domain ={$this->query['domain']}.\r\n";
                    break;
                case 'de':
                    $out = $this->query['domain'] . "\r\n";
                    //$out = "-T dn,ace {$this->query['domain']}.\r\n";
                    break;
                case 'jp':
                    $out = "DOM {$this->query['domain']}/e\r\n";
                    break;
                default:
                    $out = $this->query['domain'] . "\r\n";
                    break;
            }
            fwrite($ptr, $out);
            $null  = null;
            $start = time();
            $raw = '';
            while (!feof($ptr)) {
                $raw .= fgets($ptr, $this->buffer);
                if (time() - $start > $this->stimeout) {
                    fclose($ptr);
                    $this->error[] = 'Error Timeout reading from ' . $this->query['server'];
                }
            }
            fclose($ptr);

            if (\array_key_exists($this->query['server'], $this->NON_UTF8)) {
                $raw = \utf8_encode($raw);
            }

            $this->rawdata = $raw;
        }

        return $this->getKeyData();

    }

    protected function getKeyData(){
        switch ($this->query['tld']) {
            case 'kr':
                $this->patternRegistered = ['/Registered Date/i'];
                $this->patternExpires = ['/Expiration Date/i'];
                $this->patternUpdated = ['/Last Updated Date/i',];
                $this->patternEmail = ['/^AC E-Mail/i',];
                $this->patternRegistrant = ['/^Registrant/i',];
                $this->patternRegistrar = ['/Authorized Agency/i',];
                $this->patternRowSeparator = ['/(: )/i',];
                $this->patternColSeparator = '/(\r\n|[\r\n])/';
                break;

            case 'jp':
                $this->patternRegistered = ['/Created on/i'];
                $this->patternExpires = ['/Expires on/i'];
                $this->patternUpdated = ['/Last Updated/i',];
                $this->patternEmail = ['/Email/i',];
                $this->patternRegistrant = ['/Registrant/i',];
                $this->patternRegistrar = ['/Authorized Agency/i',];
                $this->patternRowSeparator = ['/(\] )/i'];
                $this->patternColSeparator = '/(\r\n|[\r\n])/';
                break;
            case 'fr':
                $this->patternRegistered = ['/created/i'];
                $this->patternExpires = ['/Expiry Date/i'];
                $this->patternUpdated = ['/last-update/i',];
                $this->patternEmail = ['/e-mail/i',];
                $this->patternRegistrant = ['/contact/i',];
                $this->patternRegistrar = ['/registrar/i',];
                $this->patternRowSeparator = ['/(: )/i'];
                $this->patternColSeparator = '/(\r\n|[\r\n])/';
                break;
            case 'hk':
                $this->patternRegistered = ['/Domain Name Commencement Date/i'];
                $this->patternExpires = ['/Expiry Date/i'];
                $this->patternUpdated = ['/last-update/i',];
                $this->patternEmail = ['/Email/i',];
                $this->patternRegistrant = ['/Company Chinese name/i',];
                $this->patternRegistrar = ['/registrar/i',];
                $this->patternRowSeparator = ['/(: )/i'];
                $this->patternColSeparator = '/(\r\n|[\r\n])/';
                break;
            case 'au':
                $this->patternRegistered = ['/Domain Name Commencement Date/i'];
                $this->patternExpires = ['/Expiry Date/i'];
                $this->patternUpdated = ['/last-update/i',];
                $this->patternEmail = ['/Email/i',];
                $this->patternRegistrant = ['/Company Chinese name/i',];
                $this->patternRegistrar = ['/registrar/i',];
                $this->patternRowSeparator = ['/(: )/i'];
                $this->patternColSeparator = '/(\r\n|[\r\n])/';
                break;
            case 'tw':
                $findarr = array(
                    'Record expires on',
                    'Record created on',
                    ' (YYYY-MM-DD)',':
     '
                );
                $rearr = array(
                    'domain.expires:',
                    'domain.created:',
                    '',':'
                );
                $this->rawdata = str_replace($findarr, $rearr, $this->rawdata);
                $this->patternRegistered = ['/domain.created/i'];
                $this->patternExpires = ['/domain.expires/i'];
                $this->patternUpdated = ['/last-update/i',];
                $this->patternEmail = ['/Email/i',];
                $this->patternRegistrant = ['/^Registrant$/i',];
                $this->patternRegistrar = ['/Registration Service Provider/i',];
                $this->patternRowSeparator = ['/(:)/i'];
                $this->patternColSeparator = '/(\r\n|[\r\n])/';
                break;

            case 'ru':
                $this->patternRowSeparator = ['/(: )/i',];
                break;
            case 'de':

                $this->patternExpires = ['/changed/i',];
                $this->patternRegistered = ['/created/i',];
                //$this->patternUpdated = ['/changed/i',];
                $this->patternEmail = ['/e-mail/i',];
                $this->patternRegistrant = ['/organisation/i',];
                $this->patternRegistrar = ['/organisation/i',];
                $this->patternRowSeparator = ['/(: )/i',];
                $this->patternColSeparator = '/(\r\n|[\r\n])/';
                break;

            default:
                # code...
                break;
        }
        $rows = $this->splitRows();
        return $this->keydata = $this->extractDates($rows);
    }

    public function getRawData()
    {
        return $this->rawdata;
    }

    public function getError()
    {
        return $this->error;
    }

    public function isAvailable()
    {
        $whois_string     = $this->rawdata;
        $not_found_string = 'not found';
        if (isset($this->query['found'])) {
            $not_found_string = $this->query['found'];
        }

        $whois_string2 = @preg_replace('/' . $this->query['domain'] . '/', '', $whois_string);
        $whois_string  = @preg_replace("/\s+/", ' ', $whois_string);

        $array = explode(":", $not_found_string);
        if ($array[0] == "MAXCHARS") {
            if (strlen($whois_string2) <= $array[1]) {
                return true;
            } else {
                return false;
            }
        } else {
            if (preg_match("/" . $not_found_string . "/i", $whois_string)) {
                return true;
            } else {
                return false;
            }
        }
    }

    public function validDomain($domain)
    {
        $domain = (new Punycode())->encode($domain);

        $patterns = [
            '/^[a-z\d\.\-]*\.[a-z]{2,63}$/i',
            '/^[a-z\d\.\-]*\.xn--[a-z\d]{4,59}$/i',
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $domain)) {
                return true;
            }
        }

        return false;
    }

    public function getByKey($key)
    {
        $parsed = $this->getParsed();

        if (array_key_exists('keyValue', $parsed) && array_key_exists($key, $parsed['keyValue'])) {
            return $parsed['keyValue'][$key];
        }

        return null;
    }

    /**
     * Get raw response from the whois server
     *
     * @return string
     */
    public function getRaw()
    {
        return $this->rawdata;
    }

    /**
     * Split raw data response into array by newline
     *
     * @param string|null $raw Raw response from whois server
     *
     * @return string[]
     */
    public function splitRows($raw = null)
    {
        if (is_null($raw)) {
            $raw = $this->getRaw();
        }

        // Line ending could be \r\n, \r, \n
        $rows = preg_split($this->patternColSeparator, $raw);
        return $rows;
    }

    /**
     * Try to split row into key => value array
     *
     * @param string $row  Line to parse
     * @param string[] $splitBy Regexp for splitting the line. Method only looks for the first occurence of regexp
     * @param string[] $ignorePattern  Don't parse rows which match the given expression, just return false
     * @return array|false Return key => value array if regex found, or array with just 1 element otherwise
     */
    public function splitRow($row, array $splitBy = [], array $ignorePattern = [])
    {

        /**
         * TODO: Trim row's custom symbols (See .JP)
         */

        // If ignorePrefix is not empty and row matches it - return false
        if (!count($ignorePattern)) {
            $ignorePattern = $this->patternComment;
        }
        foreach ($ignorePattern as $pattern) {
            if (preg_match($pattern, $row)) {
                return false;
            }
        }

        $row = trim($row);

        if (!count($splitBy)) {
            $splitBy = $this->patternRowSeparator;
        }
        $parts = [];
        foreach ($splitBy as $separator) {
            $parts = preg_split($separator, $row, 2);
            if (count($parts) == 2) {
                $parts[1] = trim($parts[1]);
                // If string was split by two parts - return immediately
                // Otherwise try another patterns
                return $parts;
            }
        }

        return $parts;
    }

    /**
     * Extract unix timestamp from the defined string
     *
     * @param string $date Date
     *
     * @return int|false Unix timestamp
     */
    protected function parseDate($date)
    {
        $result = false;
        if ($this->dateFormat == null) {
            $result = strtotime($date);
        } elseif (count($this->dateFormat)) {
            foreach ($this->dateFormat as $format) {
                if ($dateTime = \DateTime::createFromFormat($format, $date)) {
                    $result = $dateTime->format('U');
                    break;
                }
            }
        }
        return $result;
    }

    /**
     * Try to extract the date from the given key and value
     *
     * @param string $row           Line from raw whois response
     * @param string[] $patterns       Array with patterns for matching the $key
     * @param string[] $antiPatterns   Array with patterns which $key must not match
     *
     * @return false|int    Unix timestamp
     */
    protected function extractDate($row, array $patterns, array $antiPatterns = [])
    {
        $result = false;

        foreach ($antiPatterns as $ap) {
            if (preg_match($ap, $row)) {
                $result = false;
                return $result;
            }
        }

        $parts = $this->splitRow($row);
        if (count((array)$parts) == 2) {
            $key = $parts[0];
            $value = $parts[1];
        } else {
            return false;
        }

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $key)) {// && $time = $this->parseDate($value)
                $result = $value;
                break;
            }
        }

        return $result;
    }

    /**
     * Try to extract `registered`, `expires` and `updated` dates from the rows
     *
     * @param string[] $rows Rows in key => value format
     *
     * @return string[]
     */
    public function extractDates(array $rows)
    {
        $dates = ['expirytime' => false, 'registertime' => false, 'updatetime' => false,'registrar' => false,'registrant'=>false,'email'=>false];

        foreach ($rows as $row) {
            // 注册时间
            if (!$dates['registertime']) {
                $dates['registertime'] = ($this->extractDate($row, $this->patternRegistered)) ?: $dates['registertime'];
            }
            // 到期时间
            if (!$dates['expirytime']) {
                $dates['expirytime'] = ($this->extractDate($row, $this->patternExpires)) ?: $dates['expirytime'];
            }
            // 更新时间
            if (!$dates['updatetime']) {
                $dates['updatetime'] = ($this->extractDate($row, $this->patternUpdated, ['/>>>/i'])) ?: $dates['updatetime'];
            }

            // 注册商
            if (!$dates['registrar']) {
                $dates['registrar'] = ($this->extractDate($row, $this->patternRegistrar)) ?: $dates['registrar'];
            }

            // 所有者
            if (!$dates['registrant']) {
                $dates['registrant'] = ($this->extractDate($row, $this->patternRegistrant)) ?: $dates['registrant'];
            }

            // E-mail
            if (!$dates['email']) {
                $dates['email'] = ($this->extractDate($row, $this->patternEmail)) ?: $dates['email'];
            }
        }
        return $dates;
    }

    /**
     * Try to parse response into key => value array
     * WARNING: This is very dirty solution, since multiple keys will override each other
     *
     * @param string[] $rows
     * @return array
     */
    protected function extractKeyValue(array $rows)
    {
        $keyValue = [];
        foreach ($rows as $row) {
            $parts = $this->splitRow($row);
            if (count((array)$parts) == 2) {
                $keyValue[$parts[0]] = $parts[1];
            }
        }
        return $keyValue;
    }
}
