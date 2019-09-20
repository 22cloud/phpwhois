<?php

namespace phpwhois;

class Whois
{
    /** @var string[] List of servers and handlers (loaded from servers.whois) */
    protected $rawdata = '';

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

    public function lookup($domain)
    {
        $domain = $this->safe_replace($domain);

        $this->query['domain'] = $domain;

        // check $domain syntax and split full domain name on subdomain and TLDs
        if (
            preg_match('/^([\p{L}\d\-]+)\.((?:[\p{L}\-]+\.?)+)$/ui', $domain, $matches)
            || preg_match('/^(xn\-\-[\p{L}\d\-]+)\.(xn\-\-(?:[a-z\d-]+\.?1?)+)$/ui', $domain, $matches)
        ) {
            $this->query['keyword'] = $matches[1];
            $this->query['tld']     = $matches[2];

        } else {
            $this->error[] = "Invalid $domain syntax";

            return false;
        }

        if (array_key_exists($this->query['tld'], $this->WHOIS_SPECIAL)) {
            $this->query['server'] = $this->WHOIS_SPECIAL[$this->query['tld']][0];
            $this->query['found']  = $this->WHOIS_SPECIAL[$this->query['tld']][1];

        } else {
            $this->error[] = 'server error!';
            return false;
        }

        $raw = '';

        if ('http://' === \mb_substr($this->query['server'], 0, 7) ||
            'https://' === \mb_substr($this->query['server'], 0, 8)
        ) {
            $ch  = curl_init();
            $url = $this->query['server'] . $this->query['domain'];
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
            curl_setopt($ch, CURLOPT_TIMEOUT, 60);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

            $this->rawdata = curl_exec($ch);

            if (curl_error($ch)) {
                $this->error[] = 'Connect failed to: ' . $this->query['server'];
                return false;
            }

            curl_close($ch);
        } else {

            // Connect to whois server, or return if failed
            $ptr = @\fsockopen($this->query['server'], 43, $errno, $errstr, $this->stimeout);

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
                    $out = "-T dn,ace {$this->query['domain']}.\r\n";
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
        return true;

    }

    /**
     * Returns WhoisParserResult instance
     *
     * @return object
     */
    public function getResult()
    {
        return $this->Result;
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
}
