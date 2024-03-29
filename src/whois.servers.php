<?php

declare(strict_types=1);

/**
 *
 * NOTICE OF LICENSE
 *
 * This source file is released under GNU General Public License v2.
 *
 * @copyright 1999-2005 easyDNS Technologies Inc. & Mark Jeftovic
 * @copyright 2005-2014 David Saez
 * @copyright 2014-2019 Dmitry Lukashin
 * @copyright 2019-2020 Niko Granö (https://granö.fi)
 *
 */

return [

/* Non UTF-8 servers */

'NON_UTF8' => [
    'br.whois-servers.net'  => 1,
    'ca.whois-servers.net'  => 1,
    'cl.whois-servers.net'  => 1,
    'hu.whois-servers.net'  => 1,
    'is.whois-servers.net'  => 1,
    'pt.whois-servers.net'  => 1,
    'whois.interdomain.net' => 1,
    'whois.lacnic.net'      => 1,
    'whois.nicline.com'     => 1,
    'whois.ripe.net'        => 1,
],

/* If whois Server needs any parameters, enter it here */

'WHOIS_PARAM' => [
    'com.whois-servers.net' => 'domain =$',
    'net.whois-servers.net' => 'domain =$',
    'de.whois-servers.net'  => '-T dn,ace $',
    'jp.whois-servers.net'  => 'DOM $/e',
],

/* TLD's that have special whois servers or that can only be reached via HTTP */

'WHOIS_SPECIAL' => [
    "abogado" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "ac" => [
        "whois.nic.ac",
        "Available"
    ],
    "ac.ac" => [
        "whois.nic.ac",
        "Available"
    ],
    "ac.at" => [
        "whois.nic.at",
        "nothing found"
    ],
    "ac.be" => [
        "whois.dns.be",
        "No such domain"
    ],
    "ac.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "ac.il" => [
        "whois.isoc.org.il",
        "No data was found"
    ],
    "ac.in" => [
        "whois.inregistry.in",
        "NOT FOUND"
    ],
    "ac.jp" => [
        "whois.nic.ad.jp",
        "No match!!"
    ],
    "ac.ke" => [
        "whois.kenic.or.ke",
        "Not Registered"
    ],
    "ac.kr" => [
        "whois.nic.or.kr",
        "is not registered"
    ],
    "ac.nz" => [
        "whois.srs.net.nz",
        "220 Available"
    ],
    "ac.th" => [
        "whois.thnic.net",
        "No match for"
    ],
    "ac.uk" => [
        "whois.ja.net",
        "Sorry - no"
    ],
    "ac.za" => [
        "whois.co.za",
        "No information available"
    ],
    "academy" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "accountants" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "actor" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "ad" => [
        "whois.ripe.net",
        "no entries found"
    ],
    "adm.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "adult" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "adv.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "ae" => [
        "whois-check.aeda.net.ae",
        "---Available"
    ],
    "aero" => [
        "whois.aero",
        "NOT FOUND"
    ],
    "af" => [
        "whois.netnames.net",
        "No Match"
    ],
    "ag" => [
        "whois.nic.ag",
        "NOT FOUND"
    ],
    "agency" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "agro.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "ah.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "aid.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "airforce" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "allfinanz" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "alsace" => [
        "whois-alsace.nic.fr",
        "Requested Domain cannot be found"
    ],
    "alt.za" => [
        "whois.co.za",
        "No information available"
    ],
    "am" => [
        "whois.nic.am",
        "No match"
    ],
    "am.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "android" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "apartments" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "aquarelle" => [
        "whois-aquarelle.nic.fr",
        "Requested Domain cannot be found"
    ],
    "archi" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "army" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "arq.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "art.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "arts.ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "as" => [
        "whois.nic.as",
        "Domain Not Found"
    ],
    "asia" => [
        "whois.nic.asia",
        "NOT FOUND"
    ],
    "asn.au" => [
        "whois.aunic.net",
        "No Data Found"
    ],
    "asso.fr" => [
        "whois.nic.fr",
        "No entries found"
    ],
    "asso.mc" => [
        "whois.ripe.net",
        "no entries found"
    ],
    "associates" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "at" => [
        "whois.nic.at",
        "nothing found"
    ],
    "atm.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "attorney" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "au" => [
        "whois.audns.net.au",
        "No Data Found"
    ],
    "auction" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "audio" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "auto.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "aw" => [
        "whois.nic.aw",
        "is free"
    ],
    "ax" => [
        "whois.ax",
        "No records matching"
    ],
    "band" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "bank" => [
        "whois.nic.bank",
        "No match for"
    ],
    "bar" => [
        "whois.nic.bar",
        "DOMAIN NOT FOUND"
    ],
    "barclaycard" => [
        "whois.nic.barclaycard",
        "No Data Found"
    ],
    "barclays" => [
        "whois.nic.barclays",
        "No Data Found"
    ],
    "bargains" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "bayern" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "bbs.tr" => [
        "whois.metu.edu.tr",
        "No match found"
    ],
    "be" => [
        "whois.dns.be",
        "Status: AVAILABLE"
    ],
    "beer" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "berlin" => [
        "whois.nic.berlin",
        "% No match"
    ],
    "best" => [
        "whois.nic.best",
        "Not found:"
    ],
    "bg" => [
        "whois.register.bg",
        "does not exist in database"
    ],
    "bi" => [
        "whois1.nic.bi",
        "Domain Status: No Object Found"
    ],
    "bike" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "bingo" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "bio" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "bio.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "biz" => [
        "whois.nic.biz",
        "Not found"
    ],
    "biz.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "bj" => [
        "whois.nic.bj",
        "No records matching"
    ],
    "bj.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "black" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "blackfriday" => [
        "whois.uniregistry.net",
        "is available"
    ],
    "blue" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "bmw" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "bnpparibas" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "boo" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "boutique" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "br" => [
        "whois.nic.br",
        "No match for"
    ],
    "br.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "brussels" => [
        "whois.nic.brussels",
        "is still available"
    ],
    "budapest" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "build" => [
        "whois.nic.build ",
        "No Data Found"
    ],
    "builders" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "business" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "bw" => [
        "whois.nic.net.bw",
        "Domain Status: No Object Found"
    ],
    "by" => [
        "whois.cctld.by",
        "no entries found"
    ],
    "bz" => [
        "whois.afilias-grs.info.",
        "NOT FOUND"
    ],
    "bzh" => [
        "whois-bzh.nic.fr",
        "Requested Domain cannot be found"
    ],
    "ca" => [
        "whois.cira.ca",
        "Domain status: available"
    ],
    "cab" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "cal" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "camera" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "camp" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "cancerresearch" => [
        "whois.nic.cancerresearch",
        "No Data Found"
    ],
    "canon" => [
        "whois.nic.canon",
        "DOMAIN NOT FOUND"
    ],
    "capetown" => [
        "capetown-whois.registry.net.za",
        "Available"
    ],
    "capital" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "cards" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "care" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "career" => [
        "whois.nic.career",
        "No match for"
    ],
    "careers" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "casa" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "cash" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "casino" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "cat" => [
        "whois.cat",
        "NOT FOUND"
    ],
    "catering" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "cc" => [
        "whois.nic.cc",
        "No match"
    ],
    "cd" => [
        "whois.cd",
        "No match"
    ],
    "center" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "ceo" => [
        "whois.nic.ceo",
        "Not found:"
    ],
    "cern" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "cf" => [
        "whois.dot.cf",
        "Invalid query or domain name not known"
    ],
    "ch" => [
        "whois.nic.ch",
        "not have an entry"
    ],
    "channel" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "chat" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "cheap" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "christmas" => [
        "whois.uniregistry.net",
        "is available"
    ],
    "chrome" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "church" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "ci" => [
        "whois.nic.ci",
        "not found"
    ],
    "city" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "cl" => [
        "whois.nic.cl",
        "no existe"
    ],
    "claims" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "cleaning" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "click" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "clinic" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "clothing" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "club" => [
        "whois.nic.club",
        "Not found:"
    ],
    "cn" => [
        "whois.cnnic.net.cn",
        "No matching record"
    ],
    "cn.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "cng.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "cnt.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "co" => [
        "whois.nic.co",
        "Not found"
    ],
    "co.ac" => [
        "whois.nic.ac",
        "Available"
    ],
    "co.at" => [
        "whois.nic.at",
        "nothing found"
    ],
    "co.il" => [
        "whois.isoc.org.il",
        "No data was found"
    ],
    "co.in" => [
        "whois.inregistry.in",
        "NOT FOUND"
    ],
    "co.jp" => [
        "whois.nic.ad.jp",
        "No match!!"
    ],
    "co.ke" => [
        "whois.kenic.or.ke",
        "Not Registered"
    ],
    "co.kr" => [
        "whois.nic.or.kr",
        "is not registered"
    ],
    "co.nz" => [
        "whois.srs.net.nz",
        "220 Available"
    ],
    "co.rs" => [
        "whois.rnids.rs",
        "%ERROR:103"
    ],
    "co.th" => [
        "whois.thnic.net",
        "No match for"
    ],
    "co.uk" => [
        "whois.nic.uk",
        "No match"
    ],
    "co.ve" => [
        "whois.nic.ve",
        "No match for"
    ],
    "co.za" => [
        "http:\/\/whois.registry.net.za\/whois\/whois.sh?Domain=",
        "No Matches"
    ],
    "coach" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "codes" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "coffee" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "college" => [
        "whois.nic.college",
        "DOMAIN NOT FOUND"
    ],
    "cologne" => [
        "whois-fe1.pdt.cologne.tango.knipp.de",
        "% no matching objects found"
    ],
    "com" => [
        "whois.verisign-grs.com",
        "No match for"
    ],
    "com.au" => [
        "au.whois-servers.net",
        "No Data Found"
    ],
    "com.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "com.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "com.co" => [
        "whois.nic.co",
        "Not found"
    ],
    "com.de" => [
        "whois.centralnic.com",
        "Status: free"
    ],
    "com.ec" => [
        "whois.lac.net",
        "No match found"
    ],
    "com.fr" => [
        "whois.nic.fr",
        "No entries found"
    ],
    "com.gr" => [
        "http:\/\/grwhois.ics.forth.gr:800\/plainwhois\/plainWhois?domainName=",
        "not exist"
    ],
    "com.gt" => [
        "http:\/\/www.gt\/cgi-bin\/whois.cgi?domain=",
        "DOMINIO NO REGISTRADO"
    ],
    "com.hk" => [
        "whois.hkdnr.net.hk",
        "The domain has not been registered"
    ],
    "com.mm" => [
        "whois.nic.mm",
        "No domains matched"
    ],
    "com.mx" => [
        "whois.nic.mx",
        "Object_Not_Found"
    ],
    "com.my" => [
        "whois.mynic.net.my",
        "does not exist"
    ],
    "com.ph" => [
        "http:\/\/www2.dot.ph\/WhoIs.asp?Domain=",
        "is still available"
    ],
    "com.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "com.pt" => [
        "whois.dns.pt",
        "no match"
    ],
    "com.ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "com.ru" => [
        "whois.ripn.net",
        "No entries found"
    ],
    "com.sg" => [
        "whois.nic.net.sg",
        "Domain Not Found"
    ],
    "com.tr" => [
        "whois.metu.edu.tr",
        "No match found"
    ],
    "com.tw" => [
        "whois.twnic.net",
        "No Found"
    ],
    "com.ua" => [
        "whois.net.ua",
        "No entries found"
    ],
    "com.ve" => [
        "whois.nic.ve",
        "No match for"
    ],
    "community" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "company" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "computer" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "condos" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "construction" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "consulting" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "contractors" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "cooking" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "cool" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "coop" => [
        "whois.nic.coop",
        "No domain records were found to match"
    ],
    "country" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "courses" => [
        "whois.aridnrs.net.au",
        "No Data Found"
    ],
    "cq.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "credit" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "creditcard" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "cricket" => [
        "whois.nic.cricket",
        "is available"
    ],
    "cruises" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "cuisinella" => [
        "whois.nic.cuisinella",
        "No Data Found"
    ],
    "cx" => [
        "whois.nic.cx",
        "No match for"
    ],
    "cymru" => [
        "whois.nic.cymru",
        "This domain name has not been registered."
    ],
    "cz" => [
        "whois.nic.cz",
        "No entries found"
    ],
    "dad" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "dance" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "dating" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "datsun" => [
        "whois.nic.gmo",
        "DOMAIN NOT FOUND"
    ],
    "day" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "dclk" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "de" => [
        "whois.denic.de",
        "Status: free"
    ],
    "deals" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "degree" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "delivery" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "democrat" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "dental" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "dentist" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "desi" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "design" => [
        "whois.nic.design",
        "DOMAIN NOT FOUND"
    ],
    "dev" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "diamonds" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "diet" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "digital" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "direct" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "directory" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "discount" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "dk" => [
        "whois.dk-hostmaster.dk",
        "No entries found"
    ],
    "dm" => [
        "whois.nic.dm",
        "not found..."
    ],
    "dn.ua" => [
        "whois.net.ua",
        "No entries found"
    ],
    "docs" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "domains" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "doosan" => [
        "whois.nic.doosan",
        "No match for"
    ],
    "durban" => [
        "durban-whois.registry.net.za",
        "Available"
    ],
    "dvag" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "dz" => [
        "whois.nic.dz",
        "NO OBJECT FOUND!"
    ],
    "eat" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "ec" => [
        "whois.nic.ec",
        "Status: Not Registered"
    ],
    "ecn.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "edu" => [
        "whois.internic.net",
        "No match for"
    ],
    "edu.au" => [
        "whois.aunic.net",
        "No Data Found"
    ],
    "edu.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "edu.gr" => [
        "http:\/\/grwhois.ics.forth.gr:800\/plainwhois\/plainWhois?domainName=",
        "not exist"
    ],
    "edu.gt" => [
        "http:\/\/www.gt\/cgi-bin\/whois.cgi?domain=",
        "DOMINIO NO REGISTRADO"
    ],
    "edu.hk" => [
        "whois.hkdnr.net.hk",
        "The domain has not been registered"
    ],
    "edu.mm" => [
        "whois.nic.mm",
        "No domains matched"
    ],
    "edu.mx" => [
        "whois.nic.mx",
        "Object_Not_Found"
    ],
    "edu.my" => [
        "whois.mynic.net.my",
        "does not exist"
    ],
    "edu.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "edu.pt" => [
        "whois.dns.pt",
        "no match"
    ],
    "edu.rs" => [
        "whois.rnids.rs",
        "%ERROR:103"
    ],
    "edu.sg" => [
        "whois.nic.net.sg",
        "Domain Not Found"
    ],
    "edu.tr" => [
        "whois.metu.edu.tr",
        "No match found"
    ],
    "edu.za" => [
        "whois.co.za",
        "No information available"
    ],
    "education" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "ee" => [
        "whois.tld.ee",
        "% No entries found."
    ],
    "email" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "emerck" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "energy" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "eng.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "engineer" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "engineering" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "enterprises" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "epson" => [
        "whois.aridnrs.net.au",
        "No Data Found"
    ],
    "equipment" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "ernet.in" => [
        "whois.inregistry.in",
        "NOT FOUND"
    ],
    "es" => [
        "http:\/\/whois.virtualname.es\/whois.php?domain=",
        "LIBRE"
    ],
    "esp.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "esq" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "estate" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "etc.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "eti.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "eu" => [
        "whois.eu",
        "Status: AVAILABLE"
    ],
    "eu.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "eu.lv" => [
        "whois.biz",
        "Not found"
    ],
    "eurovision" => [
        "whois.nic.eurovision",
        "% no matching objects found"
    ],
    "eus" => [
        "whois.eus.coreregistry.net",
        "% no matching objects found"
    ],
    "events" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "exchange" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "expert" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "exposed" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "fail" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "fans" => [
        "whois.nic.fans",
        "DOMAIN NOT FOUND"
    ],
    "farm" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "fashion" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "feedback" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "fi" => [
        "whois.ficora.fi",
        "Domain not found"
    ],
    "fin.ec" => [
        "whois.lac.net",
        "No match found"
    ],
    "finance" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "financial" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "firm.ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "firmdale" => [
        "whois.nic.firmdale",
        "Domain Not Found"
    ],
    "fish" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "fishing" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "fit" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "fitness" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "flights" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "florist" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "flowers" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "flsmidth" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "fly" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "fm" => [
        "whois.nic.fm",
        "Not Registered"
    ],
    "fm.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "fo" => [
        "whois.nic.fo",
        "no entries found"
    ],
    "foo" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "football" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "forsale" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "fot.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "foundation" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "fr" => [
        "whois.nic.fr",
        "No entries found"
    ],
    "frl" => [
        "whois.nic.frl",
        "is still available"
    ],
    "frogans" => [
        "whois-frogans.nic.fr",
        "Requested Domain cannot be found"
    ],
    "fst.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "fund" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "furniture" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "futbol" => [
        "whois.unitedtld.com",
        "Domain not found"
    ],
    "g12.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "gal" => [
        "whois.gal.coreregistry.net",
        "% no matching objects found"
    ],
    "gallery" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "garden" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "gb.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "gb.net" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "gbiz" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "gd" => [
        "whois.nic.gd",
        "not found..."
    ],
    "gd.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "gdn" => [
        "whois.gdnregistry.com",
        "Domain Not Found"
    ],
    "geek.nz" => [
        "whois.srs.net.nz",
        "220 Available"
    ],
    "gen.nz" => [
        "whois.srs.net.nz",
        "220 Available"
    ],
    "gent" => [
        "whois.nic.gent",
        "is still available"
    ],
    "gf" => [
        "whois.nplus.gf",
        "not found in our database"
    ],
    "gg" => [
        "whois.gg",
        "NOT FOUND"
    ],
    "ggee" => [
        "whois.nic.ggee",
        "DOMAIN NOT FOUND"
    ],
    "gi" => [
        "whois2.afilias-grs.net",
        "NOT FOUND"
    ],
    "gift" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "gifts" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "gives" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "gl" => [
        "whois.nic.gl",
        "Domain Status: No Object Found"
    ],
    "glass" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "gle" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "global" => [
        "whois.nic.global",
        "NOT FOUND"
    ],
    "globo" => [
        "whois.gtlds.nic.br",
        "No match for"
    ],
    "gmail" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "gmina.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "gmx" => [
        "whois-fe1.gmx.tango.knipp.de",
        "% no matching objects found"
    ],
    "go.id" => [
        "whois.idnic.net.id",
        "Not found"
    ],
    "go.jp" => [
        "whois.nic.ad.jp",
        "No match!!"
    ],
    "go.kr" => [
        "whois.nic.or.kr",
        "is not registered"
    ],
    "go.th" => [
        "whois.thnic.net",
        "No match for"
    ],
    "gob.gt" => [
        "http:\/\/www.gt\/cgi-bin\/whois.cgi?domain=",
        "DOMINIO NO REGISTRADO"
    ],
    "gob.mx" => [
        "whois.nic.mx",
        "Object_Not_Found"
    ],
    "goldpoint" => [
        "whois.nic.goldpoint",
        "DOMAIN NOT FOUND"
    ],
    "goo" => [
        "whois.nic.gmo",
        "DOMAIN NOT FOUND"
    ],
    "goog" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "google" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "gop" => [
        "whois-cl01.mm-registry.com",
        "is available for registration"
    ],
    "gov" => [
        "whois.nic.gov",
        "No match for"
    ],
    "gov.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "gov.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "gov.ec" => [
        "whois.lac.net",
        "No match found"
    ],
    "gov.gr" => [
        "http:\/\/grwhois.ics.forth.gr:800\/plainwhois\/plainWhois?domainName=",
        "not exist"
    ],
    "gov.il" => [
        "whois.isoc.org.il",
        "No data was found"
    ],
    "gov.in" => [
        "whois.inregistry.in",
        "NOT FOUND"
    ],
    "gov.mm" => [
        "whois.nic.mm",
        "No domains matched"
    ],
    "gov.mx" => [
        "whois.nic.mx",
        "Object_Not_Found"
    ],
    "gov.my" => [
        "whois.mynic.net.my",
        "does not exist"
    ],
    "gov.sg" => [
        "whois.nic.net.sg",
        "Domain Not Found"
    ],
    "gov.tr" => [
        "whois.metu.edu.tr",
        "No match found"
    ],
    "gov.za" => [
        "whois.co.za",
        "No information available"
    ],
    "gq" => [
        "whois.dominio.gq",
        "Invalid query or domain name not known"
    ],
    "gr" => [
        "http:\/\/grwhois.ics.forth.gr:800\/plainwhois\/plainWhois?domainName=",
        "not exist"
    ],
    "graphics" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "gratis" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "green" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "gripe" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "gs" => [
        "whois.nic.gs",
        "No Object Found"
    ],
    "gs.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "gsm.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "guide" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "guitars" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "guru" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "gv.ac" => [
        "whois.nic.ac",
        "Available"
    ],
    "gv.at" => [
        "whois.nic.at",
        "nothing found"
    ],
    "gx.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "gy" => [
        "whois.registry.gy",
        "Domain Status: No Object Found"
    ],
    "gz.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "hamburg" => [
        "whois.nic.hamburg",
        "% No match"
    ],
    "hangout" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "haus" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "hb.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "he.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "healthcare" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "help" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "here" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "hi.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "hiphop" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "hiv" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "hk" => [
        "whois.hkirc.hk",
        "The domain has not been registered"
    ],
    "hk.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "hl.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "hn" => [
        "whois.nic.hn",
        "Domain Status: No Object Found"
    ],
    "hn.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "holdings" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "holiday" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "horse" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "host" => [
        "whois.nic.host",
        "DOMAIN NOT FOUND"
    ],
    "hosting" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "house" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "how" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "hr" => [
        "http:\/\/dns.hr\/?only_mod_instance=300_612_0&clean_tpl=true&ds_domena=",
        "nije registrirana"
    ],
    "ht" => [
        "whois.nic.ht",
        "Domain Status: No Object Found"
    ],
    "hu" => [
        "whois.nic.hu",
        "No match"
    ],
    "hu.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "ibm" => [
        "whois.nic.ibm",
        "No Data Found"
    ],
    "id" => [
        "whois.pandi.or.id",
        "DOMAIN NOT FOUND"
    ],
    "id.au" => [
        "whois.aunic.net",
        "No Data Found"
    ],
    "ie" => [
        "whois.domainregistry.ie",
        "% Not Registered"
    ],
    "ifm" => [
        "whois.nic.ifm",
        "% no matching objects found"
    ],
    "il" => [
        "whois.isoc.org.il",
        "No data was found"
    ],
    "im" => [
        "whois.nic.im",
        "was not found"
    ],
    "immo" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "immobilien" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "in" => [
        "whois.inregistry.in",
        "NOT FOUND"
    ],
    "in.rs" => [
        "whois.rnids.rs",
        "%ERROR:103"
    ],
    "in.th" => [
        "whois.thnic.net",
        "No match for"
    ],
    "ind.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "ind.gt" => [
        "http:\/\/www.gt\/cgi-bin\/whois.cgi?domain=",
        "DOMINIO NO REGISTRADO"
    ],
    "industries" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "inf.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "infiniti" => [
        "whois.nic.gmo",
        "DOMAIN NOT FOUND"
    ],
    "info" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "info.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "info.ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "info.ve" => [
        "whois.nic.ve",
        "No match for"
    ],
    "ing" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "ink" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "institute" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "insure" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "int" => [
        "whois.iana.org",
        "but this server does not have"
    ],
    "international" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "investments" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "io" => [
        "whois.nic.io",
        "is available"
    ],
    "iq" => [
        "whois.cmc.iq",
        "Domain Status: No Object Found"
    ],
    "ir" => [
        "whois.nic.ir",
        "no entries found"
    ],
    "is" => [
        "whois.isnic.is",
        "No entries found"
    ],
    "it" => [
        "whois.nic.it",
        "AVAILABLE"
    ],
    "iwi.nz" => [
        "whois.srs.net.nz",
        "220 Available"
    ],
    "java" => [
        "whois.nic.java",
        "No match for"
    ],
    "jcb" => [
        "whois.nic.gmo",
        "DOMAIN NOT FOUND"
    ],
    "je" => [
        "whois.je",
        "NOT FOUND"
    ],
    "jl.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "jobs" => [
        "jobswhois.verisign-grs.com",
        "No match for"
    ],
    "joburg" => [
        "joburg-whois.registry.net.za",
        "Available"
    ],
    "jor.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "jp" => [
        "whois.jprs.jp",
        "No match!!"
    ],
    "js.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "juegos" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "k12.il" => [
        "whois.isoc.org.il",
        "No data was found"
    ],
    "k12.tr" => [
        "whois.metu.edu.tr",
        "No match found"
    ],
    "kaufen" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "kddi" => [
        "whois.nic.kddi",
        "DOMAIN NOT FOUND"
    ],
    "ke" => [
        "whois.kenic.or.ke",
        "Domain Status: No Object Found"
    ],
    "kg" => [
        "whois.domain.kg",
        "is available for registration"
    ],
    "kh.ua" => [
        "whois.net.ua",
        "No entries found"
    ],
    "ki" => [
        "whois.nic.ki",
        "Domain Status: No Object Found"
    ],
    "kiev.ua" => [
        "whois.net.ua",
        "No entries found"
    ],
    "kim" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "kitchen" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "kiwi" => [
        "whois.nic.kiwi",
        "is available for registration"
    ],
    "kiwi.nz" => [
        "whois.srs.net.nz",
        "220 Available"
    ],
    "koeln" => [
        "whois-fe1.pdt.koeln.tango.knipp.de",
        "% no matching objects found"
    ],
    "kr" => [
        "whois.kr",
        "is not registered"
    ],
    "krd" => [
        "whois.aridnrs.net.au",
        "No Data Found"
    ],
    "ky" => [
        "whois.kyregistry.ky",
        "is available for"
    ],
    "kyoto" => [
        "whois.nic.kyoto",
        "DOMAIN NOT FOUND"
    ],
    "kz" => [
        "whois.nic.kz",
        "Nothing found for this query."
    ],
    "la" => [
        "whois.nic.la",
        "NOT FOUND"
    ],
    "lacaixa" => [
        "whois.nic.lacaixa",
        "% no matching objects found"
    ],
    "land" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "lat" => [
        "whois.nic.lat",
        "Object_Not_Found"
    ],
    "latrobe" => [
        "whois.nic.latrobe",
        "No Data Found"
    ],
    "lawyer" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "lc" => [
        "whois2.afilias-grs.net",
        "NOT FOUND"
    ],
    "lease" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "leclerc" => [
        "whois-leclerc.nic.fr",
        "Requested Domain cannot be found"
    ],
    "legal" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "lel.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "lg.ua" => [
        "whois.net.ua",
        "No entries found"
    ],
    "lgbt" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "li" => [
        "whois.nic.li",
        "do not have an entry in our database matching your query"
    ],
    "life" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "lighting" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "limited" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "limo" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "link" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "ln.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "loans" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "london" => [
        "whois-lon.mm-registry.com",
        "is available for registration"
    ],
    "lotte" => [
        "whois.nic.lotte",
        "DOMAIN NOT FOUND"
    ],
    "lt" => [
        "whois.domreg.lt",
        "Status:\t\t\tavailable"
    ],
    "ltd.uk" => [
        "whois.nic.uk",
        "No match"
    ],
    "ltda" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "lu" => [
        "whois.dns.lu",
        "No such domain"
    ],
    "luxe" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "luxury" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "lv" => [
        "whois.nic.lv",
        "Status: free"
    ],
    "lviv.ua" => [
        "whois.net.ua",
        "No entries found"
    ],
    "ly" => [
        "whois.nic.ly",
        "Not found"
    ],
    "ma" => [
        "whois.iam.net.ma",
        "Domain Status: No Object Found"
    ],
    "madrid" => [
        "whois.madrid.rs.corenic.net",
        "% no matching objects found"
    ],
    "mail.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "maison" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "management" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "mango" => [
        "whois.mango.coreregistry.net",
        "% no matching objects found"
    ],
    "maori.nz" => [
        "whois.srs.net.nz",
        "220 Available"
    ],
    "market" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "marketing" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "md" => [
        "whois.nic.md",
        "No match for"
    ],
    "me" => [
        "whois.meregistry.net",
        "NOT FOUND"
    ],
    "me.uk" => [
        "whois.nic.uk",
        "No match"
    ],
    "med.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "med.ec" => [
        "whois.lac.net",
        "No match found"
    ],
    "media" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "media.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "melbourne" => [
        "whois.aridnrs.net.au",
        "No Data Found"
    ],
    "meme" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "memorial" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "menu" => [
        "whois.nic.menu",
        "No Data Found"
    ],
    "mg" => [
        "whois.nic.mg",
        "Domain Status: No Object Found"
    ],
    "mi.th" => [
        "whois.thnic.net",
        "No match for"
    ],
    "miami" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "miasta.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "mil" => [
        "whois.internic.net",
        "No match for"
    ],
    "mil.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "mil.ec" => [
        "whois.lac.net",
        "No match found"
    ],
    "mil.gt" => [
        "http:\/\/www.gt\/cgi-bin\/whois.cgi?domain=",
        "DOMINIO NO REGISTRADO"
    ],
    "mil.id" => [
        "whois.idnic.net.id",
        "Not found"
    ],
    "mil.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "mil.tr" => [
        "whois.metu.edu.tr",
        "No match found"
    ],
    "mil.za" => [
        "whois.co.za",
        "No information available"
    ],
    "mini" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "mk" => [
        "whois.marnet.mk",
        "% No entries found."
    ],
    "ml" => [
        "whois.dot.ml",
        "Invalid query or domain name not known"
    ],
    "mn" => [
        "whois.afilias-grs.info",
        "NOT FOUND"
    ],
    "mo" => [
        "whois.monic.mo",
        "No match for"
    ],
    "mo.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "mobi" => [
        "whois.dotmobiregistry.net",
        "NOT FOUND"
    ],
    "moda" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "monash" => [
        "whois.nic.monash",
        "No Data Found"
    ],
    "money" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "mortgage" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "moscow" => [
        "whois.nic.moscow",
        "No entries found"
    ],
    "mov" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "ms" => [
        "whois.nic.ms",
        "No Object Found"
    ],
    "msk.ru" => [
        "whois.nic.ru",
        "No entries found"
    ],
    "mtpc" => [
        "whois.nic.gmo",
        "DOMAIN NOT FOUND"
    ],
    "mu" => [
        "whois.nic.mu",
        "Domain Status: No Object Found"
    ],
    "muni.il" => [
        "whois.isoc.org.il",
        "No data was found"
    ],
    "museum" => [
        "whois.museum",
        "NOT FOUND"
    ],
    "mx" => [
        "whois.nic.mx",
        "Object_Not_Found"
    ],
    "my" => [
        "whois.mynic.net.my",
        "does not exist in database"
    ],
    "mz" => [
        "whois.nic.mz",
        "Domain Status: No Object Found"
    ],
    "na" => [
        "whois.na-nic.com.na",
        "Domain Status: No Object Found"
    ],
    "name" => [
        "whois.nic.name",
        "No match"
    ],
    "navy" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "nc" => [
        "whois.nc",
        "No entries found"
    ],
    "ne.jp" => [
        "whois.nic.ad.jp",
        "No match!!"
    ],
    "ne.kr" => [
        "whois.nic.or.kr",
        "is not registered"
    ],
    "net" => [
        "whois.crsnic.net",
        "No match for"
    ],
    "net.au" => [
        "whois.aunic.net",
        "No Data Found"
    ],
    "net.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "net.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "net.co" => [
        "whois.nic.co",
        "Not found"
    ],
    "net.ec" => [
        "whois.lac.net",
        "No match found"
    ],
    "net.gr" => [
        "http:\/\/grwhois.ics.forth.gr:800\/plainwhois\/plainWhois?domainName=",
        "not exist"
    ],
    "net.gt" => [
        "http:\/\/www.gt\/cgi-bin\/whois.cgi?domain=",
        "DOMINIO NO REGISTRADO"
    ],
    "net.hk" => [
        "whois.hkdnr.net.hk",
        "The domain has not been registered"
    ],
    "net.il" => [
        "whois.isoc.org.il",
        "No data was found"
    ],
    "net.in" => [
        "whois.inregistry.in",
        "NOT FOUND"
    ],
    "net.mm" => [
        "whois.nic.mm",
        "No domains matched"
    ],
    "net.mx" => [
        "whois.nic.mx",
        "Object_Not_Found"
    ],
    "net.my" => [
        "whois.mynic.net.my",
        "does not exist"
    ],
    "net.nz" => [
        "whois.srs.net.nz",
        "220 Available"
    ],
    "net.ph" => [
        "http:\/\/www2.dot.ph\/WhoIs.asp?Domain=",
        "is still available"
    ],
    "net.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "net.ru" => [
        "whois.ripn.net",
        "No entries found"
    ],
    "net.sg" => [
        "whois.nic.net.sg",
        "Domain Not Found"
    ],
    "net.th" => [
        "whois.thnic.net",
        "No match for"
    ],
    "net.tr" => [
        "whois.metu.edu.tr",
        "No match found"
    ],
    "net.tw" => [
        "whois.twnic.net",
        "No Found"
    ],
    "net.ua" => [
        "whois.net.ua",
        "No entries found"
    ],
    "net.uk" => [
        "whois.nic.uk",
        "No match"
    ],
    "net.ve" => [
        "whois.nic.ve",
        "No match for"
    ],
    "net.za" => [
        "whois.co.za",
        "No information available"
    ],
    "network" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "new" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "nexus" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "nf" => [
        "whois.nic.nf",
        "Domain Status: No Object Found"
    ],
    "ng" => [
        "whois.nic.net.ng",
        "Domain Status: No Object Found"
    ],
    "ngo" => [
        "whois.publicinterestregistry.net",
        "NOT FOUND"
    ],
    "ngo.ph" => [
        "http:\/\/www2.dot.ph\/WhoIs.asp?Domain=",
        "is still available"
    ],
    "ngo.za" => [
        "whois.co.za",
        "No information available"
    ],
    "nico" => [
        "whois.nic.nico",
        "DOMAIN NOT FOUND"
    ],
    "ninja" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "nissan" => [
        "whois.nic.gmo",
        "DOMAIN NOT FOUND"
    ],
    "nl" => [
        "whois.domain-registry.nl",
        "is free"
    ],
    "nm.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "nm.kr" => [
        "whois.nic.or.kr",
        "is not registered"
    ],
    "no" => [
        "whois.norid.no",
        "No match"
    ],
    "no.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "nom.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "nom.co" => [
        "whois.nic.co",
        "Not found"
    ],
    "nom.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "nom.ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "nom.za" => [
        "whois.co.za",
        "No information available"
    ],
    "nra" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "nrw" => [
        "whois.nic.nrw",
        "% no matching objects found"
    ],
    "nt.ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "ntr.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "nu" => [
        "whois.nic.nu",
        "not found"
    ],
    "nx.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "nz" => [
        "whois.srs.net.nz",
        "220 Available"
    ],
    "odo.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "om" => [
        "whois.registry.om",
        "No Data Found"
    ],
    "one" => [
        "whois.nic.one",
        "No Data Found"
    ],
    "ong" => [
        "whois.publicinterestregistry.net",
        "NOT FOUND"
    ],
    "onl" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "ooo" => [
        "whois.nic.ooo",
        "No match for"
    ],
    "or.ac" => [
        "whois.nic.ac",
        "Available"
    ],
    "or.at" => [
        "whois.nic.at",
        "nothing found"
    ],
    "or.jp" => [
        "whois.nic.ad.jp",
        "No match!!"
    ],
    "or.kr" => [
        "whois.nic.or.kr",
        "is not registered"
    ],
    "or.th" => [
        "whois.thnic.net",
        "No match for"
    ],
    "org" => [
        "whois.publicinterestregistry.net",
        "NOT FOUND"
    ],
    "org.au" => [
        "whois.aunic.net",
        "No Data Found"
    ],
    "org.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "org.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "org.ec" => [
        "whois.lac.net",
        "No match found"
    ],
    "org.gr" => [
        "http:\/\/grwhois.ics.forth.gr:800\/plainwhois\/plainWhois?domainName=",
        "not exist"
    ],
    "org.gt" => [
        "http:\/\/www.gt\/cgi-bin\/whois.cgi?domain=",
        "DOMINIO NO REGISTRADO"
    ],
    "org.hk" => [
        "whois.hkdnr.net.hk",
        "The domain has not been registered"
    ],
    "org.il" => [
        "whois.isoc.org.il",
        "No data was found"
    ],
    "org.in" => [
        "whois.inregistry.in",
        "NOT FOUND"
    ],
    "org.mm" => [
        "whois.nic.mm",
        "No domains matched"
    ],
    "org.mx" => [
        "whois.nic.mx",
        "Object_Not_Found"
    ],
    "org.my" => [
        "whois.mynic.net.my",
        "does not exist"
    ],
    "org.nz" => [
        "whois.srs.net.nz",
        "220 Available"
    ],
    "org.ph" => [
        "http:\/\/www2.dot.ph\/WhoIs.asp?Domain=",
        "is still available"
    ],
    "org.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "org.ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "org.rs" => [
        "whois.rnids.rs",
        "%ERROR:103"
    ],
    "org.ru" => [
        "whois.nic.ru",
        "No entries found"
    ],
    "org.sg" => [
        "whois.nic.net.sg",
        "Domain Not Found"
    ],
    "org.tr" => [
        "whois.metu.edu.tr",
        "No match found"
    ],
    "org.tw" => [
        "whois.twnic.net",
        "No Found"
    ],
    "org.ua" => [
        "whois.net.ua",
        "No entries found"
    ],
    "org.uk" => [
        "whois.nic.uk",
        "No match"
    ],
    "org.ve" => [
        "whois.nic.ve",
        "No match for"
    ],
    "org.za" => [
        "http:\/\/org.za\/cgi-bin\/rwhois?format=full&domain=",
        "Domain not registered"
    ],
    "organic" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "ovh" => [
        "whois-ovh.nic.fr",
        "Requested Domain cannot be found"
    ],
    "paris" => [
        "whois-paris.nic.fr",
        "Requested Domain cannot be found"
    ],
    "partners" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "parts" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "pc.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "pe" => [
        "kero.yachay.pe",
        "Status: Not Registered"
    ],
    "pf" => [
        "whois.registry.pf",
        "Domain unknown"
    ],
    "ph" => [
        "http:\/\/www2.dot.ph\/WhoIs.asp?Domain=",
        "is still available"
    ],
    "photo" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "photography" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "photos" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "physio" => [
        "whois.nic.physio",
        "No Data Found"
    ],
    "pics" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "pictures" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "pink" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "pizza" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "place" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "plc.uk" => [
        "whois.nic.uk",
        "No match"
    ],
    "plumbing" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "pm" => [
        "whois.nic.pm",
        "No entries found"
    ],
    "pohl" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "poker" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "porn" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "post" => [
        "whois.dotpostregistry.net",
        "NOT FOUND"
    ],
    "pp.ru" => [
        "whois.nic.ru",
        "No entries found"
    ],
    "ppg.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "pr" => [
        "whois.nic.pr",
        "is not registered"
    ],
    "press" => [
        "whois.nic.press",
        "DOMAIN NOT FOUND"
    ],
    "presse.fr" => [
        "whois.nic.fr",
        "No entries found"
    ],
    "priv.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "pro" => [
        "whois.registrypro.pro",
        "NOT FOUND"
    ],
    "pro.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "prod" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "productions" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "prof" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "properties" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "property" => [
        "whois.uniregistry.net",
        "is available for"
    ],
    "psc.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "psi.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "pt" => [
        "whois.dns.pt",
        "no match"
    ],
    "pub" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "pw" => [
        "whois.nic.pw",
        "DOMAIN NOT FOUND"
    ],
    "qa" => [
        "whois.registry.qa",
        "No Data Found"
    ],
    "qc.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "qh.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "quebec" => [
        "whois.nic.quebec",
        "% no matching objects found"
    ],
    "re" => [
        "whois.nic.re",
        "No entries found"
    ],
    "re.kr" => [
        "whois.nic.or.kr",
        "is not registered"
    ],
    "realestate.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "rec.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "rec.ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "recipes" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "red" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "rehab" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "reise" => [
        "whois.nic.reise",
        "% No match"
    ],
    "reisen" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "reit" => [
        "whois.nic.reit",
        "DOMAIN NOT FOUND"
    ],
    "rel.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "rentals" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "repair" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "report" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "republican" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "res.in" => [
        "whois.inregistry.in",
        "NOT FOUND"
    ],
    "rest" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "restaurant" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "reviews" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "rich" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "rio" => [
        "whois.gtlds.nic.br",
        "No match for"
    ],
    "rip" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "rocks" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "rodeo" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "rs" => [
        "whois.rnids.rs",
        "%ERROR:103"
    ],
    "rsvp" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "ru" => [
        "whois.ripn.net",
        "No entries found"
    ],
    "ruhr" => [
        "whois.nic.ruhr",
        "% no matching objects found"
    ],
    "sa" => [
        "whois.nic.net.sa",
        "No Match"
    ],
    "sa.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "saarland" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "sale" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "samsung" => [
        "whois.nic.samsung",
        "No match for"
    ],
    "sarl" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "saxo" => [
        "whois.aridnrs.net.au",
        "No Data Found"
    ],
    "sb" => [
        "whois.nic.net.sb",
        "Domain Status: No Object Found"
    ],
    "sc" => [
        "wawa.eahd.or.ug",
        "No entries found"
    ],
    "sc.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "sca" => [
        "whois.nic.sca",
        "No match for"
    ],
    "scb" => [
        "whois.nic.scb",
        "NOT FOUND"
    ],
    "schmidt" => [
        "whois.nic.schmidt",
        "No Data Found"
    ],
    "school" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "school.nz" => [
        "whois.srs.net.nz",
        "220 Available"
    ],
    "school.za" => [
        "whois.co.za",
        "No information available"
    ],
    "schule" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "scot" => [
        "whois.scot.coreregistry.net",
        "% no matching objects found"
    ],
    "se" => [
        "whois.iis.se",
        "not found"
    ],
    "se.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "se.net" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "services" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "sexy" => [
        "whois.uniregistry.net",
        "is available for registration"
    ],
    "sg" => [
        "whois.nic.net.sg",
        "Domain Not Found"
    ],
    "sh" => [
        "whois.nic.sh",
        "is available for purchase"
    ],
    "sh.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "shiksha" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "shoes" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "shop.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "si" => [
        "whois.arnes.si",
        "No entries found"
    ],
    "singles" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "sk" => [
        "whois.sk-nic.sk",
        "Not found"
    ],
    "sklep.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "sky" => [
        "whois.nic.sky",
        "No match for"
    ],
    "slg.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "sm" => [
        "whois.nic.sm",
        "No entries found"
    ],
    "sn" => [
        "whois.nic.sn",
        "NOT FOUND"
    ],
    "sn.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "so" => [
        "whois.nic.so",
        "DOMAIN NOT FOUND"
    ],
    "sochi.su" => [
        "whois.nic.ru",
        "No entries found"
    ],
    "social" => [
        "whois.unitedtld.com",
        "Domain not found."
    ],
    "software" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "solar" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "solutions" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "sos.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "soy" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "space" => [
        "whois.nic.space",
        "DOMAIN NOT FOUND"
    ],
    "spb.ru" => [
        "whois.nic.ru",
        "No entries found"
    ],
    "spiegel" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "st" => [
        "whois.nic.st",
        "No entries found"
    ],
    "store.ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "study" => [
        "whois.nic.study",
        "No Data Found"
    ],
    "style" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "su" => [
        "whois.ripn.net",
        "No entries found"
    ],
    "sucks" => [
        "whois.nic.sucks",
        "No Data Found"
    ],
    "supplies" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "supply" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "support" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "surf" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "surgery" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "sx" => [
        "whois.sx",
        "Status: AVAILABLE"
    ],
    "sy" => [
        "whois.tld.sy",
        "Available"
    ],
    "sydney" => [
        "whois.nic.sydney",
        "No Data Found"
    ],
    "systems" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "taipei" => [
        "whois.nic.taipei",
        "Not found:"
    ],
    "targi.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "tatar" => [
        "whois.nic.tatar",
        "No entries found"
    ],
    "tattoo" => [
        "whois.uniregistry.net",
        "is available for registration"
    ],
    "tax" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "tc" => [
        "whois.adamsnames.tc",
        "Available"
    ],
    "technology" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "tel" => [
        "whois.nic.tel",
        "Not found"
    ],
    "tennis" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "tf" => [
        "whois.nic.tf",
        "No entries found"
    ],
    "th" => [
        "whois.thnic.co.th",
        "No match for"
    ],
    "tienda" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "tips" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "tires" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "tirol" => [
        "whois.nic.tirol",
        "% No match"
    ],
    "tj" => [
        "whois.nic.tj",
        "No match"
    ],
    "tj.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "tk" => [
        "https:\/\/partners.nic.tk\/cgi-bin\/whmcs-whois.taloha?d=",
        "has no matches"
    ],
    "tl" => [
        "whois.nic.tl",
        "Domain Status: No Object Found"
    ],
    "tm" => [
        "whois.nic.tm",
        "is available"
    ],
    "tm.fr" => [
        "whois.nic.fr",
        "No entries found"
    ],
    "tm.mc" => [
        "whois.ripe.net",
        "no entries found"
    ],
    "tm.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "tm.ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "tm.za" => [
        "whois.co.za",
        "No information available"
    ],
    "tmp.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "tn" => [
        "whois.ati.tn",
        "NO OBJECT FOUND!"
    ],
    "to" => [
        "monarch.tonic.to",
        "No match for"
    ],
    "today" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "tools" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "top" => [
        "whois.nic.top",
        "No match"
    ],
    "toshiba" => [
        "whois.nic.toshiba",
        "DOMAIN NOT FOUND"
    ],
    "tourism.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "town" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "toys" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "training" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "travel" => [
        "whois.nic.travel",
        "Not found"
    ],
    "travel.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "trust" => [
        "whois.nic.trust",
        "No Data Found"
    ],
    "tt" => [
        "https:\/\/www.nic.tt\/cgi-bin\/search.pl?name=",
        "is available"
    ],
    "tui" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "tur.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "turystyka.pl" => [
        "whois.dns.pl",
        "No information available"
    ],
    "tv" => [
        "whois.nic.tv",
        "No match for"
    ],
    "tv.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "tw" => [
        "whois.twnic.net.tw",
        "No Found"
    ],
    "tw.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "tz" => [
        "whois.tznic.or.tz",
        "% No entries found."
    ],
    "ua" => [
        "whois.net.ua",
        "No entries found"
    ],
    "ug" => [
        "whois.co.ug",
        "% No entries found."
    ],
    "uk" => [
        "whois.nic.uk",
        "This domain name has not been registered."
    ],
    "uk.co" => [
        "whois.uk.co",
        "NO MATCH"
    ],
    "uk.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "uk.net" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "university" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "uno" => [
        "whois.uno.nic",
        "Not found"
    ],
    "uol" => [
        "whois.gtlds.nic.br",
        "No match for"
    ],
    "us" => [
        "whois.nic.us",
        "Not found"
    ],
    "us.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "uy" => [
        "whois.nic.org.uy",
        "No match for"
    ],
    "uy.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "uz" => [
        "whois.cctld.uz",
        "not found..."
    ],
    "vacations" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "vc" => [
        "whois.adamsnames.tc",
        "Available"
    ],
    "ve" => [
        "whois.nic.ve",
        "No match for"
    ],
    "vegas" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "ventures" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "versicherung" => [
        "whois.nic.versicherung",
        "% No match"
    ],
    "vet" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "vet.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "vg" => [
        "whois.adamsnames.tc",
        "No Object Found"
    ],
    "viajes" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "video" => [
        "whois.rightside.co",
        "Domain not found."
    ],
    "villas" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "vision" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "vlaanderen" => [
        "whois.nic.vlaanderen",
        "is still available"
    ],
    "vodka" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "vote" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "voting" => [
        "whois.voting.tld-box.at",
        "% No match"
    ],
    "voto" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "voyage" => [
        "whois.donuts.co",
        "Domain not found"
    ],
    "vu" => [
        "vunic.vu",
        "is not valid!"
    ],
    "wales" => [
        "whois.nic.wales",
        "This domain name has not been registered."
    ],
    "wang" => [
        "whois.gtld.knet.cn",
        "No match"
    ],
    "watch" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "web.ve" => [
        "whois.nic.ve",
        "No match for"
    ],
    "web.za" => [
        "whois.co.za",
        "No information available"
    ],
    "website" => [
        "whois.nic.website",
        "DOMAIN NOT FOUND"
    ],
    "wed" => [
        "whois.nic.wed",
        "Domain Status: No Object Found"
    ],
    "wedding" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "wf" => [
        "whois.nic.wf",
        "No entries found"
    ],
    "whoswho" => [
        "whois.nic.whoswho",
        "Not found:"
    ],
    "wien" => [
        "whois.nic.wien",
        "% No match"
    ],
    "wiki" => [
        "whois.nic.wiki",
        "DOMAIN NOT FOUND"
    ],
    "wme" => [
        "whois.nic.wme",
        "DOMAIN NOT FOUND"
    ],
    "work" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "works" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "world" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "ws" => [
        "whois.website.ws",
        "No match for"
    ],
    "wtc" => [
        "whois.nic.wtc",
        "No Data Found"
    ],
    "wtf" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "www.ro" => [
        "whois.rotld.ro",
        "No entries found"
    ],
    "xj.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "xn--1qqw23a" => [
        "whois.ngtld.cn",
        "No match"
    ],
    "xn--3bst00m" => [
        "whois.gtld.knet.cn",
        "No match"
    ],
    "xn--3ds443g" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "xn--3e0b707e" => [
        "whois.kr",
        "Above domain name is not registered to"
    ],
    "xn--45q11c" => [
        "whois.nic.xn--45q11c",
        "No match"
    ],
    "xn--4gbrim" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "xn--55qw42g" => [
        "whois.conac.cn",
        "Not find MatchingRecord"
    ],
    "xn--55qx5d" => [
        "whois.ngtld.cn",
        "No match"
    ],
    "xn--6frz82g" => [
        "whois.afilias.net",
        "NOT FOUND"
    ],
    "xn--6qq986b3xl" => [
        "whois.gtld.knet.cn",
        "No match"
    ],
    "xn--80adxhks" => [
        "whois.nic.xn--80adxhks",
        "No entries found"
    ],
    "xn--80ao21a" => [
        "whois.nic.kz",
        "Nothing found for this query."
    ],
    "xn--80asehdb" => [
        "whois.online.rs.corenic.net",
        "% no matching objects found"
    ],
    "xn--80aswg" => [
        "whois.site.rs.corenic.net",
        "% no matching objects found"
    ],
    "xn--c1avg" => [
        "whois.publicinterestregistry.net",
        "NOT FOUND"
    ],
    "xn--clchc0ea0b2g2a9gcd" => [
        "whois.sgnic.sg",
        "Domain Not Found"
    ],
    "xn--czrs0t" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "xn--czru2d" => [
        "whois.gtld.knet.cn",
        "No match"
    ],
    "xn--d1acj3b" => [
        "whois.nic.xn--d1acj3b",
        "No entries found"
    ],
    "xn--d1alf" => [
        "whois.marnet.mk",
        "% No entries found."
    ],
    "xn--fiq228c5hs" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "xn--fiq64b" => [
        "whois.gtld.knet.cn",
        "No match"
    ],
    "xn--fiqs8s" => [
        "cwhois.cnnic.cn",
        "no matching record"
    ],
    "xn--fiqz9s" => [
        "cwhois.cnnic.cn",
        "no matching record"
    ],
    "xn--flw351e" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "xn--hxt814e" => [
        "whois.nic.xn--hxt814e",
        "No match"
    ],
    "xn--i1b6b1a6a2e" => [
        "whois.publicinterestregistry.net",
        "NOT FOUND"
    ],
    "xn--io0a7i" => [
        "whois.ngtld.cn",
        "No match"
    ],
    "xn--j1amh" => [
        "whois.dotukr.com",
        "No match for"
    ],
    "xn--j6w193g" => [
        "whois.hkirc.hk",
        "The domain has not been registered"
    ],
    "xn--kput3i" => [
        "whois.afilias-srs.net",
        "NOT FOUND"
    ],
    "xn--lgbbat1ad8j" => [
        "whois.nic.dz",
        "NO OBJECT FOUND!"
    ],
    "xn--mgb9awbf" => [
        "whois.registry.om",
        "No Data Found"
    ],
    "xn--mgba3a4f16a" => [
        "whois.nic.ir",
        "% No entries found."
    ],
    "xn--mgbaam7a8h" => [
        "whois.aeda.net.ae",
        "No Data Found"
    ],
    "xn--mgberp4a5d4ar" => [
        "whois.nic.net.sa",
        "No Match"
    ],
    "xn--mgbx4cd0ab" => [
        "whois.mynic.my",
        "does not exist in database"
    ],
    "xn--mxtq1m" => [
        "whois.nic.xn--mxtq1m",
        "Not Found."
    ],
    "xn--ngbc5azd" => [
        "whois.nic.xn--ngbc5azd",
        "No Data Found"
    ],
    "xn--nqv7f" => [
        "whois.publicinterestregistry.net",
        "NOT FOUND"
    ],
    "xn--o3cw4h" => [
        "whois.thnic.co.th",
        "No match for"
    ],
    "xn--ogbpf8fl" => [
        "whois.tld.sy",
        "Available"
    ],
    "xn--p1acf" => [
        "whois.nic.xn--p1acf",
        "Domain Status: No Object Found"
    ],
    "xn--p1ai" => [
        "whois.ripn.net",
        "No entries found"
    ],
    "xn--q9jyb4c" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "xn--qcka1pmc" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "xn--unup4y" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "xn--vermgensberater-ctb" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "xn--vermgensberatung-pwb" => [
        "whois.ksregistry.net",
        "not found..."
    ],
    "xn--vhquv" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "xn--wgbl6a" => [
        "whois.registry.qa",
        "No Data Found"
    ],
    "xn--xhq521b" => [
        "whois.ngtld.cn",
        "No match"
    ],
    "xn--yfro4i67o" => [
        "whois.sgnic.sg",
        "Domain Not Found"
    ],
    "xn--ygbi2ammx" => [
        "whois.pnina.ps",
        "Available"
    ],
    "xn--zfr164b" => [
        "whois.conac.cn",
        "Not find MatchingRecord"
    ],
    "xxx" => [
        "whois.nic.xxx",
        "NOT FOUND"
    ],
    "xyz" => [
        "xyz.whois-servers.net",
        "DOMAIN NOT FOUND"
    ],
    "xz.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "yn.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "yodobashi" => [
        "whois.nic.gmo",
        "DOMAIN NOT FOUND"
    ],
    "yoga" => [
        "whois-dub.mm-registry.com",
        "is available for registration"
    ],
    "youtube" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "yt" => [
        "whois.nic.yt",
        "No entries found"
    ],
    "za.com" => [
        "whois.centralnic.com",
        "DOMAIN NOT FOUND"
    ],
    "za.net" => [
        "http:\/\/www.za.net\/cgi-bin\/whois.cgi?domain=",
        "No such domain"
    ],
    "za.org" => [
        "http:\/\/www.za.net\/cgi-bin\/whois.cgi?domain=",
        "No such domain"
    ],
    "zip" => [
        "domain-registry-whois.l.google.com",
        "Domain not found."
    ],
    "zj.cn" => [
        "whois.cnnic.net.cn",
        "no matching record"
    ],
    "zlg.br" => [
        "whois.nic.br",
        "No match for"
    ],
    "zm" => [
        "whois.nic.zm",
        "Domain Status: No Object Found"
    ],
    "zone" => [
        "whois.donuts.co",
        "Domain not found."
    ],
    "zuerich" => [
        "whois.ksregistry.net",
        "not found..."
    ]
],

/* handled gTLD whois servers */

'WHOIS_GTLD_HANDLER' => [
    'whois.bulkregister.com' => 'enom',
    'whois.dotregistrar.com' => 'dotster',
    'whois.namesdirect.com'  => 'dotster',
    'whois.psi-usa.info'     => 'psiusa',
    'whois.www.tv'           => 'tvcorp',
    'whois.tucows.com'       => 'opensrs',
    'whois.35.com'           => 'onlinenic',
    'whois.nominalia.com'    => 'genericb',
    'whois.encirca.com'      => 'genericb',
    'whois.corenic.net'      => 'genericb',
],
];
