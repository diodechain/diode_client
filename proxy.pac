function FindProxyForURL(url, host)
{
  if (shExpMatch(url, "*.diode/*") ||
      shExpMatch(url, "*.diode:*") ||
      shExpMatch(url, "*.diode.ws/*") ||
      shExpMatch(url, "*.diode.ws:*")) {
    return "SOCKS5 localhost:8080";
  } else {
    return "DIRECT";
  }
}