function FindProxyForURL(url, host)
{
  if (shExpMatch(url, "*.diode/*") ||
      shExpMatch(url, "*.diode:*")) {
    return "SOCKS5 localhost:8080";
  } else if (shExpMatch(url, "*.diode.ws/*") ||
      shExpMatch(url, "*.diode.ws:*")) {
    return "SOCKS5 localhost:8079";
  } else {
    return "DIRECT";
  }
}