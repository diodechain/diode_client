// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
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