// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
function FindProxyForURL(url, host)
{
  if (shExpMatch(url, "*.diode/*") ||
      shExpMatch(url, "*.diode:*")) {
    return "SOCKS5 localhost:1080";
  } else {
    return "DIRECT";
  }
}
