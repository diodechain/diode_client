// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
function FindProxyForURL(url, host)
{
  if (shExpMatch(url, "*.diode/*") ||
      shExpMatch(url, "*.diode:*")) {
    return "SOCKS5 localhost:1080";
  } else {
    return "DIRECT";
  }
}
