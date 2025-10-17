WireGuard Integration (Join Command)

Overview
- The `diode join` command can read a WireGuard configuration from the device’s on-chain `wireguard` property and configure a local WireGuard interface for the current Diode network.
- The on-chain WireGuard config must NOT include a private key. The client generates and stores a private key locally and injects it into the final config file.
- One interface per Diode network: the interface name and config path are derived from the network, e.g. `wg-diode-prod` for mainnet and `wg-diode-dev` for testnet.

Interface Names and Paths
- Mainnet: interface `wg-diode-prod`
- Testnet: interface `wg-diode-dev`
- Local: interface `wg-diode-local`

Config file locations by OS
- Linux: `/etc/wireguard/wg-diode-<net>.conf`
- macOS: `/usr/local/etc/wireguard/wg-diode-<net>.conf`
- Windows: `C:\\Program Files\\WireGuard\\Data\\Configurations\\wg-diode-<net>.conf` (or user-local fallback)

Private Key Handling
- The client creates a private key on first use and stores it next to the config as `/etc/wireguard/wg-diode-<net>.key` (or the platform’s directory) with `0600` permissions.
- The client derives the public key and logs it for your reference. Keep the private key file secure.

On-Chain WireGuard Property
- Property key: `wireguard`
- Value: the WireGuard config content WITHOUT `PrivateKey`. Example:

```
[Interface]
Address = 10.7.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <remote-public-key>
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = example.org:51820
PersistentKeepalive = 25
```

Notes
- Omit `PrivateKey` from the on-chain configuration. The client injects a locally generated key automatically.
- You may include additional fields in `[Interface]` such as `Address`, `DNS`, and in `[Peer]` typically `PublicKey`, `AllowedIPs`, `Endpoint`, and `PersistentKeepalive`.

Bringing the Interface Up
- Linux/macOS: the client tries to enable the interface using `wg-quick up` automatically. If it fails due to permissions, run:
  - `sudo wg-quick up /etc/wireguard/wg-diode-<net>.conf`
- Windows: import and activate the generated config in WireGuard for Windows (GUI), or install it as a service (admin shell):
  - `"C:\\Program Files\\WireGuard\\wireguard.exe" /installtunnelservice C:\\Program Files\\WireGuard\\Data\\Configurations\\wg-diode-<net>.conf`

Updating
- When the on-chain `wireguard` property changes, the client rewrites the config and attempts to re-enable the interface. Any manual edits will be overwritten, so change the config on-chain instead.

Security
- The private key is never stored on-chain.
- The generated local key is stored with restrictive permissions. Ensure your system backups and access controls protect this file.

