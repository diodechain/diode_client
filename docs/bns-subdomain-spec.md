# BNS subdomain specification

Normative contract for gateway hostnames under a registered BNS zone, and for the generic BNS property commands that write those records.

Diode names (`.diode`, `.diode.link`, `.diode.ws`) are unchanged: the label next to that suffix is the BNS name.

---

## Zone model

A custom hostname is a DNS name whose registrable domain is not a Diode suffix. The BNS name is the registrable label:

| Hostname | Zone (BNS name) | Prefix labels |
|---|---|---|
| `acme.com` | `acme` | none |
| `division1.acme.com` | `acme` | `division1` |
| `mysubsub.division1.acme.com` | `acme` | `mysubsub`, `division1` |
| `division1.acme.co.uk` | `acme` | `division1` |
| `division1.diode.link` | none (Diode name) | BNS `division1` |
| `west11.division1.diode.link` | none (Diode name) | BNS `division1` |

The zone label follows the existing BNS name rules. Prefix labels do not. `div1.acme.com` is valid even though `div1` is too short to register as its own BNS name.

Only the owner of the zone name can write its properties. A prefix is not a separate registration.

---

## Property records

Records are BNS properties on the zone, stored as `key=value` strings.

- Gateway keys are `PX:` plus the prefix labels joined with `.`, lowercased. `mysubsub.division1.acme.com` looks up `PX:mysubsub.division1` and then `PX:division1`.
- The value is one destination address (`0x` plus 40 hex characters).
- An empty value is a miss. `FindPropertyKV` returns `""` both for a missing key and for an empty value, so an empty record cannot override the fallback.
- A non-empty value that is not an address fails the request.
- The first matching property wins, matching `FindPropertyKV`.

`SetPropertyKV` replaces an existing key. `AddProperty` appends and must not be used for updates, because the first copy would keep winning.

---

## Gateway resolution

For a custom name, walk the prefix from longest to shortest on that one zone entry.

`mysubsub.division1.acme.com`:

1. `PX:mysubsub.division1`
2. `PX:division1`
3. the destinations registered on BNS `acme`

A shorter key covers every name to its left. `PX:division1=<addr>` answers `division1.acme.com` and `west.division1.acme.com`, unless a longer key matches first. `acme.com` has no prefix and uses the zone destinations directly.

The leftmost label may carry the existing mode prefix (`r-`, `w-`, `s-`, or a combination) and a `-port` suffix. Those are removed before the key is built and are not stored in the property. `r-west11-8080.division1.acme.com` looks up `PX:west11.division1`, then connects to port `8080` in mode `r`. Labels under that one are literal.

Resolution reads the properties array from the BNS entry (the slot after `destinations`). The Diode L1 entry is used when that name resolves there; otherwise the Moonbeam entry is used. This is the same chain order as `ResolveBNS`.

On-demand certificates are issued for the requested hostname when that parse succeeds and the zone BNS name is allowed. The destination address is not the certificate name. Names with more than three dots are still rejected, so `mysubsub.division1.acme.com` can be issued and `mysubsub.division1.acme.co.uk` cannot.

---

## Commands

`diode bns` property commands take one argument. The BNS name is separated by the first `:`. The key and value are separated by the first `=`. Keys must not contain `=`.

```text
diode bns -set-property <name>:<key>=<value>
diode bns -get-property <name>:<key>
diode bns -delete-property <name>:<key>
```

Examples:

```text
diode bns -set-property acme:PX:division1=0x0000000000000000000000000000000000000001
diode bns -set-property acme:PX:mysubsub.division1=0x0000000000000000000000000000000000000002
diode bns -get-property acme:PX:division1
diode bns -delete-property acme:PX:division1
```

`-set-property` and `-delete-property` require the caller to own `<name>`, and they write the Diode L1 BNS contract. `-get-property` reads the same chain order the gateway uses. The commands are generic: any key is accepted, and `PX:` is only the gateway convention.
