# ble — BLE / app protocol

> The `com.vanmoof.app` GATT auth/command protocol and `vmtp` transport, as far
> as host-level strings reveal. Fill in characteristic UUIDs, payload framing,
> and the crypto from Ghidra.

## vmtp — VanMoof transport

`vmtp_zephyr` is the VanMoof transport layer over the Zephyr BT host. It carries
the `com.vanmoof.app` application protocol below. (Frame format / fragmentation —
*confirm in Ghidra*.)

## `com.vanmoof.app` service

A GATT service whose characteristics are referenced by these identifiers:

| Identifier | Likely role |
| --- | --- |
| `com.vanmoof.app:certificate` | device/app certificate exchange |
| `com.vanmoof.app:challenge` | server/app → device nonce (challenge) |
| `com.vanmoof.app:signature` | signature over the challenge/command |
| `com.vanmoof.app:command` | authenticated command channel (lock/unlock/etc.) |
| `com.vanmoof.app:status` | device → app status/notify |

These map to the strings — actual 128-bit UUIDs are assigned at runtime
(`bt_uuid` create paths seen: "Unable to create UUID", "failed to save UUID"),
so capture them from the GATT registration code in Ghidra.

### Auth flow (hypothesis — verify)

A challenge–response with asymmetric crypto:
1. App connects; device exposes its **certificate**.
2. App sends a **challenge** (nonce).
3. Device returns a **signature** (ECDSA via the SDC crypto / `bt_sdc_ecdh`)
   over the challenge, proving key possession.
4. Authenticated **command**s are then accepted (and gated by lock/stolen state);
   device replies on **status**.

Related anchors: "Could not log base64 encoded SW Authentication Token",
"Certificate expired", `MFi Token` provisioning (Apple MFi, used by FMNA).

## App-level commands (observed)

From the shell/command and log strings (the BLE command set likely mirrors these):
`Unlock bike`, `Bike is locked`, `Set bike identifier` / "Set bike ID to %s",
`Bike entered service mode`, "Update Bike distance (ODO) to %u", bell-sound
selection, master volume / mute, FindMy enable/disable, modem reset, battery
charge/discharge + capacity, power-off / shipping mode.

## Pairing / onboarding

Connect URL handed to the app:
`https://app.vanmoof.com/connect?ecu_id=%s&bike_id=%s`
Identity keys: `info/bike_id`, `info_bike_id_set`.

## To extract in Ghidra

- The `bt_gatt_service` registration → real 128-bit UUIDs per characteristic.
- The command opcode table (dispatch on the `command` characteristic).
- The exact crypto: curve, key storage location, certificate format.
- The `vmtp` frame format (header, length, fragmentation, any encryption).
