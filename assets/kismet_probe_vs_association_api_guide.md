# Distinguishing Probe Requests vs. Association (Connection) Requests Using the Kismet API

## Overview

This document describes how to use the Kismet REST API to differentiate
between:

-   **Client probe requests** (active scanning behavior)
-   **Client association / connection attempts** (actual network join
    behavior)

The methodology progresses from:

1.  **Device summary view (high-level indicators)**
2.  **Packet-level inspection (definitive determination)**

------------------------------------------------------------------------

# Part 1 --- Using the Device Summary View

## Endpoint

    GET /devices/all_devices.json

or for a specific device:

    GET /devices/by-key/<device-key>/device.json

------------------------------------------------------------------------

## Key Fields to Inspect

### 1. Device Type

    kismet.device.base.type

-   `Wi-Fi Client` → client device
-   `Wi-Fi AP` → access point

Only client devices are relevant for probing vs joining analysis.

------------------------------------------------------------------------

### 2. Last BSSID

    dot11.device.last_bssid

Interpretation:

-   **Null / empty** → likely probing only
-   **Populated BSSID** → client has transmitted traffic tied to a
    specific AP

This is a strong indicator of association or data exchange.

------------------------------------------------------------------------

### 3. Packet Counters

    kismet.device.base.packets.total
    kismet.device.base.packets.data
    kismet.device.base.packets.llc

Interpretation:

-   Probe-only clients typically have:
    -   Management frames only
    -   Zero or near-zero data frames
-   Associated clients show:
    -   Data frames
    -   Often EAPOL frames (WPA/WPA2/WPA3)

------------------------------------------------------------------------

### 4. Associated Client Map (AP Perspective)

If examining an AP:

    dot11.device.associated_client_map

If the client appears here, Kismet believes the client has associated.

------------------------------------------------------------------------

## Summary View Logic

  Condition                             Likely Behavior
  ------------------------------------- -----------------
  Only probe activity, no BSSID         Scanning
  BSSID present + data packets          Associated
  Appears in AP associated_client_map   Associated

⚠️ Limitation: The summary view does not expose the actual 802.11
management frame subtype sequence. Channel hopping may cause incomplete
visibility.

For definitive determination, use packet-level inspection.

------------------------------------------------------------------------

# Part 2 --- Packet-Level Inspection (Definitive Method)

## Endpoint

Per-device packets:

    GET /packets/by-device/<device-key>/packets.json

Global packet search:

    GET /packets/packets.json

------------------------------------------------------------------------

## Relevant 802.11 Frame Subtypes

### Probe Request

-   Frame Type: Management
-   Subtype: `probe_req`

Indicates active scanning.

------------------------------------------------------------------------

### Authentication

-   Subtype: `auth`

Step 1 of joining a network.

------------------------------------------------------------------------

### Association Request

-   Subtype: `assoc_req`
-   Subtype: `reassoc_req`

Client formally requesting to join an AP.

------------------------------------------------------------------------

### EAPOL

-   WPA/WPA2/WPA3 handshake frames
-   Indicates encryption negotiation after association

------------------------------------------------------------------------

### Data Frames

-   To-DS or From-DS flag set
-   Indicates client exchanging actual traffic with AP

------------------------------------------------------------------------

## Packet-Level Determination Logic

### Case 1 --- Probe Only

Observed frames: - `probe_req` - No `auth` - No `assoc_req` - No data
frames

Conclusion: Client is scanning only.

------------------------------------------------------------------------

### Case 2 --- Association Attempt

Observed frames: - `auth` - `assoc_req` - Possibly `assoc_resp`

Conclusion: Client is attempting to join network.

------------------------------------------------------------------------

### Case 3 --- Fully Joined

Observed frames: - `auth` - `assoc_req` - EAPOL handshake - Data frames
to/from BSSID

Conclusion: Client successfully associated and exchanged traffic.

------------------------------------------------------------------------

# Recommended Detection Algorithm

1.  Query device summary.
2.  If no BSSID and no data packets → classify as probe-only.
3.  If BSSID present → fetch packet-level data.
4.  Inspect for:
    -   `assoc_req` or `auth`
    -   EAPOL frames
    -   Data frames
5.  Classify based on frame presence.

------------------------------------------------------------------------

# Practical Considerations

-   Kismet channel hopping may miss association frames.
-   Some clients randomize MAC addresses during probing.
-   Passive scanning does not generate probe requests.
-   Hidden SSIDs complicate interpretation.
-   Data frames are the strongest evidence of actual association.

------------------------------------------------------------------------

# Conclusion

Using the Kismet API:

-   The **device summary view** provides strong indicators of
    association.
-   **Packet-level inspection** provides definitive proof based on
    802.11 frame subtype analysis.

For high-confidence detection, always confirm association behavior using
packet subtype inspection.
