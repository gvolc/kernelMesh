## This code implements a modified A* algorithm.

Here is a detailed description.

## Routing Mathematical Model ($A^*$)

The selection of the optimal next node (hop) in a decentralized network is performed using a modified $A^*$ algorithm. The final priority of each route is calculated using the canonical objective function formula:

$$F = G + H$$

---

### 1. Term $G$ (Edge Weight)

> $$G = w_{\text{p}} \cdot P_{\text{loss}} + w_{\text{t}} \cdot \text{RTT} + w_{\text{l}} \cdot \text{Load} + w_{\text{e}} \cdot \text{Energy}$$

**Formula Parameters:**
* $P_{\text{loss}}$ — Packet loss rate on the link (ranging from `0.0` to `1.0`).
* $\text{RTT}$ — Current latency (ping) in milliseconds (normalized against the maximum network timeout).
* $\text{Load}$ — Neighbor's CPU load level or network queue size (ranging from `0.0` to `1.0`).
* $\text{Energy}$ — Neighbor's battery depletion factor (`1.0 - BatteryLevel`). For nodes powered by mains electricity, this value is `0`.
* $w_{\text{p}}, w_{\text{t}}, w_{\text{l}}, w_{\text{e}}$ — Weight coefficients, configurable by the user via a configuration file.

---

### 2. Term $H$ (Heuristic: XOR Distance)

> $$H = \frac{256 - \text{CommonPrefixLen}(\text{NeighborID}, \text{TargetID})}{256}$$

**Formula Parameters:**
* $\text{NeighborID}$ — The 256-bit cryptographic identifier (SHA-256) of the neighboring node. * $\text{TargetID}$ — a 256-bit identifier of the target node (recipient).
* $\text{CommonPrefixLen}$ — a function that returns the length of the common prefix of two IDs in bits (maximum 256).