# Akita DDNS Use Cases

Akita DDNS brings the convenience of DNS to the decentralized, infrastructure-less Reticulum mesh network. By mapping human-readable names to dynamic Reticulum Identity Hashes (RIDs), Akita enables several powerful use cases for off-grid, ad-hoc, and highly mobile networks.

---

## 1. IoT & Embedded Device Management
In mesh networks, IoT sensors, controllers, and headless devices often boot up and acquire dynamic, ephemeral routing paths.
* **The Problem:** Reaching a specific sensor (e.g., a remote weather station) is difficult if its underlying connectivity changes or its Reticulum Identity is regenerated upon a hardware reset.
* **The Akita Solution:** A startup or network-change hook can call `akita-ddns cli register --name weather-station.sensors`. In an owned namespace, the hook uses the namespace-owner identity to authorize the update.

## 2. Roaming Laptops and Mobile Nodes
Reticulum is designed for roaming. A laptop might connect via a local WiFi access point, then switch to a LoRa radio when off-grid.
* **The Problem:** Friends or automated services trying to reach the laptop (e.g., via LXMF messages or NomadNet) need to know its current Destination Hash.
* **The Akita Solution:** The laptop's network-change hook updates its Akita registration whenever its destination changes. Friends resolve `alice.roaming` to obtain the current destination.

## 3. Decentralized Services Directory
Mesh networks often host community services like bulletin boards, file sharing nodes, or messaging relays.
* **The Problem:** In a decentralized mesh, there are no static IP addresses. Finding community services requires users to copy-paste long 32-character hexadecimal strings.
* **The Akita Solution:** Service operators register their nodes (e.g., `bulletin.public` or `chat.relay`). Users simply type the human-readable name into their compatible Reticulum clients, making the mesh as easy to navigate as the standard web.

## 4. Secure Corporate or Community Namespaces
Akita supports cryptographically secure namespaces owned by specific identities.
* **The Problem:** A community or organization wants to ensure that bad actors cannot hijack the names of their official services (e.g., `hr.corp` or `admin.corp`).
* **The Akita Solution:** The network authority uses `cli create_namespace --namespace corp` with the authority identity, then transfers it if a separate organization identity should own it. Only the current owner can register names ending in `.corp`.

## 5. Off-Grid Disaster Recovery
During a crisis, infrastructure like cell towers and DNS servers goes down. First responders set up ad-hoc mesh networks using portable radios.
* **The Problem:** Coordinating endpoints (command centers, medical tents) in a chaotic, rapidly shifting network topology is nearly impossible without a naming system.
* **The Akita Solution:** Akita DDNS is completely decentralized. As long as any two nodes can communicate, they gossip their registry data. A medic can simply connect to `med-tent-1.disaster` without needing to know which specific radio the tent is currently using.

## 6. Ephemeral "Watch" Triggers
Using the `watch` CLI command, scripts can monitor the network for state changes.
* **The Problem:** A script needs to wait until a specific remote node comes online or fails over to a backup identity before initiating a file transfer.
* **The Akita Solution:** Run `akita-ddns cli watch --name backupserver.storage`. The command prints transitions between unresolved and resolved values, which a supervising script can consume.
