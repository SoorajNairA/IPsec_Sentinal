# External Dataset Inventory Evidence

**Date:** 2026-09-26  
**Artifact root:** `/home/black/ipsec-sentinel-external-datasets` (WSL ext4; not tracked by Git)

This document records observed artifact facts separately from publisher declarations. Public rows and binaries are not part of the native IPsec Sentinel dataset or training table.

## USBVPN2022

- Authoritative source: `https://zenodo.org/records/7301756`
- DOI: `10.5281/zenodo.7301756`
- License metadata: CC BY 4.0
- Artifact: `encrypted_vpn_dataset.zip`
- Publisher and observed size: 811,738,498 bytes
- Publisher MD5: `35a4aef78526440cd6e352de49c4daf2` (matched)
- Local SHA-256: `8039945ffa3f22ff9443787dfbeaf74fd89d33cddd292dcaa6f7cc4b9fe2f54e`
- Archive members: 44; extracted size approximately 15 GiB

The archive contains VPN subsets for SSTP, OpenVPN, PPTP, L2TP, WireGuard, and L2TP IPsec, plus a Non VPN subset. Each protocol directory contains `mail.json`, `meet.json`, `non_streaming.json`, `ssh.json`, and `streaming.json`.

The inspected L2TP IPsec JSON objects identify UDP source/destination port 4500 and contain an `x_packets` sequence. Each observation has signed `bytes`, optional `ip_header_len`, `packets`, `timestamp_start`, and `timestamp_end`; timestamps have microsecond precision and the sign of `bytes` preserves direction. Some rows aggregate two or more packets at one timestamp. Because their individual sizes and timing cannot be recovered, the adapter rejects the complete affected flow rather than treating an aggregate as one packet or inventing observations. Clean flows provide packet timing, size, direction, a top-level session/flow boundary, protocol selection by directory, and source labels by filename. It is NAT-T traffic, not native protocol-50 ESP PCAP.

Compatibility decision: **incompatible for packet-level model evaluation**. The inspected mapped UDP/4500 flows contain aggregated rows, including all five mail flows, both NAT-T meet flows, and every NAT-T streaming flow. The clean meet rows are unrelated ICMP. Individual packet sizes and timing cannot be reconstructed without invention, so no adapter is published. The explicit candidate mappings (`mail` to `email`, `meet` to `voip`, and `streaming` to `video`) remain documented but unusable for normalization. `non_streaming` and `ssh` remain unmapped because assigning them to a supervised class would require guessing. The source is never eligible for native supervised training and does not weaken the strict native ESP-PCAP parser.

## WireGuard, OpenVPN, and strongSwan/IPsec 2026

- Authoritative source: `https://zenodo.org/records/21645499`
- DOI: `10.5281/zenodo.21645499`
- License metadata: CC BY 4.0
- Artifact: `wireguard-openvpn-ipsec-(strongswan)_dataset.zip`
- Publisher size: 4,701,066 bytes
- Observed size: 4,701,066 bytes
- Publisher MD5: `bca99ce9a6ad9a3e2ad03c9f0b63db48` (matched)
- Local SHA-256: `d3a6ec449e43ad9f776827c120a97686981a5d0ac8a197a45b789bd3e8470566`
- Outer archive members: 2,008
- Extracted size: approximately 24 MiB

Observed experiment structure:

- 189 `metadata.json` run records: 63 IPsec, 63 OpenVPN, and 63 WireGuard.
- Platforms/roles: Raspberry Pi, VM, and WSL.
- Wi-Fi bands: 2.4 GHz and 5 GHz.
- Stages: baseline, CPU stress, latency, loss, mobility, and MTU.
- Parameter values include 50 ms added latency, 1% loss, MTU 1400/1480/1500, 60-second runs, iperf TCP/UDP, ping, and CPU samples.
- Each IPsec run has `ipsec_status.txt`; OpenVPN runs have status/process evidence; WireGuard runs have `wg_show.txt`.
- The extracted outer archive contains JSON, text, log, and one nested ZIP file. No `.pcap` or `.pcapng` file was observed in the outer extraction or nested ZIP member list.

Compatibility decision: **catalog-only**. This source is useful for external protocol/configuration, SA/status, platform, and network-condition comparison. It has no application-class labels or packet sequence suitable for application-class training or inference, and aggregate iperf/ping/CPU values are not converted into synthetic packet observations.

## VNAT

- Authoritative source: `https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat`
- Artifact: `VNAT_Dataframe_release_1.h5`
- Publisher and observed size: 1,045,436,008 bytes
- Publisher checksum: absent
- Local SHA-256: `5d0c3d76cd292f19e25b5229719264bc1ddd71920a20bb27a7dec6c7138914de`
- HDF5 logical rows: 33,711 connections
- Columns: `connection`, `timestamps`, `sizes`, `directions`, and `file_names`

The file is a legacy pandas fixed-format frame. All five columns for all 33,711 rows are stored in one `ObjectAtom` VLArray row. Reading that row deserializes the entire payload; the initial generic sample attempt reached approximately 6.9 GiB RSS and was stopped before exhausting the 7.4 GiB WSL memory limit. The inspector now records variable-length/object metadata without deserializing it.

Compatibility decision: **incompatible for bounded normalization in this environment**. The logical semantics are present, but the selected representation does not permit incremental row reads, so a sample limit cannot prevent whole-file deserialization. No adapter is published and the source's precomputed wavelet/TLS features are not substituted for the native feature schema. The 36.1 GB raw PCAP archive remains intentionally excluded.

## ISCXVPN2016

Metadata-only. The official publisher page, retrieved 2026-09-26, describes approximately 28 GB of full-packet PCAP plus ISCXFlowMeter CSV, with regular and VPN forms of Web Browsing, Email, Chat, Streaming, File Transfer, VoIP, and P2P. VPN collection used OpenVPN in UDP mode. The publisher makes the dataset available to researchers through a short reporting form and requires citation of the associated paper, but no CC/SPDX redistribution grant was identified. The full collection is intentionally not downloaded in this phase.
