# GCP Live Lab Evidence

## Scope

Prototype cloud support is limited to the four validated IPsec scenarios plus
ICMP, Video, NAT-T capture normalization, ML inference, rekey/PFS, analysis,
SSE/Mystery presentation, and exact disconnect cleanup.

## Safety gate

No GCP network, firewall, disk, or VM mutation is authorized by the design or
implementation commits. Before provisioning, this document will record the
active account/project, source `/32`, resource collision check, exact rendered
commands, approval digest, cost estimate, rollback commands, and the user's
separate approval.

## Verification record

### 2026-09-29 read-only preflight

- Active account: `soorajrocks47@gmail.com`
- Project: `ipsec-sentinel` (`429285250074`, lifecycle `ACTIVE`)
- Region/zone used explicitly by every command: `asia-south1` / `asia-south1-a`
- Detected operator source: `49.37.226.254/32`
- Compute Engine API: enabled
- `e2-micro` availability in `asia-south1-a`: confirmed
- Name-collision checks: no matching VPC, subnet, firewall rule, or VM exists
- GCP mutations performed: none

The compact prototype checks passed (5 tests). Python compilation/import checks
and shell syntax validation also passed. The direct command-preview and
provisioning entry points were verified from the repository root.

### Exact creation command set

Approval digest:
`b6c4994ac0fa8fb258690419ad3506922a3972199e7567c1b6ac2435d240b151`

```text
gcloud --project=ipsec-sentinel compute networks create ipsec-sentinel-lab --subnet-mode=custom --bgp-routing-mode=regional
gcloud --project=ipsec-sentinel compute networks subnets create ipsec-sentinel-lab-asia-south1 --network=ipsec-sentinel-lab --region=asia-south1 --range=10.70.0.0/24
gcloud --project=ipsec-sentinel compute firewall-rules create ipsec-sentinel-ike-natt --network=ipsec-sentinel-lab --direction=INGRESS --action=ALLOW --rules=udp:500,udp:4500 --source-ranges=49.37.226.254/32 --target-tags=ipsec-sentinel-vpn
gcloud --project=ipsec-sentinel compute firewall-rules create ipsec-sentinel-provision-ssh --network=ipsec-sentinel-lab --direction=INGRESS --action=ALLOW --rules=tcp:22 --source-ranges=49.37.226.254/32 --target-tags=ipsec-sentinel-vpn
gcloud --project=ipsec-sentinel compute instances create vpn-secure --zone=asia-south1-a --machine-type=e2-micro --network-interface=network=ipsec-sentinel-lab,subnet=ipsec-sentinel-lab-asia-south1,stack-type=IPV4_ONLY --image-family=debian-12 --image-project=debian-cloud --boot-disk-size=10GB --boot-disk-type=pd-balanced --can-ip-forward --no-service-account --no-scopes --tags=ipsec-sentinel-vpn --labels=deployment=gcp-live-lab-v1,scenario=secure-baseline --no-restart-on-failure
gcloud --project=ipsec-sentinel compute instances stop vpn-secure --zone=asia-south1-a
gcloud --project=ipsec-sentinel compute instances create vpn-aes128 --zone=asia-south1-a --machine-type=e2-micro --network-interface=network=ipsec-sentinel-lab,subnet=ipsec-sentinel-lab-asia-south1,stack-type=IPV4_ONLY --image-family=debian-12 --image-project=debian-cloud --boot-disk-size=10GB --boot-disk-type=pd-balanced --can-ip-forward --no-service-account --no-scopes --tags=ipsec-sentinel-vpn --labels=deployment=gcp-live-lab-v1,scenario=aes128-gcm --no-restart-on-failure
gcloud --project=ipsec-sentinel compute instances stop vpn-aes128 --zone=asia-south1-a
gcloud --project=ipsec-sentinel compute instances create vpn-cbc --zone=asia-south1-a --machine-type=e2-micro --network-interface=network=ipsec-sentinel-lab,subnet=ipsec-sentinel-lab-asia-south1,stack-type=IPV4_ONLY --image-family=debian-12 --image-project=debian-cloud --boot-disk-size=10GB --boot-disk-type=pd-balanced --can-ip-forward --no-service-account --no-scopes --tags=ipsec-sentinel-vpn --labels=deployment=gcp-live-lab-v1,scenario=aes256-cbc --no-restart-on-failure
gcloud --project=ipsec-sentinel compute instances stop vpn-cbc --zone=asia-south1-a
gcloud --project=ipsec-sentinel compute instances create vpn-no-pfs --zone=asia-south1-a --machine-type=e2-micro --network-interface=network=ipsec-sentinel-lab,subnet=ipsec-sentinel-lab-asia-south1,stack-type=IPV4_ONLY --image-family=debian-12 --image-project=debian-cloud --boot-disk-size=10GB --boot-disk-type=pd-balanced --can-ip-forward --no-service-account --no-scopes --tags=ipsec-sentinel-vpn --labels=deployment=gcp-live-lab-v1,scenario=no-pfs --no-restart-on-failure
gcloud --project=ipsec-sentinel compute instances stop vpn-no-pfs --zone=asia-south1-a
gcloud --project=ipsec-sentinel compute firewall-rules delete ipsec-sentinel-provision-ssh
```

The final firewall deletion is a post-provisioning action: temporary SSH is
removed after all four responders have been configured. It is not run before
provisioning.

### Destructive rollback plan (not automatically authorized)

```text
gcloud --project=ipsec-sentinel compute instances delete vpn-no-pfs --zone=asia-south1-a --delete-disks=all
gcloud --project=ipsec-sentinel compute instances delete vpn-cbc --zone=asia-south1-a --delete-disks=all
gcloud --project=ipsec-sentinel compute instances delete vpn-aes128 --zone=asia-south1-a --delete-disks=all
gcloud --project=ipsec-sentinel compute instances delete vpn-secure --zone=asia-south1-a --delete-disks=all
gcloud --project=ipsec-sentinel compute firewall-rules delete ipsec-sentinel-provision-ssh
gcloud --project=ipsec-sentinel compute firewall-rules delete ipsec-sentinel-ike-natt
gcloud --project=ipsec-sentinel compute networks subnets delete ipsec-sentinel-lab-asia-south1 --region=asia-south1
gcloud --project=ipsec-sentinel compute networks delete ipsec-sentinel-lab
```

Rollback deletion requires separate approval if it becomes necessary. Normal
Live Lab cleanup stops only the owned active VM and leaves infrastructure in
place.

### Cost and exposure estimate

Only one VM is intended to run during a session. Budget approximately
`$0.01-$0.02/hour` for that VM plus its ephemeral external IPv4 and small
network egress. Four stopped 10 GB balanced persistent disks remain billable;
allow roughly `$5-$8/month` total as a conservative prototype estimate. If all
four VMs were accidentally left running continuously, the order-of-magnitude
cost would be about `$35-$50/month` plus disks and egress. Actual Mumbai-region
billing and taxes may differ, so Cloud Billing remains authoritative.

Permanent ingress is limited to UDP/500 and UDP/4500 from the detected operator
`/32`; protocol 50 is not exposed. TCP/22 is source-`/32` and temporary. VMs
have ephemeral public IPv4 addresses, no attached service account or OAuth
scopes, an allowlisted scenario label/tag, and a 15-minute shutdown watchdog.
Changing operator egress invalidates this preview and requires a new digest.

## Known limitation: cloud Video latency

The retained secure-baseline cloud session proved VM lifecycle, readiness,
NAT-T IKEv2, CHILD_SA and XFRM installation, tunnel activation, ICMP, live ESP
observation, and complete disconnect/VM-stop cleanup. A separate CBC session
also established its NAT-T IKE and CHILD SAs.

The complete interactive flow currently stops at cloud Video validation on the
`e2-micro` responder. All planned Video segments and bytes were received, but
two middle segments experienced intermittent encrypted data-plane pauses; a
four-second paced workload completed in approximately 24.8 seconds. The
client-side outer capture had no missing ESP sequence numbers and zero kernel
capture drops, but it cannot distinguish encrypted TCP retransmission or
backpressure from responder scheduling or CPU starvation. Validation remains
strict rather than accepting this anomalous duration.

This is a cloud Video performance limitation, not evidence of an IKE,
CHILD_SA, XFRM, NAT-T, ICMP, or cleanup failure. Determining the underlying
cause would require a targeted responder-side TCP capture and CPU/scheduling
telemetry; that investigation is intentionally deferred for the prototype.
