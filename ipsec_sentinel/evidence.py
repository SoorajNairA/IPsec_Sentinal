from __future__ import annotations

from dataclasses import dataclass
import re

from ipsec_sentinel.models import (
    CaptureEvidence,
    Check,
    PfsObservation,
    StageRecord,
    TrafficEvidence,
    Verification,
)


@dataclass(frozen=True)
class SaEvidence:
    ike_state: str
    child_state: str
    ike_proposal: str
    esp_proposal: str
    local_id: str
    remote_id: str
    local_ts: str
    remote_ts: str
    spis: tuple[str, str]


@dataclass(frozen=True)
class XfrmEvidence:
    state_valid: bool
    policy_valid: bool
    state_text: str
    policy_text: str


def parse_sa(text: str) -> SaEvidence:
    children = re.findall(r"protected-nets-\d+ \{([^{}]+)\}", text)
    child = next(
        (candidate for candidate in reversed(children) if _field(candidate, "state") == "INSTALLED"),
        children[-1] if children else "",
    )
    return SaEvidence(
        ike_state=_field(text, "state"),
        child_state=_field(child, "state"),
        ike_proposal=(
            f"{_field(text, 'encr-alg')}_{_field(text, 'encr-keysize')}"
            f"/{_field(text, 'prf-alg')}/{_field(text, 'dh-group')}"
        ),
        esp_proposal=(
            f"{_field(child, 'encr-alg')}_{_field(child, 'encr-keysize')}"
        ),
        local_id=_field(text, "local-id"),
        remote_id=_field(text, "remote-id"),
        local_ts=_bracket_field(child, "local-ts"),
        remote_ts=_bracket_field(child, "remote-ts"),
        spis=(_field(child, "spi-in"), _field(child, "spi-out")),
    )


def parse_xfrm(text: str, gateway: str | None = None) -> XfrmEvidence:
    state_text, marker, policy_text = text.partition("POLICY")
    if not marker:
        policy_text = ""
    if gateway is None:
        gateway = "gateway-a" if "src 192.0.2.1 dst 192.0.2.2" in state_text else "gateway-b"
    if gateway == "gateway-a":
        outbound = ("192.0.2.1", "192.0.2.2", "10.10.0.0/24", "10.20.0.0/24")
    else:
        outbound = ("192.0.2.2", "192.0.2.1", "10.20.0.0/24", "10.10.0.0/24")
    outer_local, outer_remote, local_ts, remote_ts = outbound
    state_valid = all(
        (
            f"src {outer_local} dst {outer_remote}" in state_text,
            f"src {outer_remote} dst {outer_local}" in state_text,
            state_text.count("proto esp") >= 2,
            state_text.count("mode tunnel") >= 2,
            state_text.count("aead rfc4106(gcm(aes))") >= 2,
            "dir out" in state_text,
            "dir in" in state_text,
        )
    )
    policy_valid = all(
        (
            f"src {local_ts} dst {remote_ts}" in policy_text,
            f"src {remote_ts} dst {local_ts}" in policy_text,
            "dir out" in policy_text,
            "dir fwd" in policy_text,
            "dir in" in policy_text,
            policy_text.count("proto esp") >= 3,
            policy_text.count("mode tunnel") >= 3,
        )
    )
    return XfrmEvidence(state_valid, policy_valid, state_text, policy_text)


def parse_ping(text: str) -> TrafficEvidence:
    match = re.search(r"(\d+) packets transmitted, (\d+) received", text)
    sent = int(match.group(1)) if match else 0
    received = int(match.group(2)) if match else 0
    return TrafficEvidence("ICMP", sent, received, sent > 0 and sent == received)


def evaluate_pfs(
    before_sas: dict[str, str],
    after_sas: dict[str, str] | None,
    log_segment: str,
    *,
    attempted: bool,
) -> PfsObservation:
    if not attempted:
        return PfsObservation.not_tested()
    after_sas = after_sas or {}
    changes: list[str] = []
    changed = True
    for gateway in ("gateway-a", "gateway-b"):
        before = parse_sa(before_sas.get(gateway, "")).spis
        after = parse_sa(after_sas.get(gateway, "")).spis
        gateway_changed = bool(all(before) and all(after) and before != after)
        changed = changed and gateway_changed
        changes.append(f"{gateway} SPIs {before} -> {after}")
    selected = "selected proposal: ESP:AES_GCM_16_256/ECP_384/NO_EXT_SEQ"
    fresh_dh = selected in log_segment
    status = "VERIFIED" if changed and fresh_dh else "NOT_VERIFIED"
    evidence = tuple(changes + [f"fresh_dh_selected={fresh_dh}", selected if fresh_dh else "fresh DH selection missing"])
    return PfsObservation(status=status, rekey_observed=True, evidence=evidence)


def evaluate_baseline(
    sas: dict[str, str],
    xfrm: dict[str, str],
    ping: str,
    capture: CaptureEvidence,
    *,
    run_id: str = "",
    pfs: PfsObservation | None = None,
) -> Verification:
    checks: list[Check] = []
    expected = {
        "gateway-a": ("gateway-a", "gateway-b", "10.10.0.0/24", "10.20.0.0/24"),
        "gateway-b": ("gateway-b", "gateway-a", "10.20.0.0/24", "10.10.0.0/24"),
    }
    for gateway in ("gateway-a", "gateway-b"):
        sa = parse_sa(sas.get(gateway, ""))
        local_id, remote_id, local_ts, remote_ts = expected[gateway]
        checks.extend(
            (
                _check(f"ike.{gateway}.established", sa.ike_state == "ESTABLISHED", sa.ike_state),
                _check(f"child.{gateway}.installed", sa.child_state == "INSTALLED", sa.child_state),
                _check(
                    f"identity.{gateway}",
                    (sa.local_id, sa.remote_id) == (local_id, remote_id),
                    f"{sa.local_id}->{sa.remote_id}",
                ),
                _check(
                    f"proposal.ike.{gateway}",
                    sa.ike_proposal == "AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384",
                    sa.ike_proposal,
                ),
                _check(
                    f"proposal.esp.{gateway}",
                    sa.esp_proposal == "AES_GCM_16_256",
                    sa.esp_proposal,
                ),
                _check(
                    f"selectors.{gateway}",
                    (sa.local_ts, sa.remote_ts) == (local_ts, remote_ts),
                    f"{sa.local_ts}->{sa.remote_ts}",
                ),
            )
        )
        parsed_xfrm = parse_xfrm(xfrm.get(gateway, ""), gateway)
        checks.extend(
            (
                _check(f"xfrm.state.{gateway}", parsed_xfrm.state_valid, "native ESP tunnel state"),
                _check(f"xfrm.policy.{gateway}", parsed_xfrm.policy_valid, "protected subnet policies"),
            )
        )

    traffic = parse_ping(ping)
    checks.extend(
        (
            _check("traffic.icmp", traffic.success and traffic.sent == 5, f"{traffic.received}/{traffic.sent}"),
            _check("capture.ike", capture.ike_packets > 0, str(capture.ike_packets)),
            _check("capture.esp", capture.esp_packets > 0, str(capture.esp_packets)),
            _check("capture.natt_absent", capture.natt_packets == 0, str(capture.natt_packets)),
            _check(
                "capture.cleartext_absent",
                capture.cleartext_packets == 0,
                str(capture.cleartext_packets),
            ),
        )
    )
    if pfs is not None:
        checks.append(
            _check(
                "pfs.rekey_fresh_dh",
                pfs.status == "VERIFIED" and pfs.rekey_observed,
                pfs.status,
            )
        )
    status = "PASS" if all(check.passed for check in checks) else "FAIL"
    failed = [check.name for check in checks if not check.passed]
    message = "all required checks passed" if not failed else ", ".join(failed)
    return Verification(
        run_id=run_id,
        status=status,
        stages=(StageRecord("verdict", status, message),),
        checks=tuple(checks),
    )


def _field(text: str, name: str) -> str:
    match = re.search(rf"(?:^|\s){re.escape(name)}=([^\s}}]+)", text)
    return match.group(1) if match else ""


def _bracket_field(text: str, name: str) -> str:
    match = re.search(rf"(?:^|\s){re.escape(name)}=\[([^]]+)\]", text)
    return match.group(1) if match else ""


def _check(name: str, passed: bool, evidence: str) -> Check:
    return Check(name=name, passed=passed, evidence=(evidence,))
