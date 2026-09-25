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
from ipsec_sentinel.scenario import NegotiatedPolicy, Scenario, negotiated_policy


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
    ike_integrity: str = ""
    esp_integrity: str = ""


@dataclass(frozen=True)
class XfrmEvidence:
    state_valid: bool
    policy_valid: bool
    state_text: str
    policy_text: str


@dataclass(frozen=True)
class XfrmState:
    source: str
    destination: str
    protocol: str
    spi: str
    mode: str
    direction: str
    aes_gcm: bool
    aes_cbc: bool
    hmac_sha256: bool


@dataclass(frozen=True)
class XfrmPolicy:
    source: str
    destination: str
    direction: str
    template_source: str
    template_destination: str
    protocol: str
    spi: str
    mode: str


def parse_sa(text: str) -> SaEvidence:
    children = re.findall(r"protected-nets-\d+ \{([^{}]+)\}", text)
    child = next(
        (candidate for candidate in reversed(children) if _field(candidate, "state") == "INSTALLED"),
        children[-1] if children else "",
    )
    return SaEvidence(
        ike_state=_field(text, "state"),
        child_state=_field(child, "state"),
        ike_proposal=_proposal(
            _field(text, "encr-alg"), _field(text, "encr-keysize"),
            _field(text, "integ-alg"), _field(text, "prf-alg"),
            _field(text, "dh-group"),
        ),
        esp_proposal=_proposal(
            _field(child, "encr-alg"), _field(child, "encr-keysize"),
            _field(child, "integ-alg"),
        ),
        local_id=_field(text, "local-id"),
        remote_id=_field(text, "remote-id"),
        local_ts=_bracket_field(child, "local-ts"),
        remote_ts=_bracket_field(child, "remote-ts"),
        spis=(_field(child, "spi-in"), _field(child, "spi-out")),
        ike_integrity=_field(text, "integ-alg"),
        esp_integrity=_field(child, "integ-alg"),
    )


def parse_xfrm(
    text: str,
    gateway: str | None = None,
    sa: SaEvidence | None = None,
    policy: NegotiatedPolicy | None = None,
) -> XfrmEvidence:
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
    states = _parse_xfrm_states(state_text)
    policies = _parse_xfrm_policies(policy_text)
    spi_in, spi_out = sa.spis if sa is not None else (None, None)
    state_valid = all(
        (
            _has_state(states, outer_local, outer_remote, "out", spi_out, policy),
            _has_state(states, outer_remote, outer_local, "in", spi_in, policy),
        )
    )
    policy_valid = all(
        (
            _has_policy(
                policies, local_ts, remote_ts, "out",
                outer_local, outer_remote, spi_out,
            ),
            _has_policy(
                policies, remote_ts, local_ts, "fwd",
                outer_remote, outer_local, None,
            ),
            _has_policy(
                policies, remote_ts, local_ts, "in",
                outer_remote, outer_local, None,
            ),
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
    completed: bool = True,
    pfs_required: bool = True,
    expected_child_proposal: str = "AES_GCM_16_256",
    expected_dh_group: str | None = "ECP_384",
) -> PfsObservation:
    if not attempted:
        return PfsObservation.not_tested()
    after_sas = after_sas or {}
    before_a = parse_sa(before_sas.get("gateway-a", "")).spis
    before_b = parse_sa(before_sas.get("gateway-b", "")).spis
    after_a = parse_sa(after_sas.get("gateway-a", "")).spis
    after_b = parse_sa(after_sas.get("gateway-b", "")).spis
    changes = [
        f"gateway-a SPIs {before_a} -> {after_a}",
        f"gateway-b SPIs {before_b} -> {after_b}",
    ]
    present = all(before_a + before_b + after_a + after_b)
    reciprocal = before_a == tuple(reversed(before_b)) and after_a == tuple(reversed(after_b))
    changed = all(old != new for old, new in zip(before_a + before_b, after_a + after_b))
    suffix = f"/{expected_dh_group}" if pfs_required and expected_dh_group else ""
    selected = (
        f"selected proposal: ESP:{expected_child_proposal}{suffix}/NO_EXT_SEQ"
    )
    selected_match = selected in log_segment
    proposal_lines = re.findall(r"selected proposal: ESP:([^\r\n]+)", log_segment)
    unexpected_dh = any("/ECP_" in line for line in proposal_lines)
    crypto_verified = selected_match and (pfs_required or not unexpected_dh)
    verified = completed and present and reciprocal and changed and crypto_verified
    if verified:
        status = "VERIFIED" if pfs_required else "VERIFIED_DISABLED"
    else:
        status = "NOT_VERIFIED"
    evidence = tuple(
        changes
        + [
            f"rekey_completed={completed}",
            f"reciprocal_spis={reciprocal}",
            f"both_directions_changed={changed}",
            f"pfs_configured={pfs_required}",
            f"expected_rekey_proposal_selected={selected_match}",
            f"unexpected_child_dh={unexpected_dh}",
            selected if selected_match else "expected CHILD rekey proposal missing",
        ]
    )
    return PfsObservation(status=status, rekey_observed=True, evidence=evidence)


def _sa_xfrm_checks(
    sas: dict[str, str],
    xfrm: dict[str, str],
    scenario: Scenario | None = None,
) -> list[Check]:
    checks: list[Check] = []
    policy = negotiated_policy(scenario or "secure-baseline")
    parsed_sas = {
        gateway: parse_sa(sas.get(gateway, ""))
        for gateway in ("gateway-a", "gateway-b")
    }
    a_spis = parsed_sas["gateway-a"].spis
    b_spis = parsed_sas["gateway-b"].spis
    checks.append(
        _check(
            "child.spis.reciprocal",
            bool(all(a_spis + b_spis) and a_spis == tuple(reversed(b_spis))),
            f"gateway-a={a_spis} gateway-b={b_spis}",
        )
    )
    expected = {
        "gateway-a": ("gateway-a", "gateway-b", "10.10.0.0/24", "10.20.0.0/24"),
        "gateway-b": ("gateway-b", "gateway-a", "10.20.0.0/24", "10.10.0.0/24"),
    }
    for gateway in ("gateway-a", "gateway-b"):
        sa = parsed_sas[gateway]
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
                    sa.ike_proposal == _policy_ike_proposal(policy),
                    sa.ike_proposal,
                ),
                _check(
                    f"proposal.esp.{gateway}",
                    sa.esp_proposal == _policy_esp_proposal(policy),
                    sa.esp_proposal,
                ),
                _check(
                    f"selectors.{gateway}",
                    (sa.local_ts, sa.remote_ts) == (local_ts, remote_ts),
                    f"{sa.local_ts}->{sa.remote_ts}",
                ),
            )
        )
        parsed_xfrm = parse_xfrm(xfrm.get(gateway, ""), gateway, sa, policy)
        checks.extend(
            (
                _check(f"xfrm.state.{gateway}", parsed_xfrm.state_valid, "native ESP tunnel state"),
                _check(f"xfrm.policy.{gateway}", parsed_xfrm.policy_valid, "protected subnet policies"),
            )
        )

    return checks


def _capture_checks(capture: CaptureEvidence) -> list[Check]:
    return [
        _check("capture.ike", capture.ike_packets > 0, str(capture.ike_packets)),
        _check("capture.esp", capture.esp_packets > 0, str(capture.esp_packets)),
        _check("capture.natt_absent", capture.natt_packets == 0, str(capture.natt_packets)),
        _check(
            "capture.cleartext_absent",
            capture.cleartext_packets == 0,
            str(capture.cleartext_packets),
        ),
    ]


def _verification(run_id: str, checks: list[Check]) -> Verification:
    status = "PASS" if all(check.passed for check in checks) else "FAIL"
    failed = [check.name for check in checks if not check.passed]
    message = "all required checks passed" if not failed else ", ".join(failed)
    return Verification(
        run_id=run_id,
        status=status,
        stages=(StageRecord("verdict", status, message),),
        checks=tuple(checks),
    )


def evaluate_tunnel(
    sas: dict[str, str], xfrm: dict[str, str], *, run_id: str = "",
    scenario: Scenario | None = None,
) -> Verification:
    return _verification(run_id, _sa_xfrm_checks(sas, xfrm, scenario))


def evaluate_ipsec(
    sas: dict[str, str],
    xfrm: dict[str, str],
    capture: CaptureEvidence,
    *,
    run_id: str = "",
    pfs: PfsObservation | None = None,
    scenario: Scenario | None = None,
) -> Verification:
    checks = list(
        evaluate_tunnel(sas, xfrm, run_id=run_id, scenario=scenario).checks
    )
    checks.extend(_capture_checks(capture))
    if pfs is not None:
        checks.append(
            _check(
                "pfs.rekey_fresh_dh",
                pfs.status == _expected_pfs_status(scenario) and pfs.rekey_observed,
                pfs.status,
            )
        )
    return _verification(run_id, checks)


def evaluate_baseline(
    sas: dict[str, str],
    xfrm: dict[str, str],
    ping: str,
    capture: CaptureEvidence,
    *,
    run_id: str = "",
    pfs: PfsObservation | None = None,
    scenario: Scenario | None = None,
) -> Verification:
    checks = _sa_xfrm_checks(sas, xfrm, scenario)
    traffic = parse_ping(ping)
    checks.append(
        _check(
            "traffic.icmp",
            traffic.success and traffic.sent == 5,
            f"{traffic.received}/{traffic.sent}",
        )
    )
    checks.extend(_capture_checks(capture))
    if pfs is not None:
        checks.append(
            _check(
                "pfs.rekey_fresh_dh",
                pfs.status == _expected_pfs_status(scenario) and pfs.rekey_observed,
                pfs.status,
            )
        )
    return _verification(run_id, checks)


def _field(text: str, name: str) -> str:
    match = re.search(rf"(?:^|\s){re.escape(name)}=([^\s}}]+)", text)
    return match.group(1) if match else ""


def _bracket_field(text: str, name: str) -> str:
    match = re.search(rf"(?:^|\s){re.escape(name)}=\[([^]]+)\]", text)
    return match.group(1) if match else ""


def _check(name: str, passed: bool, evidence: str) -> Check:
    return Check(name=name, passed=passed, evidence=(evidence,))


def _proposal(
    encryption: str,
    keysize: str,
    integrity: str = "",
    prf: str = "",
    dh_group: str = "",
) -> str:
    values = [f"{encryption}_{keysize}"] if encryption and keysize else []
    values.extend(value for value in (integrity, prf, dh_group) if value)
    return "/".join(values)


def _policy_ike_proposal(policy: NegotiatedPolicy) -> str:
    values = [policy.ike_encryption]
    values.extend(
        value
        for value in (policy.ike_integrity, policy.ike_prf, policy.ike_dh_group)
        if value
    )
    return "/".join(values)


def _policy_esp_proposal(policy: NegotiatedPolicy) -> str:
    return "/".join(
        value for value in (policy.esp_encryption, policy.esp_integrity) if value
    )


def _expected_pfs_status(scenario: Scenario | None) -> str:
    return "VERIFIED" if scenario is None or scenario.ipsec.pfs else "VERIFIED_DISABLED"


def _parse_xfrm_states(text: str) -> tuple[XfrmState, ...]:
    records: list[XfrmState] = []
    for match in re.finditer(
        r"^src (\S+) dst (\S+)\s*\n((?:[ \t].*(?:\n|$))*)",
        text,
        re.MULTILINE,
    ):
        source, destination, body = match.groups()
        records.append(
            XfrmState(
                source=source,
                destination=destination,
                protocol=_body_field(body, "proto"),
                spi=_normalize_spi(_body_field(body, "spi")),
                mode=_body_field(body, "mode"),
                direction=_body_field(body, "dir"),
                aes_gcm="aead rfc4106(gcm(aes))" in body,
                aes_cbc="enc cbc(aes)" in body,
                hmac_sha256="auth-trunc hmac(sha256)" in body,
            )
        )
    return tuple(records)


def _parse_xfrm_policies(text: str) -> tuple[XfrmPolicy, ...]:
    records: list[XfrmPolicy] = []
    for match in re.finditer(
        r"^src (\S+) dst (\S+)\s*\n((?:[ \t].*(?:\n|$))*)",
        text,
        re.MULTILINE,
    ):
        source, destination, body = match.groups()
        template = re.search(r"tmpl src (\S+) dst (\S+)", body)
        if template is None:
            continue
        records.append(
            XfrmPolicy(
                source=source,
                destination=destination,
                direction=_body_field(body, "dir"),
                template_source=template.group(1),
                template_destination=template.group(2),
                protocol=_body_field(body, "proto"),
                spi=_normalize_spi(_body_field(body, "spi")),
                mode=_body_field(body, "mode"),
            )
        )
    return tuple(records)


def _body_field(body: str, name: str) -> str:
    match = re.search(rf"(?:^|\s){re.escape(name)} (\S+)", body)
    return match.group(1) if match else ""


def _normalize_spi(value: str | None) -> str:
    return (value or "").lower().removeprefix("0x")


def _has_state(
    states: tuple[XfrmState, ...],
    source: str,
    destination: str,
    direction: str,
    spi: str | None,
    policy: NegotiatedPolicy | None = None,
) -> bool:
    expected_spi = _normalize_spi(spi)
    policy = policy or negotiated_policy("secure-baseline")
    return any(
        state.source == source
        and state.destination == destination
        and state.direction == direction
        and state.protocol == "esp"
        and state.mode == "tunnel"
        and (
            state.aes_gcm
            if policy.esp_encryption.startswith("AES_GCM")
            else state.aes_cbc and (
                not policy.esp_integrity or state.hmac_sha256
            )
        )
        and (not expected_spi or state.spi == expected_spi)
        for state in states
    )


def _has_policy(
    policies: tuple[XfrmPolicy, ...],
    source: str,
    destination: str,
    direction: str,
    template_source: str,
    template_destination: str,
    spi: str | None,
) -> bool:
    expected_spi = _normalize_spi(spi)
    return any(
        policy.source == source
        and policy.destination == destination
        and policy.direction == direction
        and policy.template_source == template_source
        and policy.template_destination == template_destination
        and policy.protocol == "esp"
        and policy.mode == "tunnel"
        and (not expected_spi or policy.spi == expected_spi)
        for policy in policies
    )
