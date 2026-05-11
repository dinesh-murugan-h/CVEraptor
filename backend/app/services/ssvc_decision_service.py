from pathlib import Path
import json

RULES_PATH = Path(__file__).resolve().parents[1] / "config" / "ssvc_decision_rules.json"


def _normalise(value: str | None) -> str:
    return str(value or "").strip().lower()


def load_rules() -> dict:
    """
    Load the SSVC decision rules from JSON on every request.

    This is intentional: the decision logic stays editable and reproducible.
    If the SSVC tree changes later, update backend/app/config/ssvc_decision_rules.json
    without rewriting Python logic.
    """
    with RULES_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def _allowed_values(rules: dict, field: str) -> set[str]:
    values = rules["allowed_values"][field]
    return {str(value).lower() for value in values}


def derive_mission_wellbeing(mission_prevalence: str, public_wellbeing: str) -> str:
    mission_prevalence = _normalise(mission_prevalence)
    public_wellbeing = _normalise(public_wellbeing)

    if mission_prevalence == "essential" or public_wellbeing == "irreversible":
        return "high"

    if mission_prevalence == "support" or public_wellbeing == "material":
        return "medium"

    return "low"


def _find_raw_decision(
    rules: dict,
    exploitation: str,
    automatable: str,
    technical_impact: str,
    mission_wellbeing: str,
) -> str:
    for row in rules["decision_table"]:
        if (
            row["exploitation"] == exploitation
            and row["automatable"] == automatable
            and row["technical_impact"] == technical_impact
            and row["mission_wellbeing"] == mission_wellbeing
        ):
            return row["decision"]

    raise ValueError(
        "No SSVC rule matched the selected Exploitation, Automatable, "
        "Technical Impact, and Mission & Well-being values."
    )


def _apply_asset_context(raw_decision: str, asset_presence: str, version_status: str) -> tuple[str, list[str]]:
    rationale = []

    if asset_presence == "not_installed":
        rationale.append(
            "Local context says the affected product is not installed on this system; "
            "the effective decision is reduced to Track for this system."
        )
        return "Track", rationale

    if version_status == "not_affected":
        rationale.append(
            "Local context says the installed version is not in the affected range; "
            "the effective decision is reduced to Track for this system."
        )
        return "Track", rationale

    if asset_presence == "unknown" or version_status == "unknown":
        rationale.append(
            "Asset or version match is unknown. Inventory/version verification is required. "
            "A raw Track result is raised to Track* so it is not silently ignored."
        )

        if raw_decision == "Track":
            return "Track*", rationale

    if asset_presence == "installed" and version_status == "affected":
        rationale.append(
            "Local context says the product is installed and the version is affected, "
            "so the raw SSVC decision is used directly."
        )
    else:
        rationale.append(
            "Local context did not rule out exposure, so the raw SSVC decision is retained."
        )

    return raw_decision, rationale


def decide_ssvc(payload: dict) -> dict:
    rules = load_rules()

    exploitation = _normalise(payload.get("exploitation"))
    automatable = _normalise(payload.get("automatable"))
    technical_impact = _normalise(payload.get("technical_impact"))
    mission_prevalence = _normalise(payload.get("mission_prevalence"))
    public_wellbeing = _normalise(payload.get("public_wellbeing"))
    asset_presence = _normalise(payload.get("asset_presence") or "unknown")
    version_status = _normalise(payload.get("version_status") or "unknown")

    validations = {
        "exploitation": exploitation,
        "automatable": automatable,
        "technical_impact": technical_impact,
        "mission_prevalence": mission_prevalence,
        "public_wellbeing": public_wellbeing,
        "asset_presence": asset_presence,
        "version_status": version_status,
    }

    for field, value in validations.items():
        if value not in _allowed_values(rules, field):
            allowed = ", ".join(sorted(_allowed_values(rules, field)))
            raise ValueError(f"Invalid value for {field}: {value}. Allowed values: {allowed}")

    mission_wellbeing = derive_mission_wellbeing(
        mission_prevalence=mission_prevalence,
        public_wellbeing=public_wellbeing,
    )

    raw_decision = _find_raw_decision(
        rules=rules,
        exploitation=exploitation,
        automatable=automatable,
        technical_impact=technical_impact,
        mission_wellbeing=mission_wellbeing,
    )

    effective_decision, asset_rationale = _apply_asset_context(
        raw_decision=raw_decision,
        asset_presence=asset_presence,
        version_status=version_status,
    )

    rationale = [
        f"Exploitation={exploitation}, Automatable={automatable}, Technical Impact={technical_impact}.",
        f"Mission Prevalence={mission_prevalence} and Public Well-being={public_wellbeing} produce Mission & Well-being={mission_wellbeing}.",
        f"The editable SSVC rule table maps this combination to raw decision {raw_decision}.",
        *asset_rationale,
    ]

    return {
        "source": "local_editable_ssvc_rules",
        "rules_version": rules.get("version"),
        "cve_id": payload.get("cve_id"),
        "inputs": {
            "asset_presence": asset_presence,
            "version_status": version_status,
            "exploitation": exploitation,
            "automatable": automatable,
            "technical_impact": technical_impact,
            "mission_prevalence": mission_prevalence,
            "public_wellbeing": public_wellbeing,
            "notes": payload.get("notes"),
        },
        "derived": {
            "mission_wellbeing": mission_wellbeing,
        },
        "raw_decision": raw_decision,
        "effective_decision": effective_decision,
        "decision_changed_by_asset_context": raw_decision != effective_decision,
        "action_guidance": rules["decision_descriptions"].get(effective_decision, "No guidance configured."),
        "rationale": rationale,
    }


def get_ssvc_decision_options() -> dict:
    rules = load_rules()
    return {
        "source": "local_editable_ssvc_rules",
        "version": rules.get("version"),
        "allowed_values": rules.get("allowed_values", {}),
        "decision_descriptions": rules.get("decision_descriptions", {}),
        "asset_context_policy": rules.get("asset_context_policy", {}),
    }
