# Canonical SOAR decision-band policy.
# Export: `nickel export config/soar_policy.ncl > config/soar_policy.json`
# Python ScoringEngine loads the JSON artifact (Nickel remains the typed source).

{
  schema_version | Number = 1,
  ignore_threshold | Number = 40,
  auto_isolate_threshold | Number = 70,
  anomaly_boost | Number = 15,
  anomaly_flag_threshold | Number = -0.5,
}
