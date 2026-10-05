package io.jenkins.plugins.secone.security.mobile;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Quality gate for a completed mobile scan. Limits are maximum allowed counts
 * ({@code maxHigh = 5} passes with 5 high findings and fails with 6), matching
 * the Sec1 Mobile Security CI contract.
 */
public final class MobileScanGate {

	/** Severity tiers from most to least severe, as reported in {@code summary.by_severity}. */
	static final String[] TIERS = { "Critical", "High", "Medium", "Low" };

	private MobileScanGate() {
	}

	/**
	 * @param bySeverity     counts keyed by tier name (case-insensitive); may be null
	 * @param score          {@code summary.aggregate_score}; may be null
	 * @param failOnSeverity lowest tier that fails the build when any finding is at
	 *                       or above it, or "None" to disable
	 * @param maxCritical    maximum critical findings allowed, null for unlimited
	 * @param maxHigh        maximum high findings allowed, null for unlimited
	 * @param maxMedium      maximum medium findings allowed, null for unlimited
	 * @param minScore       minimum aggregate score, null to disable
	 * @return human-readable reasons the gate failed; empty when it passed
	 */
	public static List<String> evaluate(Map<String, Integer> bySeverity, Integer score, String failOnSeverity,
			Integer maxCritical, Integer maxHigh, Integer maxMedium, Integer minScore) {
		List<String> violations = new ArrayList<>();

		int floor = tierIndex(failOnSeverity);
		if (floor >= 0) {
			for (int i = 0; i <= floor; i++) {
				int count = count(bySeverity, TIERS[i]);
				if (count > 0) {
					violations.add(count + " " + TIERS[i] + " finding(s) at or above the fail-on severity ("
							+ TIERS[floor] + ")");
				}
			}
		}
		checkMax(violations, bySeverity, "Critical", maxCritical);
		checkMax(violations, bySeverity, "High", maxHigh);
		checkMax(violations, bySeverity, "Medium", maxMedium);
		if (minScore != null && score != null && score < minScore) {
			violations.add("aggregate score " + score + " is below the minimum " + minScore);
		}
		return violations;
	}

	static int count(Map<String, Integer> bySeverity, String tier) {
		if (bySeverity == null) {
			return 0;
		}
		for (Map.Entry<String, Integer> e : bySeverity.entrySet()) {
			if (e.getKey() != null && e.getKey().equalsIgnoreCase(tier) && e.getValue() != null) {
				return e.getValue();
			}
		}
		return 0;
	}

	/** Index into {@link #TIERS}, or -1 for "None"/blank/unknown. */
	static int tierIndex(String tier) {
		if (tier == null) {
			return -1;
		}
		for (int i = 0; i < TIERS.length; i++) {
			if (TIERS[i].toLowerCase(Locale.ROOT).equals(tier.trim().toLowerCase(Locale.ROOT))) {
				return i;
			}
		}
		return -1;
	}

	private static void checkMax(List<String> violations, Map<String, Integer> bySeverity, String tier, Integer max) {
		if (max == null) {
			return;
		}
		int count = count(bySeverity, tier);
		if (count > max) {
			violations.add(count + " " + tier + " finding(s) exceed the maximum of " + max);
		}
	}
}
