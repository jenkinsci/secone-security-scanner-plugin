package io.jenkins.plugins.secone.security.mobile;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;

import io.jenkins.plugins.secone.security.pojo.Threshold;

/**
 * Vulnerability threshold for a completed mobile scan, with the same semantics
 * as the sec1Security step: a severity breaches when its count is non-zero and
 * greater than or equal to its threshold, so {@code criticalThreshold: '0'}
 * fails on the first critical finding and a blank threshold is not checked.
 */
public final class MobileScanGate {

	private MobileScanGate() {
	}

	/**
	 * @param bySeverity counts keyed by tier name (case-insensitive); may be null
	 * @param score      {@code summary.aggregate_score}; may be null
	 * @param threshold  per-severity thresholds; may be null
	 * @param minScore   minimum aggregate score; may be null
	 * @return breach messages; empty when nothing breached
	 */
	public static List<String> evaluate(Map<String, Integer> bySeverity, Integer score, Threshold threshold,
			Integer minScore) {
		List<String> breaches = new ArrayList<>();
		if (threshold != null) {
			check(breaches, bySeverity, "Critical", threshold.getCriticalThreshold());
			check(breaches, bySeverity, "High", threshold.getHighThreshold());
			check(breaches, bySeverity, "Medium", threshold.getMediumThreshold());
			check(breaches, bySeverity, "Low", threshold.getLowThreshold());
		}
		if (minScore != null && score != null && score < minScore) {
			breaches.add("Score threshold breached. Found: " + score + ", Minimum: " + minScore);
		}
		return breaches;
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

	private static void check(List<String> breaches, Map<String, Integer> bySeverity, String tier, String limit) {
		String value = StringUtils.trimToNull(limit);
		if (value == null || !NumberUtils.isDigits(value)) {
			return;
		}
		int count = count(bySeverity, tier);
		if (count != 0 && count >= Integer.parseInt(value)) {
			breaches.add(tier + " Vulnerability Threshold breached. Found: " + count + ", Allowed: " + value);
		}
	}
}
