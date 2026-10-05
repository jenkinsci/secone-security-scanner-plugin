package io.jenkins.plugins.secone.security.mobile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class MobileScanGateTest {

	private static Map<String, Integer> sev(int critical, int high, int medium, int low) {
		Map<String, Integer> m = new HashMap<>();
		m.put("Critical", critical);
		m.put("High", high);
		m.put("Medium", medium);
		m.put("Low", low);
		return m;
	}

	@Test
	void failOnSeverityHighFailsOnHighOrCriticalOnly() {
		assertTrue(MobileScanGate.evaluate(sev(0, 0, 9, 9), null, "High", null, null, null, null).isEmpty());
		assertEquals(1, MobileScanGate.evaluate(sev(0, 2, 0, 0), null, "High", null, null, null, null).size());
		assertEquals(2, MobileScanGate.evaluate(sev(1, 2, 0, 0), null, "High", null, null, null, null).size());
	}

	@Test
	void failOnSeverityNoneDisablesTheSeverityFloor() {
		assertTrue(MobileScanGate.evaluate(sev(5, 5, 5, 5), null, "None", null, null, null, null).isEmpty());
	}

	@Test
	void limitsAreMaximumAllowedCounts() {
		assertTrue(MobileScanGate.evaluate(sev(0, 5, 0, 0), null, "None", null, 5, null, null).isEmpty());
		List<String> v = MobileScanGate.evaluate(sev(0, 6, 0, 0), null, "None", null, 5, null, null);
		assertEquals(1, v.size());
		assertTrue(v.get(0).contains("exceed the maximum of 5"));
		assertEquals(1, MobileScanGate.evaluate(sev(1, 0, 0, 0), null, "None", 0, null, null, null).size());
	}

	@Test
	void minScoreFailsBelowThreshold() {
		assertTrue(MobileScanGate.evaluate(sev(0, 0, 0, 0), 70, "None", null, null, null, 70).isEmpty());
		assertEquals(1, MobileScanGate.evaluate(sev(0, 0, 0, 0), 41, "None", null, null, null, 70).size());
	}

	@Test
	void severityKeysAreCaseInsensitiveAndMissingCountsAsZero() {
		Map<String, Integer> lower = new HashMap<>();
		lower.put("critical", 1);
		assertEquals(1, MobileScanGate.evaluate(lower, null, "Critical", null, null, null, null).size());
		assertTrue(MobileScanGate.evaluate(null, null, "High", 0, 0, 0, null).isEmpty());
	}
}
