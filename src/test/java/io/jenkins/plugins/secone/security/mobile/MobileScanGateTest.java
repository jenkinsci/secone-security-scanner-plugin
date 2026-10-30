package io.jenkins.plugins.secone.security.mobile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.jenkins.plugins.secone.security.pojo.Threshold;

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
	void noThresholdMeansNoBreach() {
		assertTrue(MobileScanGate.evaluate(sev(9, 9, 9, 9), 0, null, null).isEmpty());
	}

	@Test
	void breachesWhenNonZeroCountReachesThresholdLikeSec1Security() {
		Threshold t = new Threshold("0", "5", "", "", "fail");
		assertTrue(MobileScanGate.evaluate(sev(0, 4, 50, 50), null, t, null).isEmpty());
		List<String> five = MobileScanGate.evaluate(sev(0, 5, 0, 0), null, t, null);
		assertEquals(1, five.size());
		assertEquals("High Vulnerability Threshold breached. Found: 5, Allowed: 5", five.get(0));
		assertEquals(1, MobileScanGate.evaluate(sev(1, 0, 0, 0), null, t, null).size());
	}

	@Test
	void blankOrNonNumericThresholdsAreNotChecked() {
		Threshold t = new Threshold(" ", "abc", null, "", "fail");
		assertTrue(MobileScanGate.evaluate(sev(9, 9, 9, 9), null, t, null).isEmpty());
	}

	@Test
	void minScoreBreachesBelowValue() {
		assertTrue(MobileScanGate.evaluate(sev(0, 0, 0, 0), 70, null, 70).isEmpty());
		assertEquals("Score threshold breached. Found: 41, Minimum: 70",
				MobileScanGate.evaluate(sev(0, 0, 0, 0), 41, null, 70).get(0));
	}

	@Test
	void severityKeysAreCaseInsensitive() {
		Map<String, Integer> lower = new HashMap<>();
		lower.put("critical", 1);
		assertEquals(1, MobileScanGate.evaluate(lower, null, new Threshold("0", "", "", "", "fail"), null).size());
	}
}
