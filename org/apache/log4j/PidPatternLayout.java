package org.apache.log4j;

import org.apache.log4j.helpers.PidPatternParser;
import org.apache.log4j.helpers.PatternParser;

public class PidPatternLayout extends PatternLayout {
    protected PatternParser createPatternParser(String pattern) {
	return new PidPatternParser(pattern);
    }
}

