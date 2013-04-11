package org.apache.log4j.helpers;

import java.lang.management.ManagementFactory;
import org.apache.log4j.spi.LoggingEvent;

public class PidPatternParser extends PatternParser {
    public PidPatternParser(String pattern) {
	super(pattern);
    }

    protected void finalizeConverter(char c) {
	PatternConverter pc = null;
	switch(c) {
	case 'P':
	    pc = new PidPatternConverter();
	    currentLiteral.setLength(0);
	    break;
	default:
	    super.finalizeConverter(c);
	}

	if (pc != null) {
	    addConverter(pc);
	}
    }

    private class PidPatternConverter extends PatternConverter {
	public String convert(LoggingEvent event) {
	    return ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
	}
    }
}
