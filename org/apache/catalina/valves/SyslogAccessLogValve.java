/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * Heavily inspired by the log4j SyslogAppender!
 */


package org.apache.catalina.valves;


import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.DatagramPacket;
import java.net.UnknownHostException;
import java.net.SocketException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import org.apache.catalina.AccessLog;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.util.LifecycleSupport;
import org.apache.catalina.util.StringManager;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * <p>
 * This Tomcat extension logs server access directly to a syslogd, and can 
 * be used instead (or in combination) of the regular file-based access log
 * implemented in  AccessLogValve.
 * To use, copy into the server/classes directory of the Tomcat installation
 * and configure in server.xml as:
 * <pre>
 *      &lt;Valve className="org.apache.catalina.valves.SyslogAccessLogValve"
 *          hostname="<i>syslog_host</i>"      <!-- defaults to localhost -->
 *          facility="<i>syslog_facility</i>"   <!-- defaults to LOG_USER -->
 *          level="<i>level</i>"               <!-- defaults to LOG_INFO -->
 *          level="<i>header</i>"              <!-- defaults to true -->
 *          pattern="combined"
 *          resolveHosts="false"
 *      /&gt;
 * </pre>
 * </p>
 * <p>
 * Many parameters can be configured, such as the loghost, facility & level.
 * But they also use sensible defaults.
 * The same options as AccessLogValve are supported, such as
 * <code>resolveHosts</code> and <code>pattern</code>.
 * </p>
 * <p>
 * This logger can be used at the level of the Engine context (being shared
 * by all the defined hosts) or the Host context (one instance of the logger 
 * per host).
 * </p>
 * <p>
 * <i>TO DO: provide option for excluding logging of certain MIME types.</i>
 * </p>
 * 
 * @author Marco Walther
 */

public final class SyslogAccessLogValve extends AccessLogValve {
    // The following constants are extracted from a syslog.h file
    // copyrighted by the Regents of the University of California
    // I hope nobody at Berkley gets offended.

    /** system is unusable */
    final static private int LOG_EMERG    = 0;
    /** action must be taken immediately */
    final static private int LOG_ALERT    = 1;
    /** critical conditions */
    final static private int LOG_CRIT     = 2;
    /** error conditions */
    final static private int LOG_ERR      = 3;
    /** warning conditions */
    final static private int LOG_WARNING  = 4;
    /** normal but significant condition */
    final static private int LOG_NOTICE   = 5;
    /** informational */
    final static private int LOG_INFO     = 6;
    /** debug-level messages */
    final static private int LOG_DEBUG    = 7;

    /** Kernel messages */
    final static private int LOG_KERN     = 0 << 3;
    /** Random user-level messages */
    final static private int LOG_USER     = 1 << 3;
    /** Mail system */
    final static private int LOG_MAIL     = 2 << 3;
    /** System daemons */
    final static private int LOG_DAEMON   = 3 << 3;
    /** security/authorization messages */
    final static private int LOG_AUTH     = 4 << 3;
    /** messages generated internally by syslogd */
    final static private int LOG_SYSLOG   = 5 << 3;
    /** line printer subsystem */
    final static private int LOG_LPR      = 6 << 3;
    /** network news subsystem */
    final static private int LOG_NEWS     = 7 << 3;
    /** UUCP subsystem */
    final static private int LOG_UUCP     = 8 << 3;
    /** clock daemon */
    final static private int LOG_CRON     = 9 << 3;
    /** security/authorization  messages (private) */
    final static private int LOG_AUTHPRIV = 10 << 3;
    /** ftp daemon */
    final static private int LOG_FTP      = 11 << 3;

    // other codes through 15 reserved for system use
    /** reserved for local use */
    final static private int LOG_LOCAL0 = 16 << 3;
    /** reserved for local use */
    final static private int LOG_LOCAL1 = 17 << 3;
    /** reserved for local use */
    final static private int LOG_LOCAL2 = 18 << 3;
    /** reserved for local use */
    final static private int LOG_LOCAL3 = 19 << 3;
    /** reserved for local use */
    final static private int LOG_LOCAL4 = 20 << 3;
    /** reserved for local use */
    final static private int LOG_LOCAL5 = 21 << 3;
    /** reserved for local use */
    final static private int LOG_LOCAL6 = 22 << 3;
    /** reserved for local use */
    final static private int LOG_LOCAL7 = 23 << 3;

    // ----------------------------------------------------------- Constructors


    /**
     * Class constructor. Initializes the fields with the default values.
     * The defaults are:
     * <pre>
     *      hostname = "localhost";
     *      facility = LOG_USER;
     *      level = LOG_INFO;
     *      pattern = "common";
     *      resolveHosts = false;
     * </pre>
     */
    public SyslogAccessLogValve() {
        super();
        hostname = "localhost";
        facility = LOG_USER;
        level = LOG_INFO;
	header = true;
        pattern = "common";
        resolveHosts = false;
    }


    // ----------------------------------------------------- Instance Variables

    private static Log log = LogFactory.getLog(SyslogAccessLogValve.class);


    private String hostname = null;
    private int facility = LOG_USER;
    private int level = LOG_INFO;
    private boolean resolveHosts;

    private InetAddress address;
    private final int port = 514;
    private DatagramSocket ds;

    /**
     * If true, the appender will generate the HEADER (timestamp and host name)
     * part of the syslog packet.
     */
    private boolean header = true;
    /**
     * Date format used if header = true.
     */
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("1 yyyy-MM-dd'T'HH:mm:ss.SSS'Z' ");
    /**
     * Host name used to identify messages from this appender.
     */
    private String localHostname;

    /**
     * The descriptive information about this implementation.
     */
    protected static String info = 
        "org.apache.catalina.valves.SyslogAccessLogValve/1.1";

    /**
     * The lifecycle event support for this component.
     */
    protected LifecycleSupport lifecycle = new LifecycleSupport(this);

    /**
     * The string manager for this package.
     */
    private StringManager sm = StringManager.getManager(Constants.Package);

    /**
     * Has this component been started yet?
     */
    private boolean started = false;


    // ------------------------------------------------------------- Properties
 
    /**
     * Gets the value of hostname
     *
     * @return the value of hostname
     */
    public String getHostname() {
	return this.hostname;
    }

    /**
     * Sets the value of hostname
     *
     * @param argHostname Value to assign to this.hostname
     */
    public void setHostname(final String argHostname) {
	hostname = argHostname;

	setAddress();
    }

    /**
     * Gets the value of facility
     *
     * @return the value of facility
     */
    public String getFacility() {
	return getFacilityString(facility);
    }

    /**
     * Sets the value of facility
     *
     * @param argFacility Value to assign to this.facility
     */
    public void setFacility(final String argFacility) {
	facility = getFacility(argFacility);

	if (facility == -1) {
	    facility = LOG_USER;
	}
    }

    /**
     * Gets the value of level
     *
     * @return the value of level
     */
    public String getLevel() {
	return getLogLevelString(level);
    }

    /**
     * Sets the value of level
     *
     * @param argLevel Value to assign to this.level
     */
    public void setLevel(final String argLevel) {
	level = getLogLevel(argLevel);

	if (level == -1) {
	    level = LOG_INFO;
	}
    }

    /**
     * Gets the value of header
     *
     * @return the value of header
     */
    public boolean isHeader() {
	return this.header;
    }

    /**
     * Determines whether the header (timestamp & hostname) should be
     * included in the message
     * 
     * @param header "true" or "false"
     */
    public void setHeader(String argHeader) {
        this.header = new Boolean(argHeader).booleanValue();
    }
    /**
     * Gets the value of resolveHosts
     *
     * @return the value of resolveHosts
     */
    public boolean isResolveHosts() {
	return this.resolveHosts;
    }

    /**
     * Determines whether IP host name resolution is done.
     * 
     * @param resolveHosts "true" or "false", if host IP resolution 
     * is desired or not.
     */
    public void setResolveHosts(String resolveHosts) {
        this.resolveHosts = new Boolean(resolveHosts).booleanValue();
    }

    // --------------------------------------------------------- Public Methods

    public void log(final String msg) {
	if (ds != null) {
	    String packet = msg;
	    String hdr = getPacketHeader(new Date().getTime());

	    if(hdr.length() > 0) {
		StringBuffer buf = new StringBuffer(hdr);

		buf.append(msg);
		packet = buf.toString();
	    }
	    
	    String p1 = "<" + ( facility | level ) + ">" + packet;
	    write(p1);
	}
    }

    // --------------------------------------------------------- Protected Methods
    protected void open() {
	setAddress();
    }

    protected void close() {
	if (ds != null) {
	    ds.close();
	}
	ds = null;
    }

    /**
       Add a %P for the PID to the formats.
     */
    protected AccessLogElement createAccessLogElement(char pattern) {
        switch (pattern) {
        case 'P':
            return new PidElement();
	}

	return super.createAccessLogElement(pattern);
    }

    /**
     * write the PID - %P
     */
    protected class PidElement implements AccessLogElement {
        public void addElement(StringBuffer buf, Date date, Request request,
			       Response response, long time) {
            buf.append(getPid());
        }
    }

    // --------------------------------------------------------- Private Methods
    /**
       Returns the specified syslog facility as a lower-case String,
       e.g. "kern", "user", etc.
    */
    private static String getFacilityString(int syslogFacility) {
	switch(syslogFacility) {
	case LOG_KERN:      return "kern";
	case LOG_USER:      return "user";
	case LOG_MAIL:      return "mail";
	case LOG_DAEMON:    return "daemon";
	case LOG_AUTH:      return "auth";
	case LOG_SYSLOG:    return "syslog";
	case LOG_LPR:       return "lpr";
	case LOG_NEWS:      return "news";
	case LOG_UUCP:      return "uucp";
	case LOG_CRON:      return "cron";
	case LOG_AUTHPRIV:  return "authpriv";
	case LOG_FTP:       return "ftp";
	case LOG_LOCAL0:    return "local0";
	case LOG_LOCAL1:    return "local1";
	case LOG_LOCAL2:    return "local2";
	case LOG_LOCAL3:    return "local3";
	case LOG_LOCAL4:    return "local4";
	case LOG_LOCAL5:    return "local5";
	case LOG_LOCAL6:    return "local6";
	case LOG_LOCAL7:    return "local7";
	default:            return null;
	}
    }

    /**
       Returns the integer value corresponding to the named syslog
       facility, or -1 if it couldn't be recognized.

       @param facilityName one of the strings KERN, USER, MAIL, DAEMON,
       AUTH, SYSLOG, LPR, NEWS, UUCP, CRON, AUTHPRIV, FTP, LOCAL0,
       LOCAL1, LOCAL2, LOCAL3, LOCAL4, LOCAL5, LOCAL6, LOCAL7.
       The matching is case-insensitive.
    */
    private static int getFacility(String facilityName) {
	if(facilityName != null) {
	    facilityName = facilityName.trim();
	}
	if("KERN".equalsIgnoreCase(facilityName)) {
	    return LOG_KERN;
	} else if("USER".equalsIgnoreCase(facilityName)) {
	    return LOG_USER;
	} else if("MAIL".equalsIgnoreCase(facilityName)) {
	    return LOG_MAIL;
	} else if("DAEMON".equalsIgnoreCase(facilityName)) {
	    return LOG_DAEMON;
	} else if("AUTH".equalsIgnoreCase(facilityName)) {
	    return LOG_AUTH;
	} else if("SYSLOG".equalsIgnoreCase(facilityName)) {
	    return LOG_SYSLOG;
	} else if("LPR".equalsIgnoreCase(facilityName)) {
	    return LOG_LPR;
	} else if("NEWS".equalsIgnoreCase(facilityName)) {
	    return LOG_NEWS;
	} else if("UUCP".equalsIgnoreCase(facilityName)) {
	    return LOG_UUCP;
	} else if("CRON".equalsIgnoreCase(facilityName)) {
	    return LOG_CRON;
	} else if("AUTHPRIV".equalsIgnoreCase(facilityName)) {
	    return LOG_AUTHPRIV;
	} else if("FTP".equalsIgnoreCase(facilityName)) {
	    return LOG_FTP;
	} else if("LOCAL0".equalsIgnoreCase(facilityName)) {
	    return LOG_LOCAL0;
	} else if("LOCAL1".equalsIgnoreCase(facilityName)) {
	    return LOG_LOCAL1;
	} else if("LOCAL2".equalsIgnoreCase(facilityName)) {
	    return LOG_LOCAL2;
	} else if("LOCAL3".equalsIgnoreCase(facilityName)) {
	    return LOG_LOCAL3;
	} else if("LOCAL4".equalsIgnoreCase(facilityName)) {
	    return LOG_LOCAL4;
	} else if("LOCAL5".equalsIgnoreCase(facilityName)) {
	    return LOG_LOCAL5;
	} else if("LOCAL6".equalsIgnoreCase(facilityName)) {
	    return LOG_LOCAL6;
	} else if("LOCAL7".equalsIgnoreCase(facilityName)) {
	    return LOG_LOCAL7;
	} else {
	    return -1;
	}
    }

    private static String getLogLevelString(int logLevel) {
	switch (logLevel) {
	case LOG_EMERG:     return "emerg";
	case LOG_ALERT:     return "alert";
	case LOG_CRIT:      return "crit";
	case LOG_ERR:       return "err";
	case LOG_WARNING:   return "warn";
	case LOG_NOTICE:    return "notice";
	case LOG_INFO:      return "info";
	case LOG_DEBUG:     return "debug";
        default:            return null;
	}
    }

    private static int getLogLevel(String logLevel) {
	if (logLevel != null) {
	    logLevel = logLevel.trim();
	}
	if ("ALERT".equalsIgnoreCase(logLevel)) {
	    return LOG_ALERT;
	}
	else if ("CRIT".equalsIgnoreCase(logLevel)) {
	    return LOG_CRIT;
	}
	else if ("DEBUG".equalsIgnoreCase(logLevel)) {
	    return LOG_DEBUG;
	}
	else if ("EMERG".equalsIgnoreCase(logLevel) || "PANIC".equalsIgnoreCase(logLevel)) {
	    return LOG_EMERG;
	}
	else if ("ERR".equalsIgnoreCase(logLevel) || "ERROR".equalsIgnoreCase(logLevel)) {
	    return LOG_ERR;
	}
	else if ("INFO".equalsIgnoreCase(logLevel)) {
	    return LOG_INFO;
	}
	else if("NOTICE".equalsIgnoreCase(logLevel)) {
	    return LOG_NOTICE;
	}
	else if("WARN".equalsIgnoreCase(logLevel) || "WARNING".equalsIgnoreCase(logLevel)) {
	    return LOG_WARNING;
	}

	return -1;
    }

    /**
     * Get the host name used to identify this appender.
     * @return local host name
     */
    private String getLocalHostname() {
	if (localHostname == null) {
	    try {
		InetAddress addr = InetAddress.getLocalHost();
		localHostname = addr.getHostName();
	    }
	    catch (UnknownHostException uhe) {
		localHostname = "UNKNOWN_HOST";
	    }
	}
	return localHostname;
    }

    /**
     * Gets HEADER portion of packet.
     * @param timeStamp number of milliseconds after the standard base time.
     * @return HEADER portion of packet, will be zero-length string if header is false.
     * FORMAT [RFC 5424]:
     *         SYSLOG-MSG      = HEADER SP STRUCTURED-DATA [SP MSG]
     *
     *         HEADER          = PRI VERSION SP TIMESTAMP SP HOSTNAME
     *                           SP APP-NAME SP PROCID SP MSGID
     */
    private String getPacketHeader(final long timeStamp) {
      if (header) {
				// PRI is done at the caller
				// dateFormat contains the VERSION 1 and the SP before and
				// after the TIMESTAMP
	  StringBuffer buf = new StringBuffer(dateFormat.format(new Date(timeStamp)));
				// HOSTNAME SP
	  buf.append(getLocalHostname());
	  buf.append(' ');
				// APP-NAME SP
	  buf.append(Thread.currentThread().getName());
	  buf.append(' ');
				// PROCID SP
	  buf.append(getPid());
	  buf.append(' ');
				// MSGID="" SP
	  buf.append(' ');
				// STRUCTURED-DATA="" SP
	  buf.append(' ');

	  return buf.toString();
      }
      return "";
    }

    private String getPid() {
	return ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
    }

    private void setAddress() {
	try {
	    address = InetAddress.getByName(hostname);
	}
	catch (UnknownHostException e) {
	    if (hostname != "localhost") {
		log.error("Could not find " + hostname +
			  ". Will revert to localhost", e);
		hostname = "localhost";
		try {
		    address = InetAddress.getByName(hostname);
		}
		catch (UnknownHostException e1) {
		    log.error("Could not find " + hostname +
			      ". All logging will fail here!", e1);
		}
	    }
	    else {
		log.error("Could not find " + hostname +
			  ". All logging will fail here!", e);
	    }
	}

	if (ds == null) {
	    try {
		ds = new DatagramSocket();
	    }
	    catch (SocketException e) {
		log.error("Could not instantiate DatagramSocket. All logging will FAIL.", e);
	    }
	}
    }

    private void write(final String string) {
	if(ds != null && address != null) {
	    byte[] bytes = string.getBytes();
				//
				//  syslog packets must be less than 1024 bytes
				//
	    int bytesLength = bytes.length;
	    if (bytesLength >= 1024) {
		bytesLength = 1024;
	    }

	    DatagramPacket packet = new DatagramPacket(bytes, bytesLength,
						       address, port);

	    try {
		ds.send(packet);
	    }
	    catch (IOException e) {
		log.error("Could not send DatagramPacket:", e);
	    }
	}
    }

}
