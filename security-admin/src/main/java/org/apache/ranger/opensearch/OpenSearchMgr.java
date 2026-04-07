/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ranger.opensearch;

import org.apache.commons.lang3.StringUtils;
import org.apache.ranger.audit.destination.OpenSearchAuditDestination;
import org.apache.ranger.authorization.credutils.CredentialsProviderUtil;
import org.apache.ranger.common.PropertiesUtil;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.RestHighLevelClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;

import java.io.File;
import java.security.PrivilegedActionException;
import java.util.Date;
import java.util.Locale;

import static org.apache.ranger.audit.destination.OpenSearchAuditDestination.*;

/**
 * This class initializes the OpenSearch client
 *
 */
@Component
public class OpenSearchMgr {

	private static final Logger logger = LoggerFactory.getLogger(OpenSearchMgr.class);
	public String index;
	Subject subject;
	String user;
	String password;

	synchronized void connect() {
		if (client == null) {
			synchronized (OpenSearchAuditDestination.class) {
				if (client == null) {

					String urls = PropertiesUtil.getProperty(CONFIG_PREFIX_OPENSEARCH + "." + CONFIG_URLS);
					if (urls == null) {
						urls = PropertiesUtil.getProperty(CONFIG_PREFIX_ELASTICSEARCH + "." + CONFIG_URLS);
					}
					String protocol = PropertiesUtil.getProperty(CONFIG_PREFIX_OPENSEARCH + "." + CONFIG_PROTOCOL);
					if (protocol == null) {
						protocol = PropertiesUtil.getProperty(CONFIG_PREFIX_ELASTICSEARCH + "." + CONFIG_PROTOCOL, "http");
					}
					user = PropertiesUtil.getProperty(CONFIG_PREFIX_OPENSEARCH + "." + CONFIG_USER);
					if (user == null) {
						user = PropertiesUtil.getProperty(CONFIG_PREFIX_ELASTICSEARCH + "." + CONFIG_USER, "");
					}
					password = PropertiesUtil.getProperty(CONFIG_PREFIX_OPENSEARCH + "." + CONFIG_PASSWORD);
					if (password == null) {
						password = PropertiesUtil.getProperty(CONFIG_PREFIX_ELASTICSEARCH + "." + CONFIG_PASSWORD, "");
					}
					String portStr = PropertiesUtil.getProperty(CONFIG_PREFIX_OPENSEARCH + "." + CONFIG_PORT);
					if (portStr == null) {
						portStr = PropertiesUtil.getProperty(CONFIG_PREFIX_ELASTICSEARCH + "." + CONFIG_PORT, "9200");
					}
					int port = Integer.parseInt(portStr);

					this.index = PropertiesUtil.getProperty(CONFIG_PREFIX_OPENSEARCH + "." + CONFIG_INDEX);
					if (this.index == null) {
						this.index = PropertiesUtil.getProperty(CONFIG_PREFIX_ELASTICSEARCH + "." + CONFIG_INDEX, "ranger_audits");
					}

					String parameterString = String.format(Locale.ROOT,"User:%s, %s://%s:%s/%s", user, protocol, urls, port, index);
					logger.info("Initializing OpenSearch " + parameterString);
					if (urls != null) {
						urls = urls.trim();
					}
					if (StringUtils.isBlank(urls) || "NONE".equalsIgnoreCase(urls.trim())) {
						logger.info(String.format("Clearing URI config value: %s", urls));
						urls = null;
					}

					try {
						if (StringUtils.isNotBlank(user) && StringUtils.isNotBlank(password) && password.contains("keytab") && new File(password).exists()) {
							subject = CredentialsProviderUtil.login(user, password);
						}
						RestClientBuilder restClientBuilder =
								OpenSearchAuditDestination.getRestClientBuilder(urls, protocol, user, password, port);
						client = new RestHighLevelClient(restClientBuilder);
					} catch (Throwable t) {
						logger.error("Can't connect to OpenSearch: " + parameterString, t);
					}
				}
			}
		}
	}

	RestHighLevelClient client = null;
	public RestHighLevelClient getClient() {
		if (client != null && subject != null) {
			KerberosTicket ticket = CredentialsProviderUtil.getTGT(subject);
			try {
				if (ticket != null && new Date().getTime() > ticket.getEndTime().getTime()){
					client = null;
					CredentialsProviderUtil.ticketExpireTime80 = 0;
					connect();
				} else if (ticket != null && CredentialsProviderUtil.ticketWillExpire(ticket)) {
					subject = CredentialsProviderUtil.login(user, password);
				}
			} catch (PrivilegedActionException e) {
				logger.error("PrivilegedActionException:", e);
				throw new RuntimeException(e);
			}
			return client;
		} else {
			connect();
		}
		return client;
	}

}
