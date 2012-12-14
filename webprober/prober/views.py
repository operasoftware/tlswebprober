#   Copyright 2010-2012 Opera Software ASA 
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

# Create your views here.

import django.views.generic.simple
from django.shortcuts import render_to_response
import encodings.idna
import re,sys
import urlparse

sys.path += ["..", "../tlslite", "../tlscommon"]

from tlscommon.probe_server import *
import webprober.prober.models as Prober
import tlslite.constants as constants

class ProbeResultEntry():
	PROBE_UNTESTED = 'U'
	PROBE_PASSED ='P'
	PROBE_FAILED = 'F'
	PROBE_NON_COMPLIANT = 'N'
	PROBERESULTVALUES  = (
		(PROBE_UNTESTED, "Untested"),
		(PROBE_PASSED, "Passed"),
		(PROBE_FAILED, "Failed"),
		(PROBE_NON_COMPLIANT, "Non-compliant"),
		)


def OK_No(value, collection):
	""" True -> "OK", green background ; False->"No",red, None to "-",no color """
	if value:
		return ("OK", "black; background-color:green;")
	if value == None:
		return ("-", "black")
	
	return ("No", "black; background-color:red;")

def Yes_No(value, collection):
	""" True -> "Yes", green background ; False->"No",red, None to "-",no color """
	if value:
		return ("Yes", "black; background-color:green;")
	if value == None:
		return ("-", "black")
	
	return ("No", "black; background-color:red;")

def Yes_No_reverse(value, collection):
	""" True -> "Yes", Red background ; False->"No",green, None to "-",no color """
	if value:
		return ("Yes", "black; background-color:red;")
	if value == None:
		return ("-", "black")
	
	return ("No", "black; background-color:green;")
	
	
def Tag_OK_No(value, link=None, reverse = False, yes_no = False):
	if reverse and not yes_no and value != None:
		value = not value
	return {"value":value, "textcolor":((Yes_No_reverse if reverse else Yes_No) if yes_no else OK_No), "link":link} 

def DoProbe(request):
	# Perform a TLS probe of the identified server, and display the result
	query= None
	if request.method == "POST":
		query = request.POST
	elif request.method == "GET":
		query = request.GET
		
	if not query or "server" not in query:
		return django.views.generic.simple.redirect_to(request, "/");

	server = query["server"].lower()
	original_server = server
	
	port = query.get("port", 443)
		
	protocol = query.get("protocol", ProbeServer.PROTOCOL_HTTPS).capitalize()
	if protocol not in ProbeServer.PROTOCOLS:
		protocol = ProbeServer.PROTOCOL_HTTPS
	
	# If the serername is a URL, extract schemer, server name and port  
	if server.find("://")>=0:
		url_list = urlparse.urlparse(server);
		if url_list.scheme.capitalize() in ProbeServer.PROTOCOLS:
			protocol = url_list.scheme.capitalize()
		if url_list.port >0 and url_list.port <65536:
			port = url_list.port
		server = url_list.hostname.lower()
		original_server = server
	elif server.find(":")>=0:
		url_list = server.split(":")
		server = url_list[0].lower()
		original_server = server
		if url_list[1]:
			port = url_list[1]
		if len(url_list)>2:
			if url_list[2].capitalize() in ProbeServer.PROTOCOLS:
				protocol = url_list[2].capitalize()
			
	if port:
		port = int(port)
		if port == 0:
			port = 443
	else:
		port = 443

	# validate inputs
	is_error = True
	is_ip_address = False
	if not server or port <0 or port > 65535 :
		is_error = True
	elif (re.search(r'^((0|[1-9]\d{0,2})\.){3}(0|[1-9]\d{0,2})$', server) or #quad dot
		 re.search(r'^\[[0-9A-Fa-f\:]+\]$', server) # IPv6 format
		 ):
		is_error = False
		is_ip_address = True
	elif (re.search(r'^[\d\.]*$', server) or #incorrect address
		'.' not in server # local host format
		):
		pass #TODO: display error
	else:
		try:
			server = encodings.idna.ToASCII(server)
			is_error = False
		except:
			raise
			pass; # report error

	if is_error:
		return render_to_response(
							"webprober_badname.html",
							{
								"hostname":original_server,
								"port":port,
								"protocol":protocol,
							}) #TODO: report error
	
	
	# test existence of server
	sock = None
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if not sock:
			is_error = True

		sock.settimeout(10)  #Only on python 2.3 or greater
		sock.connect((server, port))
		if not sock.fileno():
			is_error = True
		ip_address = sock.getpeername()[0]
			
		sock.close()
		sock = None
	except:
		is_error = True
		
	if is_error:
		return render_to_response(
							"webprober_unavailable.html",
							{
								"hostname":original_server,
								"port":port,
								"protocol":protocol,
							}) #TODO: report error

	
	# Probe server
	sn_t = "%s:%05d:%s" % (server, port,protocol)
	server_item = Prober.Server();
	server_item.full_servername = sn_t
	server_item.enabled=True
	server_item.alexa_rating=0
	server_item.servername= server 
	server_item.port= port
	server_item.protocol = protocol
	server_item.id = 0
	
	prober = ProbeServer(server_item)
	prober.debug =False

	prober.Probe(do_full_test=True)

	if not prober.available:
		return render_to_response(
							"webprober_unavailable.html",
							{
								"hostname":original_server,
								"port":port,
								"protocol":protocol,
							}) #TODO: report not online
	
	warn_details = []
	trouble_details = []

	#extract results, generate warning and trouble list
	support_20 = prober.tolerate_ssl_v2	and prober.support_v2_ciphers
	if (not prober.supported_versions or max(prober.supported_versions) < (3,0)) and prober.detected_versions and max(prober.detected_versions)>=(3,0):
		warn_details.append("Was not able to complete negotiation for SSL v3 or TLS 1.x, but did get indications on protocol support; these were used instead")
		prober.supported_versions += prober.detected_versions 
		
	support_30 = (3,0) in prober.supported_versions
	support_31 = (3,1) in prober.supported_versions
	support_32 = (3,2) in prober.supported_versions
	support_33 = (3,3) in prober.supported_versions
	
	if not all([support_30, support_31, support_32, support_33]):
		warn_details.append("Does not support the most recent TLS protocol version")

	detected_mirror_version = any([x not in prober.supported_versions for x in prober.detected_versions])
	if detected_mirror_version:
		trouble_details.append("Responds with whatever version the client states, even if the server does not support it, causing connection failures")

	version_field_swap = prober.detected_ch_version_swap
	if version_field_swap:
		trouble_details.append("Incorrectly using Record  Protocol Version field to negotiate  TLS version, instead of Client Hello Version field")
	
	support_renego = prober.have_renego
	unstable_renego = False
	if not support_renego:
		trouble_details.append("Does not provide protection against renegotiation vulnerability")
		if prober.requested_renegotiation:
			trouble_details.append("The server requested TLS Renegotiation without using secure renegotiation. This allows MITM request injection attacks.")
			if prober.completed_renegotiation != None and not prober.completed_renegotiation:
				trouble_details.append("The server requested TLS Renegotiation without using secure renegotiation, and did not complete the action when the request was rejected. This causes usability problems for users.")
		if prober.accepted_renegotiation:
			trouble_details.append("The server accepted client initiated TLS Renegotiation without using secure renegotiation. This allows MITM request injection attacks.")
	elif prober.renego_unstable:
		unstable_renego = True
		trouble_details.append("Variable protection against renegotiation vulnerability. A part of the server is not patched. Will cause intermittent connections failures in some clients")

	if support_renego:
		if prober.accepted_renego_ext_and_scsv == False: 
			trouble_details.append("The server supports the Renego patch, but refuses to accept Client Hellos with both Extension and the SCSV cipher suite. This can cause interoperability problems with some clients.")
		if prober.accepted_renegotiation:
			warn_details.append("The server accepted client initiated TLS Renegotiation. Secure Renegotiation was used, but is this support really necessary to have enabled?")
		if prober.accepted_renegotiation_fake_renego:
			trouble_details.append("The server accepted client initiated TLS Renegotiation using secure renegotiation, but did not check the finished information. This allows MITM request injection attacks.")
		
	if prober.tolerate_ssl_v2 	and prober.support_v2_ciphers:
		if prober.only_ssl_v2:
			trouble_details.append("Support only SSL v2, a 15 year old, unsecure protocol version, This version not supported by most modern browser clients")
		else:
			warn_details.append("Accept SSLv2-only connections. This support is unnecessary as most clients from 1996 and up support SSL v3 or later. Also, this 15 year old protocol version is unsecure")
		if prober.support_v2_export_ciphers:
			trouble_details.append("Support SSL v2 exportable ciphers, which can be easily cracked. Modern clients also do not support either SSL v2 or exportable ciphers anymore.") 

	if prober.extra_padding_problems:
		warn_details.append("Does not support extra padding bytes in records.")

	ver_resultlist = {3:{}, 4:{}}
	handled = {}
	for (mode_source, result_cand) in [
			(prober.non_compliant_modes, ProbeResultEntry.PROBE_NON_COMPLIANT),
			(prober.failed_modes, ProbeResultEntry.PROBE_FAILED),
			(prober.passed_modes, ProbeResultEntry.PROBE_PASSED),
			]:
		for x in mode_source:
			ver = x["version"]
			ext = x["extensions"]
			bad = x["bad_version"]
			index = str((ver, ext, bad))
			if index in handled:
				continue
			handled[index]=1
			
			ver_resultlist[ver[0]].setdefault(ver[1],[]).append((x, result_cand))

	version_status = []
	
	is_version_intolerant = False
	is_extension_intolerant = False
	is_using_no_version_check = False
	is_using_bad_version_check = False

	for (v_ma, subs) in sorted(ver_resultlist.iteritems()):
		for (v_mi, res) in sorted(subs.iteritems()):
			noext_nobad =  ProbeResultEntry.PROBE_UNTESTED
			noext_bad =  ProbeResultEntry.PROBE_UNTESTED
			ext_nobad =  ProbeResultEntry.PROBE_UNTESTED
			ext_bad =  ProbeResultEntry.PROBE_UNTESTED
			
			for x,st in res:
				if x["extensions"]:
					if x["bad_version"]:
						ext_bad = st if ext_bad == ProbeResultEntry.PROBE_UNTESTED else ext_bad
					else:
						ext_nobad = st if ext_nobad == ProbeResultEntry.PROBE_UNTESTED else ext_nobad
				else:
					if x["bad_version"]:
						noext_bad = st if noext_bad == ProbeResultEntry.PROBE_UNTESTED else noext_bad
					else:
						noext_nobad = st if noext_nobad == ProbeResultEntry.PROBE_UNTESTED else noext_nobad

			temp_version_intolerant = (noext_nobad != ProbeResultEntry.PROBE_PASSED)
			if temp_version_intolerant:
				is_version_intolerant = True
			temp_extension_intolerant = (ext_nobad != ProbeResultEntry.PROBE_PASSED  
										if noext_nobad == ProbeResultEntry.PROBE_PASSED or noext_bad == ProbeResultEntry.PROBE_NON_COMPLIANT else None)
			if temp_extension_intolerant:
				is_extension_intolerant=True
			temp_using_no_version_check = None
			temp_using_bad_version_check = None
			if (v_ma, v_mi) not in prober.supported_versions:
				if noext_bad == ProbeResultEntry.PROBE_NON_COMPLIANT or noext_bad == ProbeResultEntry.PROBE_FAILED:
					temp_using_no_version_check = (noext_nobad == ProbeResultEntry.PROBE_PASSED)
					if temp_using_no_version_check:
						is_using_no_version_check=True
						#raise
					temp_using_bad_version_check = (noext_nobad != ProbeResultEntry.PROBE_PASSED)
					if temp_using_bad_version_check:
						is_using_bad_version_check=True
				elif noext_nobad == ProbeResultEntry.PROBE_PASSED:
					temp_using_no_version_check = False
					temp_using_bad_version_check = False
					
						
			resx = {"version":(v_ma, v_mi),
					"version_name": ("TLS %d.%d"% (v_ma-2,(v_mi if v_ma>3 else v_mi-1)) if (v_ma,v_mi) > (3,0) else "SSL 3.0"),
					"version_intolerant": Tag_OK_No(temp_version_intolerant, reverse = True),
					"extension_intolerant": Tag_OK_No(temp_extension_intolerant, reverse = True),
					"no_version_check": Tag_OK_No(temp_using_no_version_check, reverse = True),
					"require_bad_version_check": Tag_OK_No(temp_using_bad_version_check, reverse = True),
					}
			
			
			version_status.append(resx)
				
	if is_version_intolerant:
		trouble_details.append("Version intolerant: Does not accept connections from clients that support some or all TLS versions newer than those supported by the server")
	if is_extension_intolerant:
		trouble_details.append("Extension intolerant: Does not accept clients that support TLS Extensions")
		if prober.intolerant_for_extension and sorted(prober.intolerant_for_extension) != sorted(ProbeServer.EXTENSION_SET_LIST_CHECKED): 
			trouble_details.append("Extension intolerant: Does not accept specific TLS Extensions: " + ", ".join([str(x) for x in prober.intolerant_for_extension]))
	if is_using_no_version_check:
		trouble_details.append("Does not check RSA Client Key Exchange Premaster Server version field to guard against version rollback attacks")
	if is_using_bad_version_check:
		trouble_details.append(
							"""Require clients supporting newer TLS versions than the ones supported by the server to (incorrectly) 
							send the negotiated version, causing interoperability problems""")

	if prober.dhe_keysize:		
		if prober.dhe_keysize<600:
			trouble_details.append("The server uses temporary keys that are less than 600 bit long, specifically %d, which can be broken very quickly"%(prober.dhe_keysize,))
		elif prober.dhe_keysize<800:
			trouble_details.append("The server uses temporary keys that are less than 800 bit long, specifically %d, which can be broken in less than a year"%(prober.dhe_keysize,))
		elif prober.dhe_keysize<1024:
			warn_details.append("The server uses temporary keys that are less than 1024 bit long, specifically %d, which are in the dangerzone security-wise"%(prober.dhe_keysize,))
	
	if prober.support_weak_ciphers:
		trouble_details.append("The server uses encryption methods that does not provide sufficient privacy for the connection")
		
	if prober.selected_deprecated_cipher:
		warn_details.append("The server supports at least one cipher suite that is no longer allowed in the protocol version it selected.")

	if prober.selected_cipher_later_version:
		warn_details.append("The server supports at least one cipher suite that is only allowed to be used in protocol versions newer than the one supported by the server.")

	if prober.detected_ch_rec_sameversion:
		warn_details.append("The server seem to require that the Client Hello version requested must match the record protocol to select the requested version.")

	supported_ciphers={}
	for s in constants.CipherSuite.rsaSuites:
		st = constants.CipherSuite.toText.get(s,"")
		supported_ciphers[st] = Tag_OK_No((st in prober.ciphers_supported),yes_no=True)
	for s in constants.CipherSuite.unsupportedSuites:
		st = constants.CipherSuite.toText.get(s,"")
		if st in prober.ciphers_supported:
			if s in constants.CipherSuite.weakSuites:
				supported_ciphers[st] = Tag_OK_No(True,yes_no=True,reverse=True)
			else:
				supported_ciphers[st] = Tag_OK_No(True,yes_no=True)
		
	if constants.CipherSuite.toText.get(constants.CipherSuite.TLS_RSA_WITH_RC4_128_MD5, "") in prober.ciphers_supported:
		if len(prober.ciphers_supported) == 1:
			warn_details.append("The server only supports the RSA/RC4 with MD5 cipher, which might be weaker than desirable")
		
	if not any([constants.CipherSuite.toText.get(x,"") in prober.ciphers_supported for x in constants.CipherSuite.aes128Suites + constants.CipherSuite.aes256Suites 
												if x in constants.CipherSuite.rsaSuites ]):
		warn_details.append("The server does not support the AES encryption method")
	
	if prober.tested_session:
		if not prober.resumable_session:
			warn_details.append("The server does not offer resumable sessions; this will significantly increase load on the server")
			if not prober.resumed_session:
				warn_details.append("The server did not resume a resumable sessions; this will significantly increase load on the server")
			
				if prober.new_session_with_original:
					warn_details.append("The server did not resume a resumable sessions when a higher version was used; this will significantly increase load on the server")
				if prober.fail_resumed_session_with_original:
					trouble_details.append("The server refused to resume a resumable sessions when a higher protocol version was used")
	
	if prober.have_renego and prober.accepted_start_fake_renego:
		trouble_details.append("Server supports Renego extension, but accepted a fake renegotition indication during the first handshake, which means a MITM injection attack is possible") 
	
	if prober.requested_renegotiation or prober.accepted_renegotiation:
		if prober.accepted_renegotiation_fake_renego != None and prober.accepted_renegotiation_fake_renego:
			trouble_details.append("Server supports Renego extension, but accepted a wrong renegotition indication during a renegotation, which means a MITM injection attack is possible") 
		if prober.accepted_renegotiation_higher_premaster:
			warn_details.append("Server supports renegotiation, but accepted the original version used during the first handshake. This could indicate that the premaster version is not checked")
		if prober.accepted_renegotiation_even_higher_premaster:
			trouble_details.append("Server supports renegotiation, but accepted a version higher than the original version used during the first handshake. This indicates that the premaster version is not checked")
	
	server_agent = prober.server_agent.strip() if prober.server_agent else "N/A"

	#display results
	return render_to_response(
							"webprober_result.html",
							{
								"hostname":original_server,
								"port":port,
								"protocol":protocol,
								"server_agent":server_agent,
								"warn_details":warn_details,
								"trouble_details":trouble_details,
								"support_20":(Tag_OK_No(support_20, reverse = True) if support_20 else None),
								"support_30":Tag_OK_No(support_30),
								"support_31":Tag_OK_No(support_31),
								"support_32":Tag_OK_No(support_32),
								"support_33":Tag_OK_No(support_33),
								"correct_version_response": Tag_OK_No(not detected_mirror_version),
								"correct_version_field": Tag_OK_No(not version_field_swap),
								"record_not_match_hello_ver": Tag_OK_No(not prober.detected_ch_rec_sameversion),
								"support_renego":Tag_OK_No(support_renego),
								"unstable_renego":unstable_renego,
								"supported_ciphers":supported_ciphers,
								"support_certstatus": Tag_OK_No(True if prober.certificate_status else False),
								"version_status":version_status,
								"dhe_keysize": prober.dhe_keysize,
								"dhe_keysize_low": prober.dhe_keysize < 1024,
								"only_strong_ciphers":Tag_OK_No(not prober.support_weak_ciphers),
								"debug":str(prober),
							}
							)
