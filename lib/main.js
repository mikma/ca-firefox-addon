const {Cc, Ci, Cu} = require("chrome");
var {XPCOMUtils} = Cu.import("resource://gre/modules/XPCOMUtils.jsm");
var self = require("sdk/self");
var CASha1Fingerprint = "<FILL IN>";

function getCertDB() {
	var certDBRef = "@mozilla.org/security/x509certdb;1";

	try {
	    // Old interface
	    return Cc[certDBRef].getService(Ci.nsIX509CertDB2);
	}
	catch (ex) {
	    // New interface
	    return Cc[certDBRef].getService(Ci.nsIX509CertDB);
	}
}

function findCert(sha1Fingerprint) {
	var certDB = getCertDB();
	var certs = certDB.getCerts();
	var iter = certs.getEnumerator();

	while (iter.hasMoreElements()) {
	    cert = iter.getNext().QueryInterface(Ci.nsIX509Cert);
	    if ( cert.sha1Fingerprint == sha1Fingerprint ) {
		return cert;
	    }
	}

	return null;
}

function installCert(CertName, CertTrust, sha1Fingerprint) {

	var gIOService = Cc["@mozilla.org/network/io-service;1"]
                        .getService(Ci.nsIIOService);
	var certDB = getCertDB();
	var scriptableStream = Cc["@mozilla.org/scriptableinputstream;1"]
                        .getService(Ci.nsIScriptableInputStream);

	var scriptableStream = Cc["@mozilla.org/scriptableinputstream;1"]
                                .getService(Ci.nsIScriptableInputStream);
	var channel = gIOService.newChannel(self.data.url(CertName), null, null);

	var cert = findCert(sha1Fingerprint);
	if (cert != null) {
	    // TODO don't enable add on
	    return;
	}

	var input = channel.open();
	scriptableStream.init(input);

	var certfile = scriptableStream.read(input.available());
	scriptableStream.close();
	input.close();

	var beginCert = "-----BEGIN CERTIFICATE-----";
	var endCert = "-----END CERTIFICATE-----";

	certfile = certfile.replace(/[\r\n]/g, "");
	var begin = certfile.indexOf(beginCert);
	var end = certfile.indexOf(endCert);
	var cert = certfile.substring(begin + beginCert.length, end);

	certDB.addCertFromBase64(cert, CertTrust, "");
}

function uninstallCert(sha1Fingerprint) {
	var certDB = getCertDB();

	var cert = findCert(sha1Fingerprint);
	if (cert != null) {
	    certDB.deleteCertificate(cert);
	}
}

exports.main = function(options, callbacks) {
    if (options.loadReason == 'install' ||
	options.loadReason == 'enable') {
	installCert("ca.crt", "C,c,c", CASha1Fingerprint);
    }
}

exports.onUnload = function(reason) {
    if (reason == 'uninstall' ||
	reason == 'disable') {
	uninstallCert(CASha1Fingerprint);
    }
}
