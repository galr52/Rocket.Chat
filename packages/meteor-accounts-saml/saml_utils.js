var zlib = Npm.require('zlib');
var xml2js = Npm.require('xml2js');
var xmlCrypto = Npm.require('xml-crypto');
var crypto = Npm.require('crypto');
var xmldom = Npm.require('xmldom');
var querystring = Npm.require('querystring');
var xmlbuilder = Npm.require('xmlbuilder');
var xmlenc = Npm.require('xml-encryption');
var xpath = xmlCrypto.xpath;
var Dom = xmldom.DOMParser;
var fs = Npm.require('fs');
var path = Npm.require('path');

var prefixMatch = new RegExp(/(?!xmlns)^.*:/);
Meteor.settings.debug = true;
function EnvelopedSignature() { };

EnvelopedSignature.prototype.process = function (node) {
	var signature = xpath(node, "//*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
	if (signature) signature.parentNode.removeChild(signature);

	return node;
};

EnvelopedSignature.prototype.getAlgorithmName = function () {
	return "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
};

xmlCrypto.SignedXml.CanonicalizationAlgorithms['http://www.w3.org/2000/09/xmldsig#enveloped-signature'] = EnvelopedSignature;

SAML = function (options) {
	this.options = this.initialize(options);
};

var stripPrefix = function (str) {
	return str.replace(prefixMatch, '');
};

SAML.prototype.initialize = function (options) {
	if (!options) {
		options = {};
	}

	if (!options.protocol) {
		options.protocol = 'https://';
	}

	if (!options.path) {
		options.path = '/saml/consume';
	}

	if (!options.issuer) {
		options.issuer = 'onelogin_saml';
	}

	options.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

	if (options.authnContext === undefined) {
		options.authnContext = "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/windows";
	}

	if (options.privateKey === undefined) {
		options.privateKey = fs.readFileSync(path.resolve('PATH_TO_CERT.key'), 'utf-8');
	}

	if (options.privateCert === undefined) {
		options.privateCert = fs.readFileSync(path.resolve('PATH_TO_CERT.pem'), 'utf-8');
	}

	return options;
};

SAML.prototype.generateUniqueID = function () {
	var chars = "abcdef0123456789";
	var uniqueID = "";
	for (var i = 0; i < 20; i++) {
		uniqueID += chars.substr(Math.floor((Math.random() * 15)), 1);
	}
	return uniqueID;
};

SAML.prototype.generateInstant = function () {
	return new Date().toISOString();
};

SAML.prototype.signRequest = function (xml) {
	var signer = crypto.createSign('RSA-SHA1');
	signer.update(xml);
	return signer.sign(this.options.privateKey, 'base64');
}

SAML.prototype.generateAuthorizeRequest = function (req) {
	var id = "_" + this.generateUniqueID();
	var instant = this.generateInstant();

	// Post-auth destination
	if (this.options.callbackUrl) {
		callbackUrl = this.options.callbackUrl;
	} else {
		var callbackUrl = this.options.protocol + req.headers.host + this.options.path;
	}

	if (this.options.id)
		id = this.options.id;

	var request =
		"<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant +
		"\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"" + callbackUrl + "\" Destination=\"" +
		this.options.entryPoint + "\">" +
		"<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>\n";

	if (this.options.identifierFormat) {
		request += "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + this.options.identifierFormat +
		"\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n";
	}

	request +=
	"<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
	"<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:federation:authentication:windows</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
	"</samlp:AuthnRequest>";

	return request;
};

SAML.prototype.generateLogoutRequest = function (options) {
	// options should be of the form
	// nameId: <nameId as submitted during SAML SSO>
	// sessionIndex: sessionIndex
	// --- NO SAMLsettings: <Meteor.setting.saml  entry for the provider you want to SLO from

	var id = "_" + this.generateUniqueID();
	var instant = this.generateInstant();

	var request = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
		"xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant +
		"\" Destination=\"" + this.options.idpSLORedirectURL + "\">" +
		"<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>" +
		"<saml:NameID Format=\"" + this.options.identifierFormat + "\">" + options.nameID + "</saml:NameID>" +
		"</samlp:LogoutRequest>";

	request = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"  " +
	"ID=\"" + id + "\" " +
	"Version=\"2.0\" " +
	"IssueInstant=\"" + instant + "\" " +
	"Destination=\"" + this.options.idpSLORedirectURL + "\" " +
	">" +
	"<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>" +
	"<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
	"NameQualifier=\"http://id.init8.net:8080/openam\" " +
	"SPNameQualifier=\"" + this.options.issuer + "\" " +
	"Format=\"" + this.options.identifierFormat + "\">" +
	options.nameID + "</saml:NameID>" +
	"<samlp:SessionIndex xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">" + options.sessionIndex + "</samlp:SessionIndex>" +
	"</samlp:LogoutRequest>";
	if (Meteor.settings.debug) {
		console.log("------- SAML Logout request -----------");
		console.log(request);
	}
	return {
		request: request,
		id: id
	};
}

SAML.prototype.requestToUrl = function (request, operation, callback) {
	var self = this;
	var result;
	zlib.deflateRaw(request, function (err, buffer) {
		if (err) {
			return callback(err);
		}

		var base64 = buffer.toString('base64');
		var target = self.options.entryPoint;

		if (operation === 'logout') {
			if (self.options.idpSLORedirectURL) {
				target = self.options.idpSLORedirectURL;
			}
		}

		if (target.indexOf('?') > 0)
			target += '&';
		else
			target += '?';

		var samlRequest = {
			SAMLRequest: base64
		};

		if (self.options.privateCert) {
			samlRequest.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
			samlRequest.Signature = self.signRequest(querystring.stringify(samlRequest));
		}

		// TBD. We should really include a proper RelayState here
		if (operation === 'logout') {
			// in case of logout we want to be redirected back to the Meteor app.
			var relayState = Meteor.absoluteUrl();
		} else {
			var relayState = self.options.provider;
		}
		target += querystring.stringify(samlRequest);//+ "&RelayState=" + relayState;

		if (Meteor.settings.debug) {
			console.log("requestToUrl: " + target);
		}
		if (operation === 'logout') {
			// in case of logout we want to be redirected back to the Meteor app.
			result = target;
			return callback(null, target);

		} else {
			callback(null, target);
		}
	});
}

SAML.prototype.getAuthorizeUrl = function (req, callback) {
	var request = this.generateAuthorizeRequest(req);

	this.requestToUrl(request, 'authorize', callback);
};

SAML.prototype.getLogoutUrl = function (req, callback) {
	var request = this.generateLogoutRequest(req);

	this.requestToUrl(request, 'logout', callback);
}

SAML.prototype.certToPEM = function (cert) {
	cert = cert.match(/.{1,64}/g).join('\n');
	cert = "-----BEGIN CERTIFICATE-----\n" + cert;
	cert = cert + "\n-----END CERTIFICATE-----\n";
	return cert;
};

function findChilds(node, localName, namespace) {
	var res = []
	for (var i = 0; i < node.childNodes.length; i++) {
		var child = node.childNodes[i]
		if (child.localName == localName && (child.namespaceURI == namespace || !namespace)) {
			res.push(child)
		}
	}
	return res;
}

SAML.prototype.validateSignature = function (xml, cert) {
	var self = this;

	var doc = new xmldom.DOMParser().parseFromString(xml);
	var signature = xmlCrypto.xpath(doc, "//*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];

	var sig = new xmlCrypto.SignedXml();

	sig.keyInfoProvider = {
		getKeyInfo: function (key) {
			return "<X509Data></X509Data>"
		},
		getKey: function (keyInfo) {
			return self.certToPEM(cert);
		}
	};

	sig.loadSignature(signature);

	return sig.checkSignature(xml);
};

SAML.prototype.getElement = function (parentElement, elementName) {
	if (parentElement['saml:' + elementName]) {
		return parentElement['saml:' + elementName];
	} else if (parentElement['samlp:' + elementName]) {
		return parentElement['samlp:' + elementName];
	} else if (parentElement['saml2p:' + elementName]) {
		return parentElement['saml2p:' + elementName];
	} else if (parentElement['saml2:' + elementName]) {
		return parentElement['saml2:' + elementName];
	}
	return parentElement[elementName];
}

SAML.prototype.validateLogoutResponse = function (samlResponse, callback) {
	var self = this;

	var compressedSAMLResponse = new Buffer(samlResponse, 'base64');
	zlib.inflateRaw(compressedSAMLResponse, function (err, decoded) {

		if (err) {
			if (Meteor.settings.debug) {
				console.log(err)
			}
		} else {
			var parser = new xml2js.Parser({
				explicitRoot: true
			});
			parser.parseString(decoded, function (err, doc) {
				var response = self.getElement(doc, 'LogoutResponse');

				if (response) {
					// TBD. Check if this msg corresponds to one we sent
					var inResponseTo = response['$'].InResponseTo;
					if (Meteor.settings.debug) {
						console.log("In Response to: " + inResponseTo);
					}
					var status = self.getElement(response, 'Status');
					var statusCode = self.getElement(status[0], 'StatusCode')[0]['$'].Value;
					if (Meteor.settings.debug) {
						console.log("StatusCode: " + JSON.stringify(statusCode));
					}
					if (statusCode === 'urn:oasis:names:tc:SAML:2.0:status:Success') {
						// In case of a successful logout at IDP we return inResponseTo value.
						// This is the only way how we can identify the Meteor user (as we don't use Session Cookies)
						callback(null, inResponseTo);
					} else {
						callback("Error. Logout not confirmed by IDP", null);
					}
				} else {
					callback("No Response Found", null);
				}
			})
		}

	})
}

SAML.prototype.validateResponse = function (samlResponse, relayState, callback) {
	var self = this;
	var xml = new Buffer(samlResponse, 'base64').toString('utf8');
	var doc = new xmldom.DOMParser().parseFromString(xml);
	/*
	// We currently use RelayState to save SAML provider
	if (Meteor.settings.debug) {
		console.log("Validating response with relay state: " + xml);
	}
	var parser = new xml2js.Parser({
		explicitRoot: true
	});

	// Verify signature
	if (Meteor.settings.debug) {
		console.log("Verify signature");
	}
	if (!self.options.cert && !self.validateSignature(xml, self.options.cert)) {
		if (Meteor.settings.debug) {
			console.log("Signature WRONG");
		}
		return callback(new Error('Invalid signature'), null, false);
	}
	if (Meteor.settings.debug) {
		console.log("Signature OK");
	}
	var response = self.getElement(doc, 'Response');
	if (Meteor.settings.debug) {
		console.log("Got response");
	}*/

	var assertions = xpath(doc, "/*[local-name()='Response']/*[local-name()='Assertion']");
    var encryptedAssertions = xpath(doc,
		"/*[local-name()='Response']/*[local-name()='EncryptedAssertion']");

	if (assertions.length + encryptedAssertions.length > 1) {
		throw new Error('Invalid signature');
	}

	if (assertions.length == 1) {
		if (!self.options.cert &&
			!self.validateSignature(xml, assertions[0], self.options.cert)) {
			throw new Error('Invalid signature');
		}

		//return self.processValidlySignedAssertion(assertions[0].toString(), callback);
	}

	if (encryptedAssertions.length == 1) {
        if (!self.options.privateKey)
            throw new Error('No decryption key for encrypted SAML response');
		var encryptedDatas = xpath(encryptedAssertions[0], "./*[local-name()='EncryptedData']");
		if (encryptedDatas.length != 1)
            throw new Error('Invalid signature');
        var encryptedDataXml = encryptedDatas[0].toString();
		var xmlencOptions = { key: self.options.privateKey };
        xmlenc.decrypt(encryptedDataXml, xmlencOptions, function (err, decryptedXml) {
            var decryptedDoc = new xmldom.DOMParser().parseFromString(decryptedXml);
            var decryptedAssertions = xpath(decryptedDoc, "/*[local-name()='Assertion']");
            if (decryptedAssertions.length != 1)
                throw new Error('Invalid EncryptedAssertion content');

			// Gal
			return self.regexProcessValidlySignedAssertion(decryptedAssertions[0].toString(), callback);

            // return self.processValidlySignedAssertion(decryptedAssertions[0].toString(), callback);
        });
	}



/*
	var encryptedData = response.EncryptedAssertion[0]["xenc:EncryptedData"][0];
	var encryptedContent = encryptedData["xenc:CipherData"][0]["xenc:CipherValue"][0];
	var encrypted = new Buffer(encryptedContent, 'base64');
	var symmetricKey = xmlenc.decryptKeyInfo(encryptedContent, { key: self.options.privateKey });
	var decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, encrypted.slice(0, 16));
	decipher.setAutoPadding(false);
	var decrypted = decipher.update(encrypted.slice(16), 'base64', 'utf8') + decipher.final('utf8');
	if (!assertion) {
		return callback(new Error('Missing SAML assertion'), null, false);
	}

	profile = {};

	if (response['$'] && response['$']['InResponseTo']) {
		profile.inResponseToId = response['$']['InResponseTo'];
	}

	var issuer = assertion.Issuer;
	if (issuer) {
		profile.issuer = issuer[0];
	}

	var subject = assertion.Subject;

	if (subject) {
		var nameID = subject[0].NameID;
		if (nameID) {
			profile.nameID = nameID[0]["_"];

			if (nameID[0]['$'].Format) {
				profile.nameIDFormat = nameID[0]['$'].Format;
			}
		}
	}

	var authnStatement = assertion.AuthnStatement;

	if (authnStatement) {
		if (authnStatement[0]['$'].SessionIndex) {

			profile.sessionIndex = authnStatement[0]['$'].SessionIndex;
			if (Meteor.settings.debug) {
				console.log("Session Index: " + profile.sessionIndex);
			}
		} else {
			if (Meteor.settings.debug) {
				console.log("No Session Index Found");
			}
		}


	} else {
		if (Meteor.settings.debug) {
			console.log("No AuthN Statement found");
		}
	}

	var attributeStatement = assertion.AttributeStatement;
	if (attributeStatement) {
		var attributes = attributeStatement[0].Attribute;

		if (attributes) {
			attributes.forEach(function (attribute) {
				var value = attribute.AttributeValue;
				if (typeof value[0] === 'string') {
					profile[attribute['$'].Name] = value[0];
				} else {
					profile[attribute['$'].Name] = value[0]['_'];
				}
			});
		}

		if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
			// See http://www.incommonfederation.org/attributesummary.html for definition of attribute OIDs
			profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
		}

		if (!profile.email && profile.mail) {
			profile.email = profile.mail;
		}
	}

	if (!profile.email && profile.nameID && profile.nameIDFormat && profile.nameIDFormat.indexOf('emailAddress') >= 0) {
		profile.email = profile.nameID;
	}
	if (Meteor.settings.debug) {
		console.log("NameID: " + JSON.stringify(profile));
	}

	callback(null, profile, false);*/

};
SAML.prototype.regexProcessValidlySignedAssertion = function(xml, callback){
	var profile = {};
	console.log("----------------------- SAML Assertion -------------------------");
	console.log(xml);
	console.log("----------------------- END SAML Assertion ---------------------");
	
	// profile.nameID= xml.match(/<NameID Format=\"urn\:oasis\:names\:tc\:SAML\:1\.1\:nameid\-format\:unspecified\">(.+?)<\/NameID>/)[1];
	profile.nameID = xml.match(/<Attribute Name=\"\/UniqueID\"><AttributeValue>(.+?)<\/AttributeValue><\/Attribute>/)[1];
	profile.nameIDFormat=profile.nameID;
	profile.email=profile.nameID;
	profile.issuer=xml.match(/<Issuer>(.+?)<\/Issuer>/)[1];
	// profile.hirarchy=xml.match(/<Attribute Name=\"http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/name\"><AttributeValue>(.+?)<\/AttributeValue><\/Attribute>/)[1];	
	profile.inResponseToId = xml.match(/InResponseTo=\"(.+?)\"/)[1];
	
	var firstname = xml.match(/<Attribute Name="http:\/\/schemas\.xmlsoap\.org\/ws\/2005\/05\/identity\/claims\/givenname\"><AttributeValue>(.+?)<\/AttributeValue><\/Attribute>/);
	if (firstname === null){
			firstname = xml.match(/<Attribute Name=\"http:\/\/schemas\.xmlsoap\.org\/ws\/2005\/05\/identity\/claims\/givenname\" a:OriginalIssuer="(.*?)" xmlns\:a=\"http:\/\/schemas\.xmlsoap\.org\/ws\/2009\/09\/identity\/claims\"><AttributeValue>(.+?)<\/AttributeValue><\/Attribute>/)[2].trim();
	}else{
		firstname = firstname[1].trim();
	}
	
	var lastname = xml.match(/<Attribute Name=\"http:\/\/schemas\.xmlsoap\.org\/ws\/2005\/05\/identity\/claims\/surname\"><AttributeValue>(.+?)<\/AttributeValue><\/Attribute>/);
	
		if (lastname === null){
			lastname = xml.match(/<Attribute Name=\"http:\/\/schemas\.xmlsoap\.org\/ws\/2005\/05\/identity\/claims\/surname\" a:OriginalIssuer="(.*?)" xmlns\:a=\"http:\/\/schemas\.xmlsoap\.org\/ws\/2009\/09\/identity\/claims\"><AttributeValue>(.+?)<\/AttributeValue><\/Attribute>/)[2].trim();
	}else{
		lastname = lastname[1].trim();
	}
	
	profile.name = firstname + " " + lastname;
	profile.username = profile.nameID.toLowerCase();
	profile.email=profile.nameID;	
	profile.mail = profile.nameID; // = xml.match(/<Attribute Name=\"http:\/\/schemas\.xmlsoap\.org\/ws\/2005\/05\/identity\/claims\/emailaddress\"><AttributeValue>(.+?)<\/AttributeValue><\/Attribute>/)[1];
	callback(null, profile, false);
}

SAML.prototype.processValidlySignedAssertion = function (xml, callback) {
	var self = this;
	var msg;
	var parserConfig = {
		explicitRoot: true,
		tagNameProcessors: [stripPrefix]
	};

	var nowMs = new Date().getTime();
    var profile = {};
    var assertion;
    var parser = new xml2js.Parser(parserConfig);
    parser.parseString(xml, function (doc) {

        assertion = doc.Assertion;

        var issuer = assertion.Issuer;
        if (issuer) {
            profile.issuer = issuer[0];
        }

        var authnStatement = assertion.AuthnStatement;
        if (authnStatement) {
            if (authnStatement[0].$ && authnStatement[0].$.SessionIndex) {
                profile.sessionIndex = authnStatement[0].$.SessionIndex;
            }
        }

        var subject = assertion.Subject;
        if (subject) {
            var nameID = subject[0].NameID;
            if (nameID) {
                profile.nameID = nameID[0]._ || nameID[0];

                if (nameID[0].$ && nameID[0].$.Format) {
                    profile.nameIDFormat = nameID[0].$.Format;
                }
            }
        }

        var subjectConfirmation = subject[0].SubjectConfirmation ?
			subject[0].SubjectConfirmation[0] : null;
        var confirmData = subjectConfirmation && subjectConfirmation.SubjectConfirmationData ?
			subjectConfirmation.SubjectConfirmationData[0] : null;
        if (subject[0].SubjectConfirmation && subject[0].SubjectConfirmation.length > 1) {
            msg = 'Unable to process multiple SubjectConfirmations in SAML assertion';
            throw new Error(msg);
        }

        if (subjectConfirmation) {
            if (confirmData && confirmData.$) {
                var subjectNotBefore = confirmData.$.NotBefore;
                var subjectNotOnOrAfter = confirmData.$.NotOnOrAfter;

                var subjErr = self.checkTimestampsValidityError(
					nowMs, subjectNotBefore, subjectNotOnOrAfter);
                if (subjErr) {
                    throw subjErr;
                }
            }
        }

		var conditions = assertion.Conditions ? assertion.Conditions[0] : null;
        if (assertion.Conditions && assertion.Conditions.length > 1) {
            msg = 'Unable to process multiple conditions in SAML assertion';
            throw new Error(msg);
        }
        if (conditions && conditions.$) {
            var conErr = self.checkTimestampsValidityError(
				nowMs, conditions.$.NotBefore, conditions.$.NotOnOrAfter);
            if (conErr)
                throw conErr;
        }

        var attributeStatement = assertion.AttributeStatement;
        if (attributeStatement) {
            var attributes = attributeStatement[0].Attribute;

            var attrValueMapper = function (value) {
                return typeof value === 'string' ? value : value._;
            };

            if (attributes) {
                attributes.forEach(function (attribute) {
                    var value = attribute.AttributeValue;
                    if (value.length === 1) {
                        profile[attribute.$.Name] = attrValueMapper(value[0]);
                    } else {
                        profile[attribute.$.Name] = value.map(attrValueMapper);
                    }
                });
            }
        }

        if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
            // See http://www.incommonfederation.org/attributesummary.html for definition of attribute OIDs
            profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
        }

        if (!profile.email && profile.mail) {
            profile.email = profile.mail;
        }

        profile.getAssertionXml = function () { return xml; };

        callback(null, profile, false);
    });
}

SAML.prototype.generateServiceProviderMetadata = function (callbackUrl) {

	var keyDescriptor = null;

	if (!decryptionCert) {
		decryptionCert = this.options.privateCert;
	}

	if (this.options.privateKey) {
		if (!decryptionCert) {
			throw new Error(
				"Missing decryptionCert while generating metadata for decrypting service provider");
		}

		decryptionCert = decryptionCert.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, '');
		decryptionCert = decryptionCert.replace(/-+END CERTIFICATE-+\r?\n?/, '');
		decryptionCert = decryptionCert.replace(/\r\n/g, '\n');

		keyDescriptor1 = {
			'@use': 'signing',
			'ds:KeyInfo': {
				'@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
				'ds:X509Data': {
					'ds:X509Certificate': {
						'#text': decryptionCert
					}
				}
			},
			'#list': [
				// this should be the set that the xmlenc library supports
				{
					'EncryptionMethod': {
						'@Algorithm': 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
					}
				},
				{
					'EncryptionMethod': {
						'@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
					}
				},
				{
					'EncryptionMethod': {
						'@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
					}
				},
				{
					'EncryptionMethod': {
						'@Algorithm': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
					}
				},
			]
		};

		keyDescriptor2 = {
			'@use': 'encryption',
			'ds:KeyInfo': {
				'@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
				'ds:X509Data': {
					'ds:X509Certificate': {
						'#text': decryptionCert
					}
				}
			},
			'#list': [
				// this should be the set that the xmlenc library supports
				{
					'EncryptionMethod': {
						'@Algorithm': 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
					}
				},
				{
					'EncryptionMethod': {
						'@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
					}
				},
				{
					'EncryptionMethod': {
						'@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
					}
				},
				{
					'EncryptionMethod': {
						'@Algorithm': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
					}
				},
			]
		};
	}

	if (!this.options.callbackUrl && !callbackUrl) {
		throw new Error(
			"Unable to generate service provider metadata when callbackUrl option is not set");
	}

	var metadata = {
		'EntityDescriptor': {
			'@xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
			'@entityID': this.options.issuer,
			'SPSSODescriptor': {
				'@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol',
				// 'KeyDescriptor': keyDescriptor,
				'#list': [
					{ 'KeyDescriptor': keyDescriptor1 },
					{ 'KeyDescriptor': keyDescriptor2 }
				],
				'SingleLogoutService': {
					'@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
					'@Location': Meteor.absoluteUrl() + "_saml/logout/" + this.options.provider + "/",
					//'@ResponseLocation': Meteor.absoluteUrl() + "_saml/logout/" + this.options.provider + "/"
				},
				'NameIDFormat': this.options.identifierFormat,
				'#list2': [
					{
						'AssertionConsumerService': {
							'@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
							'@Location': Meteor.absoluteUrl() + "_saml/logout/" + this.options.provider + "/",
							'@index': '1'
						}
					},
					{
						'AssertionConsumerService': {
							'@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
							'@Location': callbackUrl,
							'@index': '0'
						}
					},
				]
			},
			'ContactPerson': {
				'@contactType': 'technical',
				'GivenName': 'Administrator',
				'EmailAddress': 'noreply@example.org'
			}
		}
	};

	return xmlbuilder.create(metadata).end({
		pretty: true,
		indent: '  ',
		newline: '\n'
	});
};