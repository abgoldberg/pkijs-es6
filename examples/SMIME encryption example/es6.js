import * as asn1js from "asn1js";
import { arrayBufferToString, stringToArrayBuffer, utilConcatBuf } from "pvutils";
import { getCrypto, getAlgorithmParameters } from "pkijs/src/common";
import Certificate from "pkijs/src/Certificate";
import EnvelopedData from "pkijs/src/EnvelopedData";
import ContentInfo from "pkijs/src/ContentInfo";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue";
import BasicConstraints from "pkijs/src/BasicConstraints";
import Extension from "pkijs/src/Extension";
//*********************************************************************************
let certificateBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created CERT 
let trustedCertificates = []; // Array of root certificates from "CA Bundle"
//*********************************************************************************
//region Auxiliary functions 
//*********************************************************************************
function formatPEM(pemString)
{
	const stringLength = pemString.length;
	let resultString = "";
	
	for(let i = 0, count = 0; i < stringLength; i++, count++)
	{
		if(count > 63)
		{
			resultString = `${resultString}\r\n`;
			count = 0;
		}
		
		resultString = `${resultString}${pemString[i]}`;
	}
	
	return resultString;
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Create CERT  
//*********************************************************************************
export function createCertificate()
{
	//region Initial variables
	let sequence = Promise.resolve();
	
	const certificate = new Certificate();
	
	let publicKey;
	let privateKey;
	
	let hashAlgorithm;
	const hashOption = document.getElementById("hash_alg").value;
	switch(hashOption)
	{
		case "alg_SHA1":
			hashAlgorithm = "sha-1";
			break;
		case "alg_SHA256":
			hashAlgorithm = "sha-256";
			break;
		case "alg_SHA384":
			hashAlgorithm = "sha-384";
			break;
		case "alg_SHA512":
			hashAlgorithm = "sha-512";
			break;
		default:
	}
	
	let signatureAlgorithmName;
	const signOption = document.getElementById("sign_alg").value;
	switch(signOption)
	{
		case "alg_RSA15":
			signatureAlgorithmName = "RSASSA-PKCS1-V1_5";
			break;
		case "alg_RSA2":
			signatureAlgorithmName = "RSA-PSS";
			break;
		case "alg_ECDSA":
			signatureAlgorithmName = "ECDSA";
			break;
		default:
	}
	//endregion
	
	//region Get a "crypto" extension
	const crypto = getCrypto();
	if(typeof crypto === "undefined")
	{
		alert("No WebCrypto extension found");
		return;
	}
	//endregion
	
	//region Put a static values
	certificate.version = 2;
	certificate.serialNumber = new asn1js.Integer({ value: 1 });
	certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.6", // Country name
		value: new asn1js.PrintableString({ value: "RU" })
	}));
	certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.3", // Common name
		value: new asn1js.BmpString({ value: "Test" })
	}));
	certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.6", // Country name
		value: new asn1js.PrintableString({ value: "RU" })
	}));
	certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.3", // Common name
		value: new asn1js.BmpString({ value: "Test" })
	}));
	
	certificate.notBefore.value = new Date(2016, 1, 1);
	certificate.notAfter.value = new Date(2019, 1, 1);
	
	certificate.extensions = []; // Extensions are not a part of certificate by default, it's an optional array
	
	//region "BasicConstraints" extension
	let basic_constr = new BasicConstraints({
		cA: true,
		pathLenConstraint: 3
	});
	
	certificate.extensions.push(new Extension({
		extnID: "2.5.29.19",
		critical: false,
		extnValue: basic_constr.toSchema().toBER(false),
		parsedValue: basic_constr // Parsed value for well-known extensions
	}));
	//endregion
	
	//region "KeyUsage" extension
	const bitArray = new ArrayBuffer(1);
	const bitView = new Uint8Array(bitArray);
	
	bitView[0] = bitView[0] | 0x02; // Key usage "cRLSign" flag
	bitView[0] = bitView[0] | 0x04; // Key usage "keyCertSign" flag
	
	const keyUsage = new asn1js.BitString({ valueHex: bitArray });
	
	certificate.extensions.push(new Extension({
		extnID: "2.5.29.15",
		critical: false,
		extnValue: keyUsage.toBER(false),
		parsedValue: keyUsage // Parsed value for well-known extensions
	}));
	//endregion
	//endregion
	
	//region Create a new key pair
	sequence = sequence.then(() => {
		//region Get default algorithm parameters for key generation
		const algorithm = getAlgorithmParameters(signatureAlgorithmName, "generatekey");
		if("hash" in algorithm.algorithm)
			algorithm.algorithm.hash.name = hashAlgorithm;
		//endregion
		
		return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
	});
	//endregion
	
	//region Store new key in an interim variables
	sequence = sequence.then(keyPair => {
		publicKey = keyPair.publicKey;
		privateKey = keyPair.privateKey;
	}, error => {
		alert(`Error during key generation: ${error}`);
	});
	//endregion
	
	//region Exporting public key into "subjectPublicKeyInfo" value of certificate
	sequence = sequence.then(() =>
		certificate.subjectPublicKeyInfo.importKey(publicKey)
	);
	//endregion
	
	//region Signing final certificate
	sequence = sequence.then(() =>
			certificate.sign(privateKey, hashAlgorithm),
		error => {
			alert(`Error during exporting public key: ${error}`);
		});
	//endregion
	
	//region Encode and store certificate
	sequence = sequence.then(() => {
		certificateBuffer = certificate.toSchema(true).toBER(false);
		
		const certificateString = String.fromCharCode.apply(null, new Uint8Array(certificateBuffer));
		
		let resultString = "-----BEGIN CERTIFICATE-----\r\n";
		resultString = `${resultString}${formatPEM(window.btoa(certificateString))}`;
		resultString = `${resultString}\r\n-----END CERTIFICATE-----\r\n`;
		
		trustedCertificates.push(certificate);
		
		document.getElementById("new_signed_data").innerHTML = resultString;
		
		alert("Certificate created successfully!");
	}, error => {
		alert(`Error during signing: ${error}`);
	});
	//endregion
	
	//region Exporting private key
	sequence = sequence.then(() =>
		crypto.exportKey("pkcs8", privateKey)
	);
	//endregion
	
	//region Store exported key on Web page
	sequence = sequence.then(result => {
		const privateKeyString = String.fromCharCode.apply(null, new Uint8Array(result));
		
		let resultString = "";
		
		resultString = `${resultString}\r\n-----BEGIN PRIVATE KEY-----\r\n`;
		resultString = `${resultString}${formatPEM(window.btoa(privateKeyString))}`;
		resultString = `${resultString}\r\n-----END PRIVATE KEY-----\r\n`;
		
		document.getElementById("pkcs8_key").innerHTML = resultString;
		
		alert("Private key exported successfully!");
	}, error => {
		alert(`Error during exporting of private key: ${error}`);
	});
	//endregion
	
	return sequence;
}
//*********************************************************************************
//endregion 
//*********************************************************************************
//region Encrypt input data and format as S/MIME message
//*********************************************************************************
export function smimeEncrypt()
{
	//region Decode input certificate 
	let encodedCertificate = document.getElementById("new_signed_data").innerHTML;
	let clearEncodedCertificate = encodedCertificate.replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, '');
	let certificateBuffer = stringToArrayBuffer(window.atob(clearEncodedCertificate));
	
	let asn1 = asn1js.fromBER(certificateBuffer);
	let certSimpl = new Certificate({ schema: asn1.result });
	//endregion 
	
	//region Create WebCrypto form of content encryption algorithm 
	let encryptionAlgorithm = {};
	
	let encryptionAlgorithmSelect = document.getElementById("content_enc_alg").value;
	switch(encryptionAlgorithmSelect)
	{
		case "alg_CBC":
			encryptionAlgorithm.name = "AES-CBC";
			break;
		case "alg_GCM":
			encryptionAlgorithm.name = "AES-GCM";
			break;
		default:
	}
	
	let encryptionAlgorithmLengthSelect = document.getElementById("content_enc_alg_len").value;
	switch(encryptionAlgorithmLengthSelect)
	{
		case "len_128":
			encryptionAlgorithm.length = 128;
			break;
		case "len_192":
			encryptionAlgorithm.length = 192;
			break;
		case "len_256":
			encryptionAlgorithm.length = 256;
			break;
		default:
	}
	//endregion 
	
	let cmsEnveloped = new EnvelopedData();
	
	cmsEnveloped.addRecipientByCertificate(certSimpl);
	
	cmsEnveloped.encrypt(encryptionAlgorithm, stringToArrayBuffer(document.getElementById("content").value)).
	then(
		() => {
			let cmsContentSimpl = new ContentInfo();
			cmsContentSimpl.contentType = "1.2.840.113549.1.7.3";
			cmsContentSimpl.content = cmsEnveloped.toSchema();
			
			let schema = cmsContentSimpl.toSchema();
			let ber = schema.toBER(false);
			
                        // Insert enveloped data into new Mime message
                        var Mimebuilder = window['emailjs-mime-builder'];
                        let mimeBuilder = new Mimebuilder('application/pkcs7-mime; name=smime.p7m; smime-type=enveloped-data')
                            .setHeader('content-description', 'Enveloped Data')
                            .setHeader('content-disposition', 'attachment; filename=smime.p7m')
                            .setHeader('content-transfer-encoding', 'base64')
                            .setContent(new Uint8Array(ber));
                        mimeBuilder.setHeader('from', 'sender@example.com');
                        mimeBuilder.setHeader('to', 'recipient@example.com');
                        mimeBuilder.setHeader('subject', 'Example S/MIME encrypted message');
                        let mimeMessage = mimeBuilder.build();

		        document.getElementById("encrypted_content").innerHTML = mimeMessage;
			
			alert("Encryption process finished successfully");
		},
		error => alert("ERROR DURING ENCRYPTION PROCESS: " + error)
	);
}
//*********************************************************************************
//endregion 
//*********************************************************************************
//region Decrypt input data 
//*********************************************************************************
export function smimeDecrypt()
{
	//region Decode input certificate 
	let encodedCertificate = document.getElementById("new_signed_data").innerHTML;
	let clearEncodedCertificate = encodedCertificate.replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, '');
	let certificateBuffer = stringToArrayBuffer(window.atob(clearEncodedCertificate));
	
	let asn1 = asn1js.fromBER(certificateBuffer);
	let certSimpl = new Certificate({ schema: asn1.result });
	//endregion 
	
	//region Decode input private key 
	let encodedPrivateKey = document.getElementById("pkcs8_key").innerHTML;
	let clearPrivateKey = encodedPrivateKey.replace(/(-----(BEGIN|END)( NEW)? PRIVATE KEY-----|\n)/g, '');
	let privateKeyBuffer = stringToArrayBuffer(window.atob(clearPrivateKey));
	//endregion 
	
	//region Parse S/MIME message to get CMS enveloped content 

        // Parse MIME message and extract the envelope data
        const parser = new MimeParser();

	let mimeMessage = document.getElementById("encrypted_content").innerHTML;
        parser.write(mimeMessage);
        parser.end();
        //endregion

        // Note: MimeParser handles the base64 decoding to get us back a buffer
        const cmsEnvelopedBuffer = utilConcatBuf(new ArrayBuffer(0), parser.node.content);
	
	asn1 = asn1js.fromBER(cmsEnvelopedBuffer);
	let cmsContentSimpl = new ContentInfo({ schema: asn1.result });
	let cmsEnvelopedSimp = new EnvelopedData({ schema: cmsContentSimpl.content });
	//endregion 
	
	cmsEnvelopedSimp.decrypt(0,
		{
			recipientCertificate: certSimpl,
			recipientPrivateKey: privateKeyBuffer
		}).then(
		result => document.getElementById("decrypted_content").innerHTML = arrayBufferToString(result),
		(error => alert("ERROR DURING DECRYPTION PROCESS: " + error))
	);
}
//*********************************************************************************
//endregion 
//*********************************************************************************
