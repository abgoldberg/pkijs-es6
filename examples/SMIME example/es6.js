import * as asn1js from "asn1js";
import { arrayBufferToString, stringToArrayBuffer, bufferToHexCodes, utilConcatBuf } from "pvutils";
import Certificate from "pkijs/src/Certificate";
import SignedData from "pkijs/src/SignedData";
import ContentInfo from "pkijs/src/ContentInfo";
//*********************************************************************************
const trustedCertificates = []; // Array of root certificates from "CA Bundle"
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
		
		resultString = resultString + pemString[i];
	}
	
	return resultString;
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Parse "CA Bundle" file
//*********************************************************************************
function parseCAbundle(buffer)
{
	//region Initial variables
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	
	const startChars = "-----BEGIN CERTIFICATE-----";
	const endChars = "-----END CERTIFICATE-----";
	const endLineChars = "\r\n";
	
	const view = new Uint8Array(buffer);
	
	let waitForStart = false;
	let middleStage = true;
	let waitForEnd = false;
	let waitForEndLine = false;
	let started = false;
	
	let certBodyEncoded = "";
	//endregion
	
	for(let i = 0; i < view.length; i++)
	{
		if(started === true)
		{
			if(base64Chars.indexOf(String.fromCharCode(view[i])) !== (-1))
				certBodyEncoded = certBodyEncoded + String.fromCharCode(view[i]);
			else
			{
				if(String.fromCharCode(view[i]) === "-")
				{
					//region Decoded trustedCertificates
					const asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(certBodyEncoded)));
					try
					{
						trustedCertificates.push(new Certificate({ schema: asn1.result }));
					}
					catch(ex)
					{
						alert("Wrong certificate format");
						return;
					}
					//endregion
					
					//region Set all "flag variables"
					certBodyEncoded = "";
					
					started = false;
					waitForEnd = true;
					//endregion
				}
			}
		}
		else
		{
			if(waitForEndLine === true)
			{
				if(endLineChars.indexOf(String.fromCharCode(view[i])) === (-1))
				{
					waitForEndLine = false;
					
					if(waitForEnd === true)
					{
						waitForEnd = false;
						middleStage = true;
					}
					else
					{
						if(waitForStart === true)
						{
							waitForStart = false;
							started = true;
							
							certBodyEncoded = certBodyEncoded + String.fromCharCode(view[i]);
						}
						else
							middleStage = true;
					}
				}
			}
			else
			{
				if(middleStage === true)
				{
					if(String.fromCharCode(view[i]) === "-")
					{
						if((i === 0) ||
							((String.fromCharCode(view[i - 1]) === "\r") ||
							(String.fromCharCode(view[i - 1]) === "\n")))
						{
							middleStage = false;
							waitForStart = true;
						}
					}
				}
				else
				{
					if(waitForStart === true)
					{
						if(startChars.indexOf(String.fromCharCode(view[i])) === (-1))
							waitForEndLine = true;
					}
					else
					{
						if(waitForEnd === true)
						{
							if(endChars.indexOf(String.fromCharCode(view[i])) === (-1))
								waitForEndLine = true;
						}
					}
				}
			}
		}
	}
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Verify SMIME signature
//*********************************************************************************
export function verifySMIME()
{
    //region Parse MIME contents to find signature and detached data
    const parser = new MimeParser();
    parser.write(document.getElementById("smime_message").value);
    parser.end();
    //endregion

    if(("_childNodes" in parser.node) || (parser.node._childNodes.length !== 2))
    {
        const lastNode = parser.getNode("2");
        if((lastNode.contentType.value === "application/x-pkcs7-signature") || (lastNode.contentType.value === "application/pkcs7-signature"))
        {
            // Get signature buffer
            const signedBuffer = utilConcatBuf(new ArrayBuffer(0), lastNode.content);

            // Parse into pkijs types
            const asn1 = asn1js.fromBER(signedBuffer);
            const cmsContentSimpl = new ContentInfo({ schema: asn1.result });
            const cmsSignedSimpl = new SignedData({ schema: cmsContentSimpl.content });

            // Get signed data buffer
            const signedDataBuffer = stringToArrayBuffer(parser.nodes.node1.raw.replace(/\n/g, "\r\n"));

            // Verify the signed data
            let sequence = Promise.resolve();
            sequence = sequence.then(
                () => {
                    return cmsSignedSimpl.verify({ signer: 0, data: signedDataBuffer, trusted_certs: trustedCertificates });
                }
            );

            sequence.then(
                result => {
                    let failed = false;
                    if(typeof result !== "undefined")
                    {
                        if(result === false)
                        {
                            failed = true;
                        }
                    }

                    if (failed) {
                        alert("S/MIME message verification failed!");
                    } else {
                        alert("S/MIME message successfully verified!");
                    }
                },
                error =>
                    alert(`Error during verification: ${error}`)
            );
        }
    }
    else
        alert("No child nodes!");
}

//*********************************************************************************
//endregion 
//*********************************************************************************
//region Functions handling file selection
//*********************************************************************************
export function handleMIMEFile(evt)
{
        var tempReader = new FileReader();

        var current_files = evt.target.files;

        tempReader.onload =
                event => {
                        document.getElementById("smime_message").value = String.fromCharCode.apply(null, new Uint8Array(event.target.result));
                };

        tempReader.readAsArrayBuffer(current_files[0]);
}
//*********************************************************************************
export function handleCABundle(evt)
{
	const tempReader = new FileReader();
	
	const currentFiles = evt.target.files;
	
	tempReader.onload =
		event => parseCAbundle(event.target.result);
	
	tempReader.readAsArrayBuffer(currentFiles[0]);
}
//*********************************************************************************
//endregion
//*********************************************************************************
