import * as asn1js from "asn1js";
import { getParametersValue } from "pvutils";
import IssuerAndSerialNumber from "pkijs/src/IssuerAndSerialNumber";
import OriginatorPublicKey from "pkijs/src/OriginatorPublicKey";
//**************************************************************************************
export default class OriginatorIdentifierOrKey 
{
	//**********************************************************************************
	/**
	 * Constructor for OriginatorIdentifierOrKey class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {number}
		 * @description variant
		 */
		this.variant = getParametersValue(parameters, "variant", OriginatorIdentifierOrKey.defaultValues("variant"));

		if("value" in parameters)
			/**
			 * @type {Array}
			 * @description values
			 */
			this.value = getParametersValue(parameters, "value", OriginatorIdentifierOrKey.defaultValues("value"));
		//endregion
		
		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "variant":
				return (-1);
			case "value":
				return {};
			default:
				throw new Error(`Invalid member name for OriginatorIdentifierOrKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "variant":
				return (memberValue === (-1));
			case "value":
				return (Object.keys(memberValue).length === 0);
			default:
				throw new Error(`Invalid member name for OriginatorIdentifierOrKey class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//OriginatorIdentifierOrKey ::= CHOICE {
		//    issuerAndSerialNumber IssuerAndSerialNumber,
		//    subjectKeyIdentifier [0] SubjectKeyIdentifier,
		//    originatorKey [1] OriginatorPublicKey }
		
		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new asn1js.Choice({
			value: [
				IssuerAndSerialNumber.schema({
					names: {
						blockName: (names.blockName || "")
					}
				}),
				new asn1js.Primitive({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					name: (names.blockName || "")
				}),
				new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					name: (names.blockName || ""),
					value: OriginatorPublicKey.schema().valueBlock.value
				})
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = asn1js.compareSchema(schema,
			schema,
			OriginatorIdentifierOrKey.schema({
				names: {
					blockName: "blockName"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for OriginatorIdentifierOrKey");
		//endregion

		//region Get internal properties from parsed schema
		if(asn1.result.blockName.idBlock.tagClass === 1)
		{
			this.variant = 1;
			this.value = new IssuerAndSerialNumber({ schema: asn1.result.blockName });
		}
		else
		{
			if(asn1.result.blockName.idBlock.tagNumber === 0)
			{
				//region Create "OCTETSTRING" from "ASN1_PRIMITIVE"
				asn1.result.blockName.idBlock.tagClass = 1; // UNIVERSAL
				asn1.result.blockName.idBlock.tagNumber = 4; // OCTETSTRING
				//endregion

				this.variant = 2;
				this.value = asn1.result.blockName;
			}
			else
			{
				//region Create "SEQUENCE" from "ASN1_CONSTRUCTED"
				asn1.result.blockName.idBlock.tagClass = 1; // UNIVERSAL
				asn1.result.blockName.idBlock.tagNumber = 16; // SEQUENCE
				//endregion

				this.variant = 3;
				this.value = new OriginatorPublicKey({ schema: asn1.result.blockName });
			}
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		switch(this.variant)
		{
			case 1:
				return this.value.toSchema();
			case 2:
				this.value.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
				this.value.idBlock.tagNumber = 0; // [0]

				return this.value;
			case 3:
				{
					const _schema = this.value.toSchema();

					_schema.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
					_schema.idBlock.tagNumber = 1; // [1]

					return _schema;
				}
			default:
				return new asn1js.Any();
		}
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		const _object = {
			variant: this.variant
		};

		if((this.variant === 1) || (this.variant === 2) || (this.variant === 3))
			_object.value = this.value.toJSON();

		return _object;
	}
	//**********************************************************************************
}
//**************************************************************************************
