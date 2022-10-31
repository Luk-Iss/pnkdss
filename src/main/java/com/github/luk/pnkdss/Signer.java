package com.github.luk.pnkdss;

import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class Signer {

	public static void main(String[] args) throws Exception {
		System.out.println("Start!");
		System.out.println("Working directory: " + System.getProperty("user.dir"));
		System.out.println("Parse parameters");
		if(args.length < 4 || args.length > 5) {
			System.err.println("Error: This command have to have 4 or 5 parameters");
			help();
			return;
		}
		File signatureF = new File(args[0]);
		if(!signatureF.exists()) {
			System.err.println("Error: The file with key '" + args[0] + "' doesn't exists.");
			help();
			return;
		}
		File documentF = new File(args[1]);
		if(!documentF.exists()) {
			System.err.println("Error: The subscribed file '" + args[1] + "' doesn't exists.");
			help();
			return;
		}
		TypeE typeE = null;
		try {
			typeE = TypeE.valueOf(args[2].toUpperCase()); 
		} catch (IllegalArgumentException e) {
			System.err.println("Error: Wrong parameter '" + args[2] + "' have to be 'F' or 'P'");
			help();
			return;
		}
		WriteE writeE = null;
		try {
			writeE = WriteE.valueOf(args[3].toUpperCase()); 
		} catch (IllegalArgumentException e) {
			System.err.println("Error: Wrong parameter '" + args[3] + "' have to be 'W' or 'N'");
			help();
			return;
		}
		char[] passCh = null;
		if(typeE.equals(TypeE.P)) {
			Console cnsl = System.console();
			if(cnsl == null) {
				System.err.println("Error: No console aviable");
				return;
			}
			passCh = cnsl.readPassword("Enter password: ");
		} else {
			File passwordF = new File(args[4]);
			if(!passwordF.exists()) {
				System.err.println("Error: The file with password '" + args[4] + "' doesn't exists.");
				help();
				return;
			}
			passCh = new String(Files.readAllBytes(passwordF.toPath())).toCharArray();
		}
		if(writeE.equals(WriteE.W)) {
			System.out.println("Pass: '" + String.valueOf(passCh) + "'");
		}
		
				
		InputStream document = new FileInputStream(documentF);
		InputStream p12 = new FileInputStream(signatureF);
		String output = null;
		Signer signer = new Signer();
		try {
			output = signer.sign(document, p12, passCh);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("Output:");
		System.err.println(output);
		System.out.println("Stop!");
	}
	
	public static enum TypeE { F, P };
	public static enum WriteE { W, N };
	
	public static void help() {
		System.out.println("Check: java -version returns version 1.8");
		System.out.println("Run: java -jar target/pnkDss-1.0-SNAPSHOT-one.jar signcert.p12 document.xml f n pass.txt");
		System.out.println("1: file name with signing key and certificate (one key only), p12 format");
		System.out.println("2: file name with signed document (without signature, all data included)");
		System.out.println("3: f - the password is in file, p - prompt password");
		System.out.println("4: w - print out the password, n - don't print the password");
		System.out.println("5: file name with password (or nothing if p)");
	}

	/**
	 * @param document document
	 * @param keystore p12 form, one key
	 * @param password for keystore
	 * @return signed document
	 */
	public String sign(InputStream document, InputStream keystore, char[] password)
			throws Exception {

		DSSDocument binaryInMemoryDocument = new InMemoryDocument(document);

		Pkcs12SignatureToken token = new Pkcs12SignatureToken(
				keystore, new PasswordProtection(password)
		);

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setXPathLocationString("//*[@*[local-name()='id']='signedData']/*[last()]");
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

		List<DSSReference> references = new ArrayList<>();
		// Initialize and configure ds:Reference based on the provided signer document
		DSSReference dssReference = new DSSReference();
		dssReference.setContents(binaryInMemoryDocument);
		dssReference.setId("r-" + binaryInMemoryDocument.hashCode());
		List<DSSTransform> transforms = new ArrayList<DSSTransform>();
		DSSTransform envelopedTransform = new EnvelopedSignatureTransform();
		transforms.add(envelopedTransform);
		DSSTransform canonicalization = new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
		transforms.add(canonicalization);
		dssReference.setTransforms(transforms);
		// set empty URI to cover the whole document
		dssReference.setUri("#signedData");
		dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		references.add(dssReference);
		// set references
		parameters.setReferences(references);
		parameters.setXPathElementPlacement(
				XAdESSignatureParameters.XPathElementPlacement.XPathAfter
		);
		parameters.setEn319132(false);

		parameters.setSigningCertificate(token.getKeys().get(0).getCertificate());
		parameters.setCertificateChain(token.getKeys().get(0).getCertificateChain());

		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

		XAdESService service = new XAdESService(commonCertificateVerifier);

		ToBeSigned dataToSign = service.getDataToSign(binaryInMemoryDocument, parameters);

		SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), token.getKeys().get(0));

		token.close();

		DSSDocument signedDocument = service.signDocument(
				binaryInMemoryDocument, parameters, signatureValue
		);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		signedDocument.writeTo(baos);

		return baos.toString();
	}
}