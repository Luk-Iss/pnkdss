package com.github.luk.pnkdss;

import java.io.InputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

public class Validator {

	Logger log = LoggerFactory.getLogger(Signer.class);

	public static void main(String[] args) {
		System.out.println("Start!");
		Validator validator = new Validator();
		InputStream document = Signer.class.getResourceAsStream("/docsigned.xml");
		System.out.println("document: " + document);
		try {
			SignatureResult sr = validator.check(document);
			System.out.println("---- 1 ----");
			System.out.println("Signing certificate: "	+ sr.getPem());
			System.out.println("---- 2 ----");
			System.out.println("Valid: " + (sr.isResultOK() ? "Yes." : "No."));
			System.out.println("---- 3 ----");
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("Stop!");
	}

	/**
	 * @param signeddoc signed document (xades baseline b enveloped)
	 */
	public SignatureResult check(InputStream signeddoc) throws Exception {

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setAIASource(null);
		DSSDocument xmlDocument = new InMemoryDocument(signeddoc);

		SignatureResult sr = new SignatureResult();
		
		XMLDocumentValidator xmlDocumentValidator = new XMLDocumentValidator(xmlDocument);
		xmlDocumentValidator.setCertificateVerifier(certificateVerifier);
		sr.setPem(
				DSSUtils.convertToPEM(
						xmlDocumentValidator.getSignatures().get(0).getSigningCertificateToken()
				)
		);

		Reports reports = xmlDocumentValidator.validateDocument();
		
		log.info(reports.getXmlDetailedReport());

		String sigid = reports.getDiagnosticData().getSignatureIdList().iterator().next();
		SignatureWrapper sid = reports.getDiagnosticData().getSignatureById(sigid);
		sr.setResultOK(sid.isSignatureValid());
		
		return sr;
	}
}