package com.github.luk.pnkdss;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.springframework.stereotype.Component;

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

@Component
public class Signer {

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