package com.github.luk.pnkdss.utils;

public class SignatureResult {

	protected boolean ResultOK;
	protected boolean XmlValid;
	protected boolean chain;
	protected String subject;
	protected String issuer;
	protected String pem;
	protected String text;
	protected String payload;
	protected String timestamp;
	
	public SignatureResult() {
    	setChain(false);
    	setResultOK(false);
    	setXmlValid(false);
        setText("");
        setIssuer("");
        setPem("");
        setSubject("");
        setPayload("");
        setTimestamp("");
	}
	
	public String getPayload() {
		return payload;
	}

	public void setPayload(String payload) {
		this.payload = payload;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}

	public boolean isResultOK() {
		return ResultOK;
	}
	public void setResultOK(boolean resultOK) {
		ResultOK = resultOK;
	}
	public boolean isXmlValid() {
		return XmlValid;
	}
	public void setXmlValid(boolean xmlValid) {
		XmlValid = xmlValid;
	}
	public boolean isChain() {
		return chain;
	}
	public void setChain(boolean chain) {
		this.chain = chain;
	}
	public String getSubject() {
		return subject;
	}
	public void setSubject(String subject) {
		this.subject = subject;
	}
	public String getIssuer() {
		return issuer;
	}
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	public String getPem() {
		return pem;
	}
	public void setPem(String pem) {
		this.pem = pem;
	}
	public String getText() {
		return text;
	}
	public void setText(String text) {
		this.text = text;
	}
}
