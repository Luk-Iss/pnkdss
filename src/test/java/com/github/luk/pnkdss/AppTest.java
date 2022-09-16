package com.github.luk.pnkdss;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( AppTest.class );
    }
    
    public static String pass = "7T4W#+bjYY9wrS78";

    /**
     * Rigourous Test :-)
     */
    public void testApp()
    {	InputStream document = Signer.class.getResourceAsStream("/document.xml");
		InputStream p12 = Signer.class.getResourceAsStream("/signcert.p12");
		String output = null;
		Signer signer = new Signer();
		try {
			output = signer.sign(document, p12,pass.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			assert(false);
		}
		document = new ByteArrayInputStream(output.getBytes());
		Validator validator = new Validator();
		SignatureResult sr = null;
		try {
			sr = validator.check(document);
		} catch (Exception e) {
			e.printStackTrace();
			assert(false);
		}
        assertTrue(sr.isResultOK());
    }
    
    public void testApp2()
    {	InputStream document = Signer.class.getResourceAsStream("/document.xml");
		InputStream p12 = Signer.class.getResourceAsStream("/signcert.p12");
		String output = null;
		Signer signer = new Signer();
		try {
			output = signer.sign(document, p12,pass.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
			assert(false);
		}

		/*
		 * !!
		 */
		output = output.replace("Hello World!", "Hello World?");
		
		document = new ByteArrayInputStream(output.getBytes());
		Validator validator = new Validator();
		SignatureResult sr = null;
		
		try {
			sr = validator.check(document);
		} catch (Exception e) {
			e.printStackTrace();
			assert(false);
		}
        assertTrue(!sr.isResultOK());
    }
}
