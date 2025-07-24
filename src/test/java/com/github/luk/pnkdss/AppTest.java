package com.github.luk.pnkdss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import com.github.luk.pnkdss.utils.Generator;
import com.github.luk.pnkdss.utils.SignatureResult;
import com.github.luk.pnkdss.utils.Signer;
import com.github.luk.pnkdss.utils.Validator;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class AppTest extends TestCase {
  static {
    try {
      KeyStore p12KeyStore = Generator.createP12KeyStore();
      try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
        p12KeyStore.store(bos, Generator.DEFAULT_PASSWORD.toCharArray());
        System.out.println("P12 KeyStore byl úspěšně vygenerován do paměti.");
        p12 = bos.toByteArray();
      }
    } catch (Exception e) {
      e.printStackTrace();
      throw new RuntimeException("Nepodařilo se inicializovat p12 KeyStore", e);
    }
  }

  /**
   * Create the test case
   *
   * @param testName name of the test case
   */
  public AppTest(String testName) {
    super(testName);
  }

  /**
   * @return the suite of tests being tested
   */
  public static Test suite() {
    return new TestSuite(AppTest.class);
  }

  //private static InputStream p12;
  private static byte[] p12;

  /**
   * Rigourous Test :-)
   */
  public void testApp() {
    InputStream document = new ByteArrayInputStream(Generator.xmlContent.getBytes(StandardCharsets.UTF_8));
    String output = null;
    try {
      output = Signer.sign(document, new ByteArrayInputStream(p12), Generator.DEFAULT_PASSWORD.toCharArray());
    } catch (Exception e) {
      e.printStackTrace();
      assert (false);
    }
    document = new ByteArrayInputStream(output.getBytes());
    SignatureResult sr = null;
    try {
      sr = Validator.check(document);
    } catch (Exception e) {
      e.printStackTrace();
      assert (false);
    }
    assertTrue(sr.isResultOK());
  }

  public void testApp2() {
    InputStream document = new ByteArrayInputStream(Generator.xmlContent.getBytes(StandardCharsets.UTF_8));
    String output = null;
    try {
      output = Signer.sign(document, new ByteArrayInputStream(p12), Generator.DEFAULT_PASSWORD.toCharArray());
    } catch (Exception e) {
      e.printStackTrace();
      assert (false);
    }

    /*
     * !!
     */
    output = output.replace("Hello World!", "Hello World?");

    document = new ByteArrayInputStream(output.getBytes());
    SignatureResult sr = null;

    try {
      sr = Validator.check(document);
    } catch (Exception e) {
      e.printStackTrace();
      assert (false);
    }
    assertTrue(!sr.isResultOK());
  }
}
