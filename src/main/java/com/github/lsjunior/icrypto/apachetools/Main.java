package com.github.lsjunior.icrypto.apachetools;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.github.lsjunior.icrypto.core.certificate.impl.PemCertificateReader;
import com.github.lsjunior.icrypto.core.certificate.impl.PemCertificateWriter;
import com.github.lsjunior.icrypto.core.certificate.impl.Pkcs7CertificateReader;
import com.github.lsjunior.icrypto.core.certificate.util.CertPaths;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.certificate.util.OpenSslCertificates;
import com.github.lsjunior.icrypto.core.crl.impl.PemCrlWriter;
import com.github.lsjunior.icrypto.core.crl.util.Crls;
import com.github.lsjunior.icrypto.core.net.JdkWebClient;
import com.github.lsjunior.icrypto.core.net.WebClient;
import com.github.lsjunior.icrypto.ext.icpbrasil.certificate.IcpBrasilHierarchyDownloader;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;

public class Main {

  private static final String APP_NAME = "Main";

  public static void main(String[] args) {
    Options options = new Options();
    options.addRequiredOption("a", "action", true, "action to execute");
    options.addRequiredOption("i", "input", true, "input file/dir");
    options.addRequiredOption("o", "output", true, "output file/dir");
    options.addOption("h", "help", false, "show help");

    CommandLineParser parser = new DefaultParser();
    try {
      Main.initHttps();

      CommandLine commandLine = parser.parse(options, args);
      if (commandLine.hasOption("a")) {
        String action = commandLine.getOptionValue("a");
        if ("ca-certs".equals(action)) {
          Main.doHandleCaCerts(args, parser, options);
        } else if ("ca-crls".equals(action)) {
          Main.doHandleCaCrls(args, parser, options);
        } else {
          Main.showHelpAndExit(options);
        }
      } else {
        Main.showHelpAndExit(options);
      }
    } catch (ParseException e) {
      System.err.println("Parsing failed.  Reason: " + e.getMessage());
      Main.showHelpAndExit(options);
    } catch (Exception e) {
      System.err.println("Runtime error.  Reason: " + e.getMessage());
      e.printStackTrace(System.err);
      System.exit(127);
    }
  }

  private static void doHandleCaCerts(String[] args, CommandLineParser parser, Options options) throws ParseException {
    CommandLine commandLine = parser.parse(options, args);
    if ((commandLine.hasOption("i")) && (commandLine.hasOption("o"))) {
      String input = commandLine.getOptionValue("i");
      String output = commandLine.getOptionValue("o");

      File inputFile = new File(input);
      if ((!inputFile.exists()) || (!inputFile.isFile())) {
        System.err.print("Invalid input file " + input);
        Main.showHelpAndExit(options);
      }

      File outputDir = new File(output);
      if ((!outputDir.exists()) || (!outputDir.isDirectory())) {
        System.err.print("Invalid output dir " + input);
        Main.showHelpAndExit(options);
      }

      List<Certificate> allCertificates = new ArrayList<>();

      try (Scanner scanner = new Scanner(inputFile)) {
        Pkcs7CertificateReader pkcs7CertificateReader = new Pkcs7CertificateReader();
        while (scanner.hasNextLine()) {
          String line = scanner.nextLine();
          List<Certificate> certificates = null;
          if (!Strings.isNullOrEmpty(line)) {
            if (line.startsWith("#")) {
              continue;
            }
            if (line.startsWith("P7B")) {
              byte[] bytes = Main.doGet(line.substring(4));
              certificates = pkcs7CertificateReader.read(new ByteArrayInputStream(bytes));
            } else if (line.startsWith("P7S")) {
              byte[] bytes = Main.doGet(line.substring(4));
              certificates = PemCertificateReader.getInstance().read(new ByteArrayInputStream(bytes));
            } else if (line.startsWith("PEM")) {
              try {
                byte[] bytes = Main.doGet(line.substring(4));
                Certificate certificate = Certificates.toCertificate(bytes);
                certificates = Collections.singletonList(certificate);
              } catch (Exception e) {
                System.err.println("Error: " + line + " " + e.getMessage());
              }
            } else if (line.startsWith("ZIP")) {
              byte[] bytes = Main.doGet(line.substring(4));
              Map<String, Certificate> map = IcpBrasilHierarchyDownloader.getCertificates(new ByteArrayInputStream(bytes));
              Collection<Certificate> collection = map.values();
              certificates = Lists.newArrayList(collection);
            } else {
              System.err.println("Invalid line" + line);
            }
          }
          if ((certificates != null) && (!certificates.isEmpty())) {
            allCertificates.addAll(certificates);
          }
        }
      } catch (IOException e) {
        // e.printStackTrace(System.err);
        System.err.print("Error: " + e.getMessage());
        System.exit(1);
      }

      if (!allCertificates.isEmpty()) {
        for (Certificate certificate : allCertificates) {
          X509Certificate x509Certificate = (X509Certificate) certificate;
          try {
            System.out.println(x509Certificate.getSubjectX500Principal());
            CertPath certPath = CertPaths.toCertPath(certificate, allCertificates);
            String opensslName = OpenSslCertificates.getOpenSslHash(x509Certificate.getSubjectX500Principal());
            String fileName = opensslName + "." + (certPath.getCertificates().size() - 1);
            File file = new File(outputDir, fileName);
            try (FileOutputStream outputStream = new FileOutputStream(file)) {
              PemCertificateWriter.getInstance().write(Collections.singletonList(certificate), outputStream);
            }
            System.out.println(x509Certificate.getSubjectX500Principal() + " => " + file.getAbsolutePath());
          } catch (Exception e) {
            System.err.println(x509Certificate.getSubjectX500Principal() + " Error: " + e.getMessage());
            // System.err.println(" " + x509Certificate.getIssuerX500Principal() + " Error: " + e.getMessage());
          }
        }
      }
    } else {
      Main.showHelpAndExit(options);
    }
  }

  private static void doHandleCaCrls(String[] args, CommandLineParser parser, Options options) throws ParseException {
    CommandLine commandLine = parser.parse(options, args);
    if ((commandLine.hasOption("i")) && (commandLine.hasOption("o"))) {
      String input = commandLine.getOptionValue("i");
      String output = commandLine.getOptionValue("o");

      File inputDir = new File(input);
      if ((!inputDir.exists()) || (!inputDir.isDirectory())) {
        System.err.print("Invalid input dir " + input);
        Main.showHelpAndExit(options);
      }

      File outputDir = new File(output);
      if ((!outputDir.exists()) || (!outputDir.isDirectory())) {
        System.err.print("Invalid output dir " + input);
        Main.showHelpAndExit(options);
      }

      for (File certFile : inputDir.listFiles()) {
        try (FileInputStream fileInputStream = new FileInputStream(certFile)) {
          Certificate certificate = Certificates.toCertificate(fileInputStream);
          CRL crl = Crls.getCrl(certificate);
          if (crl != null) {
            File crlFile = new File(outputDir, certFile.getName());
            try (FileOutputStream fileOutputStream = new FileOutputStream(crlFile)) {
              PemCrlWriter.getInstance().write(Collections.singletonList(crl), fileOutputStream);
              X509Certificate x509Certificate = (X509Certificate) certificate;
              System.out.println(x509Certificate.getSubjectX500Principal() + " => " + crlFile.getAbsolutePath());
            }
          }
        } catch (Exception e) {
          System.err.print("Error " + e.getMessage() + ", file " + certFile.getName());
        }
      }
    } else {
      Main.showHelpAndExit(options);
    }
  }

  private static byte[] doGet(final String url) throws IOException {
    WebClient webClient = new JdkWebClient();
    byte[] bytes = webClient.get(url);
    return bytes;
  }

  private static void showHelpAndExit(Options options) {
    HelpFormatter helpFormatter = new HelpFormatter();
    helpFormatter.printHelp(Main.APP_NAME, options);
    System.exit(1);
  }

  private static void initHttps() throws NoSuchAlgorithmException, KeyManagementException {
    TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
      @Override
      public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        return null;
      }

      @Override
      public void checkClientTrusted(X509Certificate[] certs, String authType) {
        //
      }

      @Override
      public void checkServerTrusted(X509Certificate[] certs, String authType) {
        //
      }
    }};

    SSLContext sc = SSLContext.getInstance("SSL");
    sc.init(null, trustAllCerts, new java.security.SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
  }

}
