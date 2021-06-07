import static java.lang.System.out;

import java.net.InetAddress;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.TimeZone;
import java.util.stream.Collectors;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class Main {

  public static void main(String[] args) throws Exception {

    out.println("<----- Processes ----->");
    var ps = ProcessHandle.allProcesses()
        .sorted(ProcessHandle::compareTo)
        .collect(Collectors.toList());
    ps.forEach(p -> {
      var pInfo = p.pid() + " : " + p.info();
      out.println(pInfo);
    });

    out.println("\n<----- Trust stores ----->");
    var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init((KeyStore) null);
    var issuers = Arrays.stream(tmf.getTrustManagers()).flatMap(tm -> {
      var x509Tm = (X509TrustManager) tm;
      return Arrays.stream(x509Tm.getAcceptedIssuers());
    }).collect(Collectors.toList());
    issuers.forEach(cert -> out.println(cert.getIssuerDN()));

    out.println("\n<----- Dns Resolution ----->");
    var dns = Arrays.stream(InetAddress.getAllByName("google.com")).collect(Collectors.toList());
    dns.forEach(out::println);

    out.println("\n<----- TimeZones ----->");
    var tz = Arrays.stream(TimeZone.getAvailableIDs()).collect(Collectors.toList());
    tz.forEach(out::println);

    out.println("\n<----- Charsets ----->");
    var cs = Charset.availableCharsets();
    cs.forEach((name, charSet) -> out.println(name + " : " + charSet));

    var stats = "\nProcesses      : " + ps.size() + "\n" +
        "Dns Addresses  : " + dns.size() + "\n" +
        "Trust Stores   : " + issuers.size() + "\n" +
        "TimeZones      : " + tz.size() + "\n" +
        "CharSets       : " + ps.size() + "\n";

    out.println(stats);
  }
}
