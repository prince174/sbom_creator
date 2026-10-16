// External build helper only: consume Maven's effective model, never resolve it.
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;
import org.w3c.dom.*;

public class ReactorCollect {
    static Element child(Element root, String name) {
        for (Node node = root.getFirstChild(); node != null; node = node.getNextSibling())
            if (node instanceof Element && name.equals(node.getLocalName())) return (Element) node;
        return null;
    }
    static String text(Element root, String name) {
        Element element = child(root, name);
        return element == null ? "" : element.getTextContent().trim();
    }
    static String token(String value) {
        if (!value.matches("[A-Za-z0-9_.+\\-]+")) throw new IllegalArgumentException("Unresolved Maven output token");
        return value;
    }
    public static void main(String[] args) throws Exception {
        Path module = Path.of(args[0]).toRealPath(), reference = Path.of(args[1]), output = Path.of(args[2]);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        Element root = factory.newDocumentBuilder().parse(reference.resolve("effective-pom.xml").toFile()).getDocumentElement();
        String group = token(text(root, "groupId")), name = token(text(root, "artifactId")), version = token(text(root, "version"));
        String packaging = text(root, "packaging"), sha = "", filename = "";
        if (packaging.isEmpty()) packaging = "jar";
        if (packaging.equals("jar")) {
            Element build = child(root, "build");
            Path directory = Path.of(text(build, "directory")).toRealPath();
            filename = token(text(build, "finalName")) + ".jar";
            Path artifact = directory.resolve(filename).toRealPath();
            if (!artifact.startsWith(module) || !Files.isRegularFile(artifact))
                throw new IllegalArgumentException("Artifact outside module or missing");
            Files.createDirectories(output);
            Files.copy(artifact, output.resolve(filename));
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (var stream = Files.newInputStream(artifact)) {
                byte[] buffer = new byte[1024 * 1024];
                for (int count; (count = stream.read(buffer)) != -1;) digest.update(buffer, 0, count);
            }
            sha = HexFormat.of().formatHex(digest.digest());
        } else if (!packaging.equals("pom")) throw new IllegalArgumentException("Unsupported packaging " + packaging);
        String json = String.format("{\"group\":\"%s\",\"artifact\":\"%s\",\"version\":\"%s\",\"packaging\":\"%s\",\"file\":\"%s\",\"sha256\":\"%s\"}\n",
            group, name, version, packaging, filename, sha);
        Files.writeString(reference.resolve("module.json"), json);
    }
}
