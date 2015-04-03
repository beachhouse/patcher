/*
 * JBoss, Home of Professional Open Source.
 * Copyright (c) 2015, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.beach.patcher;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;

/**
 * @author <a href="mailto:cdewolf@redhat.com">Carlo de Wolf</a>
 */
public class GeneratorMockup {
    private static final MessageDigest MESSAGE_DIGEST;

    static {
        try {
            MESSAGE_DIGEST = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] digest(final Path file) throws IOException {
        MESSAGE_DIGEST.reset();
        final byte[] buf = new byte[8192];
        final DigestInputStream in = new DigestInputStream(new BufferedInputStream(new FileInputStream(file.toFile())), MESSAGE_DIGEST);
        while (in.read(buf, 0, buf.length) != -1) {
            // do nothing
        }
        in.close();
        return MESSAGE_DIGEST.digest();
    }

    public static void main(final String[] args) throws IOException {
        final String propertiesFile = GeneratorMockup.class.getResource("/eap.properties").getFile();
        // TODO: Properties in an unordered map, should use an ordered one
        final Properties props = new Properties();
        props.load(new BufferedReader(new FileReader(propertiesFile)));
        final Map<PathMatcher, Consumer<Path>> defaultConsumers = new LinkedHashMap<>();
        for (Map.Entry<Object, Object> entry : props.entrySet()) {
            final String key = (String) entry.getKey();
            final String value = (String) entry.getValue();
            if (value.equals("ignore")) {
                defaultConsumers.put(FileSystems.getDefault().getPathMatcher("glob:" + key), new Consumer<Path>() {
                    @Override
                    public void accept(final Path path) {
                        // ignore
                    }
                });
            } else {
                throw new IllegalArgumentException("Unknown action '" + value + "' for pattern " + key);
            }
        }

        final String[] originals = { "jboss-eap-6.3.0/jboss-eap-6.3", "jboss-eap-6.3.1/jboss-eap-6.3", "jboss-eap-6.3.2/jboss-eap-6.3", "jboss-eap-6.3.3/jboss-eap-6.3", "jboss-eap-6.4.0.CR2/jboss-eap-6.4" };
        final String originalBase = "/home/carlo/patcher/install";

        final Map<Path, Set<byte[]>> verifiedDigests = new TreeMap<>();

        for (int i = 0; i < originals.length; i++) {
            final Path startingDir = Paths.get(originalBase, originals[i]);
            final Map<PathMatcher, Consumer<Path>> consumers = new LinkedHashMap<>();
            consumers.putAll(defaultConsumers);
            consumers.put(null, new Consumer<Path>() {
                @Override
                public void accept(final Path file) {
                    try {
                        final Path element = startingDir.relativize(file);
                        final byte[] digest = digest(file);
                        System.out.println(element + ": " + toHex(digest));
                        Set<byte[]> digests = verifiedDigests.get(element);
                        if (digests == null) {
                            digests = new HashSet<byte[]>();
                            verifiedDigests.put(element, digests);
                        }
                        digests.add(digest);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            });
            Files.walkFileTree(startingDir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(final Path file, final BasicFileAttributes attrs) throws IOException {
                    final Path element = startingDir.relativize(file);
                    for (Map.Entry<PathMatcher, Consumer<Path>> entry : consumers.entrySet()) {
                        final PathMatcher key = entry.getKey();
                        if (key == null || key.matches(element)) {
                            entry.getValue().accept(file);
                            break;
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        }
        System.out.println(verifiedDigests.size());
        for (byte[] d : verifiedDigests.get(Paths.get("version.txt"))) {
            System.out.println(toHex(d));
        }

        final Path targetBuildFile = Paths.get("/tmp/build.xml");
        final PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(targetBuildFile.toFile())));

        out.println("<project xmlns:unless=\"ant:unless\"\n" +
                "         name=\"patcher\" default=\"verify\">");
        out.println("   <patternset id=\"verified-files\">");
        for (Map.Entry<Path, Set<byte[]>> entry : verifiedDigests.entrySet()) {
            final Path path = entry.getKey();
            out.println("       <include name=\"" + path + "\"/>");
        }
        out.println("   </patternset>\n");
        final StringBuilder verifyDependencies = new StringBuilder();
        for (Map.Entry<Path, Set<byte[]>> entry : verifiedDigests.entrySet()) {
            final Path path = entry.getKey();
            final String targetName = "verify-" + path.toString().replace(',', '_');
            out.println(
                    "    <target name=\"" + targetName + "\">\n" +
                    "        <local name=\"verified\"/>\n" +
                    "        <condition property=\"verified\" else=\"false\">\n" +
                    "            <or>\n" +
                    "                <not>\n" +
                    "                    <available file=\"${dist}/" + path + "\"/>\n" +
                    "                </not>");
            for (byte[] d : entry.getValue()) {
                out.println(
                        "                <checksum file=\"${dist}/" + path + "\" property=\"" + toHex(d) + "\"/>");
            };
            out.println(
                    "            </or>\n" +
                    "        </condition>\n" +
                    "        <echo unless:true=\"${verified}\" message=\"'" + path + "' verification failed\"/>\n" +
                    "        <condition property=\"verification-failed\">\n" +
                    "            <isfalse value=\"${verified}\"/>\n" +
                    "        </condition>\n" +
                    "    </target>\n"
            );
            if (verifyDependencies.length() > 0)
                verifyDependencies.append(", ");
            verifyDependencies.append(targetName);
        }
        out.println(
                "   <target name=\"verify\" depends=\"" + verifyDependencies + "\">\n" +
                "       <fail if=\"verification-failed\" message=\"Verification failed\"/>\n" +
                "   </target>\n"
        );

        final String target = originals[originals.length - 1];

        // TODO: install target must be further worked out. It must not depend on verify, but rather an 'empty' target directory
        //  'empty' meaning not containing any verified files

        // overwrite must be true, because the installation could be newer than the released files.
        out.println(
                "   <target name=\"install\" depends=\"verify\">\n" +
                "      <property name=\"src\" value=\".\"/>\n" +
                "      <copy todir=\"${dist}\" overwrite=\"true\">\n" +
                "           <fileset dir=\"${src}\">\n" +
                "               <present targetdir=\"${dist}\" present=\"srconly\" />\n" +
                "           </fileset>\n" +
                "      </copy>\n" +
                "   </target>\n"
        );

        out.println(
                "   <target name=\"uninstall\" depends=\"verify\">\n" +
                "      <delete>\n" +
                "         <fileset dir=\"${dist}\">\n" +
                "            <patternset refid=\"verified-files\"/>\n" +
                "         </fileset>\n" +
                "      </delete>\n" +
                "      <delete includeemptydirs=\"true\">\n" +
                "         <fileset dir=\"${dist}\">\n" +
                "            <and>\n" +
                "               <size value=\"0\"/>\n" +
                "               <type type=\"dir\"/>\n" +
                "            </and>\n" +
                "         </fileset>\n" +
                "      </delete>\n" +
                "   </target>\n"
        );

        out.println("</project>");

        out.flush();
        out.close();
    }

    private static String toHex(final byte b) {
        final String s = Integer.toHexString(0xFF & b);
        if (s.length() < 2)
            return "0" + s;
        return s;
    }

    private static String toHex(final byte[] a) {
        final StringBuffer sb = new StringBuffer();
        for (int i = 0; i < a.length; i++)
            sb.append(toHex(a[i]));
        return sb.toString();
    }
}
