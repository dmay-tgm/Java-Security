#DEZSYS-L02 "Java Security"
##1 Einführung
Diese Übung zeigt die Anwendung von Verschlüsselung in Java.

###1.1 Ziele

Das Ziel dieser Übung ist die symmetrische und asymmetrische Verschlüsselung in Java umzusetzen. Dabei soll ein Service mit einem Client einen sicheren Kommunikationskanal aufbauen und im Anschluss verschlüsselte Nachrichten austauschen. Ebenso soll die Verwendung eines Namensdienstes zum Speichern von Informationen (hier PublicKey) verwendet werden.

Die Kommunikation zwischen Client und Service soll mit Hilfe einer Übertragungsmethode (IPC, RPC, Java RMI, JMS, etc) aus dem letzten umgesetzt werden.

###1.2 Voraussetzungen

+ Grundlagen Verzeichnisdienst
+ Administration eines LDAP Dienstes
+ Grundlagen der JNDI API für eine JAVA Implementierung
+ Grundlagen Verschlüsselung (symmetrisch, asymmetrisch)
+ Einführung in Java Security JCA (Cipher, KeyPairGenerator, KeyFactory)
+ Kommunikation in Java (IPC, RPC, Java RMI, JMS)
+ Verwendung einer virtuellen Instanz für den Betrieb des Verzeichnisdienstes

###1.3 Aufgabenstellung

Mit Hilfe der zur Verfügung gestellten VM wird ein vorkonfiguriertes LDAP Service zur Verfügung gestellt. Dieser Verzeichnisdienst soll verwendet werden, um den PublicKey von einem Service zu veröffentlichen. Der PublicKey wird beim Start des Services erzeugt und im LDAP Verzeichnis abgespeichert. Wenn der Client das Service nutzen will, so muss zunächst der PublicKey des Services aus dem Verzeichnis gelesen werden. Dieser PublicKey wird dazu verwendet, um den symmetrischen Schlüssel des Clients zu verschlüsseln und im Anschluss an das Service zu senden.

Das Service empfängt den verschlüsselten symmetrischen Schlüssel und entschlüsselt diesen mit dem PrivateKey. Nun kann eine Nachricht verschlüsselt mit dem symmetrischen Schlüssel vom Service zum Client gesendet werden.

Der Client empfängt die verschlüsselte Nachricht und entschlüsselt diese mit dem symmetrischen Schlüssel. Die Nachricht wird zuletzt zur Kontrolle ausgegeben.

*Gruppengröße*: 1 Person

*Bewertung*: 16 Punkte
- asymmetrische Verschlüsselung (4 Punkte)
- symmetrische Verschlüsselung (4 Punkte)
- Kommunikation in Java (3 Punkte)
- Verwendung eines Naming Service, JNDI (3 Punkte)
- Protokoll (2 Punkte)

*Links*:
- Java Security Overview:
     https://docs.oracle.com/javase/8/docs/technotes/guides/security/overview/jsoverview.html
- Security Architecture:
     https://docs.oracle.com/javase/8/docs/technotes/guides/security/spec/security-spec.doc.html
- Java Cryptography Architecture (JCA) Reference Guide:
     https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html
 
Read the Java Security Documentation and focus on following Classes: KeyPairGenerator, SecureRandom, KeyFactory, X509EncodedKeySpec, Cipher 
