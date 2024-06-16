package es.chiteroman.playintegrityfix;

import org.bouncycastle.asn1.x500.X500Name;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.LinkedList;

public record Keybox(KeyPair keypair, PrivateKey privateKey,
                     LinkedList<Certificate> certificateChain,
                     LinkedList<X500Name> certificateChainSubject) {

}
