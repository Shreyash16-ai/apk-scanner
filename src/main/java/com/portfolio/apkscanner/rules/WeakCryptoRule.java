package com.portfolio.apkscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.portfolio.apkscanner.model.Finding;
import com.portfolio.apkscanner.model.Severity;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Detects weak/misused cryptography: ECB mode, MD5/SHA-1 for security
 * purposes, and hardcoded IVs.
 *
 * SECURITY REASONING (for interview defense):
 *
 * - ECB MODE: encrypts each fixed-size block independently, so identical
 *   plaintext blocks produce identical ciphertext blocks. This leaks
 *   structure (the canonical demo: ECB-encrypting an image of a penguin
 *   still shows the penguin outline). There is no legitimate use case for
 *   ECB in application code — the fix is always CBC/GCM with a random IV,
 *   which is why we flag this HIGH regardless of context.
 *
 * - MD5 / SHA-1 "FOR SECURITY PURPOSES": both are cryptographically broken
 *   for collision resistance (practical collisions demonstrated for both).
 *   The important nuance — and something worth saying explicitly in an
 *   interview — is that MD5/SHA-1 are NOT always vulnerabilities: using
 *   MD5 as a checksum for cache-key generation or de-duplication is fine,
 *   because there's no adversary trying to forge a collision in that
 *   context. This rule can't fully distinguish "security use" from
 *   "checksum use" via syntax alone (that's a semantic/intent question),
 *   so it flags MessageDigest.getInstance("MD5"/"SHA-1") at MEDIUM and
 *   documents this ambiguity explicitly in the finding text, rather than
 *   overclaiming certainty MobSF-style tools often gloss over too.
 *
 * - HARDCODED IV: an IV's job is to ensure that encrypting the same
 *   plaintext twice (even with the same key) produces different
 *   ciphertext. A hardcoded/static IV defeats this — with CBC mode in
 *   particular, a fixed IV plus a fixed key leaks whether two ciphertexts'
 *   first blocks came from identical plaintext, and under some usage
 *   patterns enables chosen-plaintext attacks. IVs must be freshly random
 *   (or a nonce, for GCM) per encryption operation, never a literal.
 *
 * DETECTION STRATEGY: visit MethodCallExpr nodes and match on
 * (receiver-type-ish method name, string-literal argument), which is where
 * JCE (Java Cryptography Extension) algorithm selection happens. Separately,
 * visit "new IvParameterSpec(...)" constructor calls and check whether the
 * argument traces back to a literal byte array — a cheap, syntax-level proxy
 * for "not runtime-random", which is the practical limit of what an
 * AST-only (no data-flow) scanner can claim; documented as a known
 * limitation rather than silently over-claiming.
 */
public class WeakCryptoRule implements JavaSourceRule {

    @Override
    public String getId() { return "WEAK_CRYPTO"; }

    @Override
    public String getName() { return "Weak Cryptography Usage"; }

    @Override
    public List<Finding> apply(CompilationUnit cu, Path filePath) {
        List<Finding> findings = new ArrayList<>();

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr call, Void arg) {
                super.visit(call, arg);

                if (isCall(call, "getInstance") && !call.getArguments().isEmpty()) {
                    call.getArgument(0).toStringLiteralExpr().ifPresent(argLit -> {
                        String alg = argLit.asString();
                        String algUpper = alg.toUpperCase(Locale.ROOT);
                        int line = call.getRange().map(r -> r.begin.line).orElse(-1);

                        if (algUpper.contains("ECB")) {
                            findings.add(new Finding(
                                    getId(), "ECB Cipher Mode", Severity.HIGH, "CWE-327",
                                    filePath.toString(), line,
                                    truncate(call.toString()),
                                    "Cipher.getInstance(\"" + alg + "\") uses ECB mode, which encrypts " +
                                            "identical plaintext blocks to identical ciphertext blocks, " +
                                            "leaking structural patterns in the plaintext. There is no " +
                                            "correct use of ECB for general-purpose encryption.",
                                    "Use AES/GCM/NoPadding (preferred, provides authentication) or " +
                                            "AES/CBC/PKCS5Padding with a securely random per-message IV."
                            ));
                        } else if (algUpper.equals("MD5") || algUpper.equals("SHA-1") || algUpper.equals("SHA1")) {
                            findings.add(new Finding(
                                    getId(), "Weak Hash Algorithm (" + alg + ")", Severity.MEDIUM, "CWE-327",
                                    filePath.toString(), line,
                                    truncate(call.toString()),
                                    "MessageDigest.getInstance(\"" + alg + "\") is cryptographically broken " +
                                            "for collision resistance. NOTE: this is only a real vulnerability " +
                                            "if the hash is used in a security context (password hashing, " +
                                            "integrity/signature verification, token generation) — MD5/SHA-1 " +
                                            "used purely as a non-adversarial checksum (e.g. cache keys) is not " +
                                            "a security issue. This scanner flags at MEDIUM and defers the " +
                                            "final call to manual review since usage intent isn't always " +
                                            "syntactically determinable.",
                                    "For password hashing use bcrypt/scrypt/Argon2 (via a library, since " +
                                            "the JDK doesn't ship these). For integrity/signatures use SHA-256 " +
                                            "or better."
                            ));
                        } else if (algUpper.startsWith("DES") || algUpper.equals("RC4")) {
                            findings.add(new Finding(
                                    getId(), "Deprecated Cipher Algorithm (" + alg + ")", Severity.HIGH, "CWE-327",
                                    filePath.toString(), line,
                                    truncate(call.toString()),
                                    "\"" + alg + "\" is a deprecated/weak cipher (DES's 56-bit key is " +
                                            "brute-forceable; RC4 has known keystream biases).",
                                    "Use AES-256/GCM."
                            ));
                        }
                    });
                }
            }

            @Override
            public void visit(ObjectCreationExpr oce, Void arg) {
                super.visit(oce, arg);
                String typeName = oce.getType().getNameAsString();
                if (typeName.equals("IvParameterSpec") && !oce.getArguments().isEmpty()) {
                    Expression firstArg = oce.getArgument(0);
                    if (referencesLiteralByteArray(firstArg, cu)) {
                        int line = oce.getRange().map(r -> r.begin.line).orElse(-1);
                        findings.add(new Finding(
                                getId(), "Hardcoded IV", Severity.HIGH, "CWE-329",
                                filePath.toString(), line,
                                truncate(oce.toString()),
                                "This IvParameterSpec appears to be constructed from a literal byte array " +
                                        "rather than a freshly-generated random value. A static IV means " +
                                        "encrypting the same plaintext with the same key always produces the " +
                                        "same ciphertext, defeating the purpose of the IV and enabling pattern " +
                                        "analysis / chosen-plaintext style attacks against CBC mode.",
                                "Generate the IV randomly per encryption: byte[] iv = new byte[16]; " +
                                        "new SecureRandom().nextBytes(iv); and transmit/store the IV " +
                                        "alongside the ciphertext (IVs are not secret, just non-reused)."
                        ));
                    }
                }
            }
        }, null);

        return findings;
    }

    /**
     * Cheap syntax-level check: is this expression (a) directly an array
     * initializer literal, e.g. {0x00, 0x01, ...}, or (b) a simple name that
     * resolves within THIS file to a field/local initialized with one?
     * We deliberately do NOT attempt cross-file/cross-method data flow here —
     * that's out of scope for an AST-only scanner (see project scope notes).
     */
    private boolean referencesLiteralByteArray(Expression expr, CompilationUnit cu) {
        if (expr instanceof ArrayInitializerExpr) {
            return true;
        }
        // e.g. new IvParameterSpec(IV_BYTES) where IV_BYTES is a local/field
        // initialized with a literal array — simple same-file lookup only.
        String name = expr.toString();
        final boolean[] found = {false};
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(com.github.javaparser.ast.body.VariableDeclarator vd, Void arg) {
                super.visit(vd, arg);
                if (vd.getNameAsString().equals(name)) {
                    vd.getInitializer().ifPresent(init -> {
                        if (init instanceof ArrayInitializerExpr) found[0] = true;
                    });
                }
            }
        }, null);
        return found[0];
    }

    private boolean isCall(MethodCallExpr call, String methodName) {
        return call.getNameAsString().equals(methodName);
    }

    private static String truncate(String s) {
        s = s.replaceAll("\\s+", " ").trim();
        return s.length() > 140 ? s.substring(0, 137) + "..." : s;
    }
}
