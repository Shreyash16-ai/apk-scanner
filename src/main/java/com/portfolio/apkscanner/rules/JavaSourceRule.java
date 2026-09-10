package com.portfolio.apkscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.portfolio.apkscanner.model.Finding;

import java.nio.file.Path;
import java.util.List;

/**
 * Contract for a detector that operates on a parsed Java source file (AST).
 *
 * Design note: each rule gets the FULL CompilationUnit rather than being
 * handed pre-extracted nodes. This keeps rules self-contained (they declare
 * their own visitor logic) at the cost of each rule doing its own tree walk.
 * For a portfolio-scale scanner (dozens of files, not millions) this is the
 * right tradeoff — a single shared visitor dispatching to N rule callbacks
 * would be more "efficient" but adds indirection that makes each rule harder
 * to read and defend individually in an interview.
 */
public interface JavaSourceRule {

    /** Stable machine-readable id, e.g. "HARDCODED_SECRET". Used in reports and for suppression. */
    String getId();

    /** Human-readable name shown in reports. */
    String getName();

    /**
     * Run this rule against one parsed file and return any findings.
     * @param cu the parsed AST for the file
     * @param filePath the path to the source file, for reporting
     */
    List<Finding> apply(CompilationUnit cu, Path filePath);
}
