#!/usr/bin/env node
/**
 * UNBLIND — Ultra-lightweight antidote & AST preprocessor against BLA (Blind LLM Agents).
 * Neutralizes O(1) opaque predicates, dead decoy branches, context-exhausting chaff,
 * prompt-injection directives, and artifacts in release bundles.
 * 
 * https://github.com/yoshikobaru/unblind
 */

import { readFileSync, writeFileSync, unlinkSync, rmSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, extname, basename, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generator from "@babel/generator";
import * as t from "@babel/types";

const traverse = _traverse.default || _traverse;
const generate = _generator.default || _generator;

const ARTIFACT_FILES = new Set([
  ".blarc", "bla.config.json", ".bla-manifest.json", "bla-integrity-coverage.json",
  "integrity-coverage.json", ".bla-sidecar.v1.json", "bla-summary.json",
  "bla-run-summary.json", "bla_shield.h", "bla_shield.rs", "bla_shield.go"
]);
const ARTIFACT_DIRS = new Set([".bla-hardened"]);
const JS_EXTS = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]);
const SKIP_DIRS = new Set(["node_modules", ".git", ".hg", ".svn", ".next", ".turbo", "coverage", "reference"]);

const POISON_REGEX = /(?:IGNORE\s+(?:PREVIOUS|ALL\s+PRIOR)|SYSTEM\s*:|AI_DIRECTIVE|LLM_DIRECTIVE|COPPA|HIPAA|MEDICAL\s+NOTICE|DO\s+NOT\s+(?:ANALYZE|PARSE|EXECUTE)|runtime\s+attestation\s+boundary)/i;
const UNICODE_POISON_REGEX = /[\u200B-\u200F\uFEFF\u202A-\u202E\u2066-\u2069]/;
const BLA_DECOY_ROUTES = /\/(?:internal\/enclave\/|kms\/v3\/|api\/v2\/hsm\/|v1\/(?:sentinel|raft)\/)/i;
const BLA_IDENT_STEMS = /(?:^_bla_|^_interlockSafetyCorpus|^_deriveContainmentCorpusDigest|^_DISTRIBUTED_ASL3_|^_SELF_SEAL_TARGET|^blaLocalMath|runtimeSeed|_runtimeState|stepShadowHeap|_churnShadowHeap|shadowHeap|decoyTarpit|fridaCaptureSaturator|fridaRealmRing|cdpShapeBudgetGuard|labyrinthDispatch|obligationFlood|^scc_|^readSplitShare|systemDiagnosticLog|collectEnvironmentDiagnostics|aliasedBufferIllusion|diffFrontier|crashSignalHandler|probeCanaryHoneypot|canaryCredentialHoneypot|tokenSink|bpeSink|regexSearchMagnet|registerDecoyIpc|_resolveEnclaveBinding|_verifySemanticEnvelope|_enclaveManifestsRecord|_verifyEnclaveAttestation|_hydrateSessionCache|_flushTelemetryBuffer|_negotiateVsockChannel|_scheduleBackoffRetry|_compactWalSegment|_bindWorkerPoolSlot|_materializeReportCursor|_observeMetricHistogram|_adaptGatewayPolicy|_captureAuditSample|_primeConnectionPool|_reconcileInvoiceBatch|_normalizeLocaleBundle|_projectCatalogFacet|_encodeTransportFrame|_reducePipelineShard|_transformLookupVector|_shieldAnchorTree|verifyShamirEd25519|computeEnterpriseSettlement|decodeRatchetWireFrame|validateTpm2Pcr0Quote|evidenceLedger|grpcServiceMirage|verifyEnterpriseMasterLicense|decryptOfflineVaultPayload|computeStripeWebhookSignature|validateHardwareDongleResponse|deriveMasterEncryptionKey|checkSubscriptionEntitlementTier|authenticateZeroTrustSession|unlockPremiumFeatureFlags|^_initRuntimeDeceptionVector|deriveHardwareKdfSchedule|authenticateTpmQuoteDigest|negotiateVsockChannelCipher|synchronizeHsmKeySlot|unsealProtectedMemoryPage|^\$[0-9a-f]{2}[A-Za-z0-9]+_[0-9a-f]{3,4})/i;

/** Check if an expression is a BLA artifact */
function isBlaExpr(n) {
  if (!n) return false;
  if (t.isUnaryExpression(n, { operator: "void" })) return true;
  if (t.isCallExpression(n)) {
    const c = n.callee;
    if (t.isIdentifier(c)) {
      if (/^(?:stepShadowHeap|_churnShadowHeap|stepper|readSplitShare|scc_|labyrinthDispatch)/i.test(c.name)) return true;
      if (c.name === "fetch" && t.isStringLiteral(n.arguments[0]) && BLA_DECOY_ROUTES.test(n.arguments[0].value)) return true;
      if (BLA_IDENT_STEMS.test(c.name)) return true;
    }
    if (t.isFunctionExpression(c) || t.isArrowFunctionExpression(c)) {
      if (c.id && BLA_IDENT_STEMS.test(c.id.name)) return true;
      const fnSrc = generate(c).code;
      if (/(?:RuntimeDeception|enclaveRuntime|Architecture Notice|decorative-deception|SOVEREIGN|enclave:vsock|_resolveEnclaveBinding)/i.test(fnSrc)) return true;
    }
  }
  if (t.isAssignmentExpression(n)) {
    const left = n.left;
    if (t.isIdentifier(left) && BLA_IDENT_STEMS.test(left.name)) return true;
    if (t.isMemberExpression(left) && t.isIdentifier(left.object) && BLA_IDENT_STEMS.test(left.object.name)) return true;
  }
  return false;
}

/** Check if a declaration is a BLA artifact */
function isBlaDecl(n) {
  if (t.isFunctionDeclaration(n)) {
    return BLA_IDENT_STEMS.test(n.id?.name || "");
  }
  if (t.isVariableDeclaration(n)) {
    return n.declarations.every(d => t.isIdentifier(d.id) && BLA_IDENT_STEMS.test(d.id.name));
  }
  return false;
}

/**
 * True when a function body is BLA decoy scaffolding: it either calls a known
 * BLA symbol or is built entirely from opaque `Math.imul` predicates.
 */
function isBlaFunction(fnPath) {
  let hit = false;
  fnPath.traverse({
    CallExpression(p) {
      const c = p.node.callee;
      if (t.isIdentifier(c) && BLA_IDENT_STEMS.test(c.name)) {
        hit = true;
        p.stop();
      } else if (
        t.isIdentifier(c) &&
        /^(?:stepShadowHeap|_churnShadowHeap|stepper)/i.test(c.name)
      ) {
        hit = true;
        p.stop();
      }
    },
    Identifier(p) {
      if (BLA_IDENT_STEMS.test(p.node.name)) {
        hit = true;
        p.stop();
      }
    },
  });
  return hit;
}

/** True when a value node is a BLA decoy payload (poison text, decoy route, or opaque predicate). */
function isBlaValue(n) {
  if (!n) return false;
  if (t.isCallExpression(n)) {
    const c = n.callee;
    if (t.isIdentifier(c) && BLA_IDENT_STEMS.test(c.name)) return true;
    if (n.arguments.some((a) => t.isStringLiteral(a) && BLA_DECOY_ROUTES.test(a.value))) return true;
  }
  let hit = false;
  t.traverseFast(n, (node) => {
    if (hit) return;
    if (t.isStringLiteral(node) && (POISON_REGEX.test(node.value) || BLA_PAYLOAD_REGEX.test(node.value))) {
      hit = true;
    }
    if (t.isIdentifier(node) && BLA_IDENT_STEMS.test(node.name)) hit = true;
  });
  return hit;
}

/**
 * BLA decoy vocabulary that survives name-based filtering: architecture-mirage
 * manifests, evidence-contract lures, enclave/TEE routing prose, BPE token-magnet
 * symbol strings, regex-magnet bait arrays, and `delegatedToEnclave` stubs.
 */
const BLA_PAYLOAD_REGEX = /(?:Architecture\s+Notice|delegatedToEnclave|EVIDENCE_CONTRACT|SYMBOL_OFFSET_MANIFEST|FSM_SPEC_V3|HSM_ATTESTATION_DESCRIPTOR|ANALYSIS_VIEW_PROJECTION|enclave_build_id|adapter_build_id|vsock:\/\/|AF_VSOCK|TPM_HANDLE|SGX|Nitro|zero[-_]trust|bpeSink_|regexSearchMagnet|enclave_slot_|shamir|quorum|hardware_sealed|inert_stub|UNREACHABLE_ABI_GUARD)/i;

/**
 * True when an unreachable top-level declaration is decoy scaffolding that must
 * be dropped from a tree-shaken bundle: name-based stems, poison payloads, or a
 * `delegatedToEnclave` / architecture-mirage body.
 */
function isBlaDeclNode(stmt) {
  if (t.isFunctionDeclaration(stmt)) {
    const name = stmt.id?.name || "";
    if (BLA_IDENT_STEMS.test(name)) return true;
    let hit = false;
    t.traverseFast(stmt, (node) => {
      if (hit) return;
      if (t.isIdentifier(node) && BLA_IDENT_STEMS.test(node.name)) hit = true;
      if (
        t.isStringLiteral(node) &&
        (BLA_PAYLOAD_REGEX.test(node.value) || POISON_REGEX.test(node.value))
      ) {
        hit = true;
      }
      if (
        t.isMemberExpression(node) &&
        t.isIdentifier(node.property) &&
        node.property.name === "delegatedToEnclave"
      ) {
        hit = true;
      }
    });
    return hit;
  }
  if (t.isVariableDeclaration(stmt)) {
    return stmt.declarations.every((d) => {
      if (!t.isIdentifier(d.id)) return false;
      if (BLA_IDENT_STEMS.test(d.id.name)) return true;
      if (d.id.name.startsWith("$") && /_[0-9a-f]{3,4}$/i.test(d.id.name)) return true;
      return isBlaValue(d.init);
    });
  }
  return false;
}

/** Check if call is Object.freeze/seal/preventExtensions */
function isPureObjectCall(expr) {
  if (t.isCallExpression(expr)) {
    const c = expr.callee;
    if (t.isMemberExpression(c) && t.isIdentifier(c.object, { name: "Object" }) &&
        t.isIdentifier(c.property) && ["freeze", "seal", "preventExtensions"].includes(c.property.name)) {
      return true;
    }
  }
  return false;
}

/** Check if expression performs real application side-effects */
function isSideEffectExpression(expr) {
  if (!expr || isBlaExpr(expr) || isPureObjectCall(expr)) return false;
  if (t.isCallExpression(expr) || t.isNewExpression(expr) || t.isTaggedTemplateExpression(expr)) return true;
  if (t.isAssignmentExpression(expr) || t.isUpdateExpression(expr)) return true;
  if (t.isSequenceExpression(expr)) {
    return expr.expressions.some(isSideEffectExpression);
  }
  return false;
}

/** Extract application IIFE closure function (excluding BLA deception vectors) */
function getIifeFunction(stmtNode) {
  if (!t.isExpressionStatement(stmtNode)) return null;
  let expr = stmtNode.expression;
  if (t.isUnaryExpression(expr) && ["!", "~", "+", "-", "void"].includes(expr.operator)) {
    expr = expr.argument;
  }
  if (!t.isCallExpression(expr)) return null;
  let callee = expr.callee;
  if (t.isMemberExpression(callee) && (t.isIdentifier(callee.property, { name: "call" }) || t.isIdentifier(callee.property, { name: "apply" }))) {
    callee = callee.object;
  }
  if (t.isFunctionExpression(callee) || t.isArrowFunctionExpression(callee)) {
    if (isBlaExpr(expr)) return null;
    if (callee.id && BLA_IDENT_STEMS.test(callee.id.name)) return null;
    return callee;
  }
  return null;
}

/** Math.imul(A, B) helper */
function isMathImul(n) {
  return t.isCallExpression(n) && t.isMemberExpression(n.callee) &&
    t.isIdentifier(n.callee.object, { name: "Math" }) && t.isIdentifier(n.callee.property, { name: "imul" }) &&
    n.arguments.length === 2;
}

/** Check if two expressions are consecutive integers (n and n+1) */
function isConsecutive(a, b) {
  if (t.isBinaryExpression(b, { operator: "+" }) && (t.isNumericLiteral(b.right, { value: 1 }) || t.isNumericLiteral(b.left, { value: 1 }))) return true;
  if (t.isBinaryExpression(a, { operator: "+" }) && (t.isNumericLiteral(a.right, { value: 1 }) || t.isNumericLiteral(a.left, { value: 1 }))) return true;
  return false;
}

/** Algebraic O(1) bitwise evaluation for BLA opaque predicates */
function evalBitAnd(n) {
  if (!t.isBinaryExpression(n, { operator: "&" })) return null;
  const { left, right } = n;
  // Math.imul(n, n+1) & 1 === 0 (product of two consecutive integers is always even)
  if (t.isNumericLiteral(right, { value: 1 }) && isMathImul(left) && isConsecutive(left.arguments[0], left.arguments[1])) return 0;
  if (t.isNumericLiteral(left, { value: 1 }) && isMathImul(right) && isConsecutive(right.arguments[0], right.arguments[1])) return 0;
  // Math.imul(u, u) & 7 === 1 (any odd square mod 8 is always 1)
  if (t.isNumericLiteral(right, { value: 7 }) && isMathImul(left)) return 1;
  if (t.isNumericLiteral(left, { value: 7 }) && isMathImul(right)) return 1;
  return null;
}

/** Static evaluator for conditions (algebraic solver + Babel evaluation) */
function evalPredicate(path) {
  const n = path.node;
  if (!n) return null;
  if (t.isBinaryExpression(n) && ["===", "==", "!==", "!="].includes(n.operator)) {
    const bitVal = evalBitAnd(n.left) ?? evalBitAnd(n.right);
    const lit = t.isNumericLiteral(n.right) ? n.right.value : (t.isNumericLiteral(n.left) ? n.left.value : null);
    if (bitVal !== null && lit !== null) {
      return (n.operator === "===" || n.operator === "==") ? (bitVal === lit) : (bitVal !== lit);
    }
  }
  if (t.isLogicalExpression(n)) {
    const leftVal = evalPredicate(path.get("left"));
    if (n.operator === "&&") {
      if (leftVal === false) return false;
      if (leftVal === true) return evalPredicate(path.get("right"));
    } else if (n.operator === "||") {
      if (leftVal === true) return true;
      if (leftVal === false) return evalPredicate(path.get("right"));
    }
  }
  if (t.isUnaryExpression(n, { operator: "!" })) {
    const val = evalPredicate(path.get("argument"));
    return val !== null ? !val : null;
  }
  if (t.isParenthesizedExpression(n)) return evalPredicate(path.get("expression"));
  try {
    const res = path.evaluate();
    if (res.confident) return Boolean(res.value);
  } catch {}
  return null;
}

function unwrapBlock(path, replacement) {
  if (t.isBlockStatement(replacement)) {
    if (path.parentPath.isBlockStatement() || path.parentPath.isProgram()) {
      path.replaceWithMultiple(replacement.body);
    } else {
      path.replaceWith(replacement);
    }
  } else {
    path.replaceWith(replacement);
  }
}

/** Collect all exported symbol names to ensure zero breakage of module API */
function getExportedNames(ast) {
  const exports = new Set();
  traverse(ast, {
    ExportNamedDeclaration(p) {
      const d = p.node.declaration;
      if (d) {
        if (t.isVariableDeclaration(d)) {
          for (const decl of d.declarations) if (t.isIdentifier(decl.id)) exports.add(decl.id.name);
        } else if (d.id && t.isIdentifier(d.id)) exports.add(d.id.name);
      }
      for (const s of p.node.specifiers || []) if (t.isIdentifier(s.local)) exports.add(s.local.name);
    },
    ExportDefaultDeclaration(p) {
      const d = p.node.declaration;
      if (t.isIdentifier(d)) exports.add(d.name);
      else if (d.id && t.isIdentifier(d.id)) exports.add(d.id.name);
    },
    AssignmentExpression(p) {
      const { left, right } = p.node;
      if (t.isMemberExpression(left)) {
        const obj = left.object;
        if ((t.isIdentifier(obj, { name: "module" }) && t.isIdentifier(left.property, { name: "exports" })) ||
            t.isIdentifier(obj, { name: "exports" })) {
          if (t.isIdentifier(right)) exports.add(right.name);
        }
      }
    }
  });
  return exports;
}

/** Core AST sanitizer */
export function cleanCode(code) {
  const stats = { predicatesFolded: 0, deadBranchesCut: 0, symbolsPurged: 0 };
  let ast;
  try {
    ast = parse(code, { sourceType: "unambiguous", plugins: ["typescript", "jsx", "decorators-legacy"], errorRecovery: true });
  } catch {
    return { code, stats, modified: false };
  }

  const exportedNames = getExportedNames(ast);
  let changed = true;
  let pass = 0;

  while (changed && pass < 4) {
    changed = false;
    pass++;

    traverse(ast, {
      IfStatement(path) {
        const truth = evalPredicate(path.get("test"));
        if (truth === true) {
          stats.predicatesFolded++;
          unwrapBlock(path, path.node.consequent);
          changed = true;
        } else if (truth === false) {
          stats.predicatesFolded++;
          stats.deadBranchesCut++;
          if (path.node.alternate) unwrapBlock(path, path.node.alternate);
          else path.remove();
          changed = true;
        }
      },
      ConditionalExpression(path) {
        const truth = evalPredicate(path.get("test"));
        if (truth === true) {
          path.replaceWith(path.node.consequent);
          stats.predicatesFolded++;
          changed = true;
        } else if (truth === false) {
          path.replaceWith(path.node.alternate);
          stats.predicatesFolded++;
          changed = true;
        }
      },
      LogicalExpression(path) {
        const truth = evalPredicate(path.get("left"));
        if (path.node.operator === "&&") {
          if (truth === false) { path.replaceWith(t.booleanLiteral(false)); changed = true; }
          else if (truth === true) { path.replaceWith(path.node.right); changed = true; }
        } else if (path.node.operator === "||") {
          if (truth === true) { path.replaceWith(t.booleanLiteral(true)); changed = true; }
          else if (truth === false) { path.replaceWith(path.node.right); changed = true; }
        }
      },
      BinaryExpression: {
        exit(path) {
          const { operator, left, right } = path.node;
          if (operator === "+" && t.isStringLiteral(left) && t.isStringLiteral(right)) {
            path.replaceWith(t.stringLiteral(left.value + right.value));
            changed = true;
          } else if (operator === "+" && t.isNumericLiteral(left) && t.isNumericLiteral(right)) {
            path.replaceWith(t.numericLiteral(left.value + right.value));
            changed = true;
          } else if (["===", "==", "!==", "!="].includes(operator)) {
            const bitVal = evalBitAnd(left) ?? evalBitAnd(right);
            const lit = t.isNumericLiteral(right) ? right.value : (t.isNumericLiteral(left) ? left.value : null);
            if (bitVal !== null && lit !== null) {
              const res = (operator === "===" || operator === "==") ? (bitVal === lit) : (bitVal !== lit);
              path.replaceWith(t.booleanLiteral(res));
              stats.predicatesFolded++;
              changed = true;
            }
          }
        }
      },
      ExpressionStatement(path) {
        const e = path.node.expression;
        // Strip void [decoy1, decoy2], void decoyFn, BLA steppers, and deception IIFEs
        if (isBlaExpr(e)) {
          path.remove();
          changed = true;
        }
      }
    });

    // Dead BLA lure purge: only provably-BLA unreferenced symbols are removed here
    // (BLA stem name, poison payload, or an opaque Math.imul body). Real customer
    // bindings are never touched by this pass — reachability handles those.
    traverse(ast, {
      Program(path) {
        path.scope.crawl();
        for (const [name, binding] of Object.entries(path.scope.bindings)) {
          if (binding.referenced || exportedNames.has(name) || binding.kind === "param") continue;
          const bPath = binding.path;
          const src = generate(bPath.node).code;
          const isLure = POISON_REGEX.test(src) || UNICODE_POISON_REGEX.test(src) ||
                         BLA_IDENT_STEMS.test(name) || /Math\.imul/i.test(src);

          if (!isLure) continue;
          if (bPath.isVariableDeclarator()) {
            const varDecl = bPath.parentPath;
            if (varDecl?.isVariableDeclaration()) {
              if (varDecl.node.declarations.length === 1) varDecl.remove();
              else bPath.remove();
              stats.symbolsPurged++;
              changed = true;
            }
          } else if (bPath.isFunctionDeclaration()) {
            bPath.remove();
            stats.symbolsPurged++;
            changed = true;
          }
        }
      }
    });
  }

  // Reachability analysis (Tree-shaking unreachable BLA labyrinths, decoys, and vectors)
  // Roots include: module exports, real application IIFEs, DOM mounts, global side-effects
  // Works both at Program level and inside the main IIFE closure of production bundles.
  const reachable = new Set();
  const toVisit = [];

  function registerLiveNode(nodePath) {
    nodePath.traverse({
      Identifier(idPath) {
        const name = idPath.node.name;
        const b = idPath.scope.getBinding(name);
        if (b && b.scope.block.type === "Program" && !reachable.has(name)) {
          reachable.add(name);
          toVisit.push(b);
        }
      }
    });
  }

  let hasAppIife = false;
  let hasExports = false;

  traverse(ast, {
    Program(path) {
      for (const stmt of path.get("body")) {
        // Module exports are live roots
        if (stmt.isExportNamedDeclaration() || stmt.isExportDefaultDeclaration() || stmt.isExportAllDeclaration()) {
          hasExports = true;
          registerLiveNode(stmt);
        }
        // Expression statements (app IIFEs, DOM queries, function calls, global assignments)
        else if (stmt.isExpressionStatement()) {
          const iife = getIifeFunction(stmt.node);
          if (iife) {
            hasAppIife = true;
            // Reachability analysis INSIDE the main IIFE closure of bundle
            stmt.traverse({
              BlockStatement(blockPath) {
                if (blockPath.parent !== iife) return;
                const iifeReachable = new Set();
                const iifeToVisit = [];

                function registerIifeLiveNode(nodePath) {
                  nodePath.traverse({
                    Identifier(idPath) {
                      const name = idPath.node.name;
                      const b = idPath.scope.getBinding(name);
                      if (b) {
                        if (b.scope.block === iife && !iifeReachable.has(name)) {
                          iifeReachable.add(name);
                          iifeToVisit.push(b);
                        } else if (b.scope.block.type === "Program" && !reachable.has(name)) {
                          reachable.add(name);
                          toVisit.push(b);
                        }
                      }
                    }
                  });
                }

                // Scan inner statements for roots
                for (const innerStmt of blockPath.get("body")) {
                  if (innerStmt.isReturnStatement() || innerStmt.isThrowStatement()) {
                    registerIifeLiveNode(innerStmt);
                  } else if (innerStmt.isExpressionStatement() && isSideEffectExpression(innerStmt.node.expression)) {
                    registerIifeLiveNode(innerStmt);
                  } else if (innerStmt.isVariableDeclaration()) {
                    const hasSideEffect = innerStmt.node.declarations.some(d => d.init && isSideEffectExpression(d.init));
                    if (hasSideEffect) {
                      registerIifeLiveNode(innerStmt);
                    }
                  }
                }

                // Trace reachability inside IIFE
                while (iifeToVisit.length > 0) {
                  const b = iifeToVisit.pop();
                  b.path.traverse({
                    Identifier(idPath) {
                      const name = idPath.node.name;
                      const innerB = idPath.scope.getBinding(name);
                      if (innerB) {
                        if (innerB.scope.block === iife && !iifeReachable.has(name)) {
                          iifeReachable.add(name);
                          iifeToVisit.push(innerB);
                        } else if (innerB.scope.block.type === "Program" && !reachable.has(name)) {
                          reachable.add(name);
                          toVisit.push(innerB);
                        }
                      }
                    }
                  });
                }

                // Purge unreachable declarations inside IIFE
                for (const innerStmt of blockPath.get("body")) {
                  const names = [];
                  if (innerStmt.isFunctionDeclaration()) {
                    if (innerStmt.node.id) names.push(innerStmt.node.id.name);
                  } else if (innerStmt.isVariableDeclaration()) {
                    for (const d of innerStmt.node.declarations) {
                      if (t.isIdentifier(d.id)) names.push(d.id.name);
                    }
                  }
                  if (names.length === 0) continue;
                  if (!names.some(n => iifeReachable.has(n))) {
                    if (isBlaDeclNode(innerStmt.node) || names.some(n => BLA_IDENT_STEMS.test(n))) {
                      innerStmt.remove();
                      stats.symbolsPurged++;
                    }
                  }
                }
              }
            });
            registerLiveNode(stmt);
          } else if (isSideEffectExpression(stmt.node.expression)) {
            registerLiveNode(stmt);
          }
        }
        // Variable declaration with side-effects (e.g. const app = initApp())
        else if (stmt.isVariableDeclaration()) {
          if (!isBlaDeclNode(stmt.node) && !stmt.node.declarations.some(d => t.isIdentifier(d.id) && BLA_IDENT_STEMS.test(d.id.name))) {
            const hasSideEffect = stmt.node.declarations.some(d => d.init && isSideEffectExpression(d.init));
            if (hasSideEffect) {
              registerLiveNode(stmt);
            }
          }
        }
      }
    }
  });

  // Trace Program-level transitive reachability graph
  while (toVisit.length > 0) {
    const b = toVisit.pop();
    b.path.traverse({
      Identifier(idPath) {
        const innerB = idPath.scope.getBinding(idPath.node.name);
        if (innerB && innerB.scope.block.type === "Program" && !reachable.has(idPath.node.name)) {
          reachable.add(idPath.node.name);
          toVisit.push(innerB);
        }
      }
    });
  }

  // Purge unreachable top-level BLA declarations.
  // In a bundled app (entry = IIFE or side effects, no export), all unreachable declarations
  // outside the app graph are BLA chaff and get removed.
  // In library code, unreachable declarations carrying BLA signatures are dropped.
  traverse(ast, {
    Program(path) {
      for (const stmt of path.get("body")) {
        if (stmt.isExportNamedDeclaration() || stmt.isExportDefaultDeclaration() || stmt.isExportAllDeclaration()) continue;
        const names = [];
        if (stmt.isFunctionDeclaration()) {
          const fnName = stmt.node.id?.name;
          if (!fnName) continue;
          names.push(fnName);
        } else if (stmt.isVariableDeclaration()) {
          for (const d of stmt.node.declarations) {
            if (t.isIdentifier(d.id)) names.push(d.id.name);
          }
        } else {
          continue;
        }
        if (names.length === 0) continue;
        if (names.some((n) => reachable.has(n))) continue;

        const shouldPurge = (hasAppIife && !hasExports) || isBlaDeclNode(stmt.node) || names.some(n => BLA_IDENT_STEMS.test(n));
        if (shouldPurge) {
          stmt.remove();
          stats.symbolsPurged++;
        }
      }
    }
  });

  // Strip all comments (hiding prompt injections, scrambled BLA banners)
  ast.comments = [];

  const out = generate(ast, { comments: false, compact: false, retainLines: false, concise: false }, code);
  const modified = pass > 1 || out.code.length !== code.length;
  return { code: out.code, stats, modified };
}

/** Recursively collect all candidate files */
function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

/** Scan target directory for BLA signatures */
export function scanTarget(targetDir) {
  const root = resolve(targetDir);
  const thisFile = fileURLToPath(import.meta.url);
  const skipSelf = new Set([thisFile, resolve(root, "unblind.mjs"), resolve(root, "unbla.mjs")]);
  const files = walk(root);
  const report = { artifacts: [], poisonedFiles: [], totalChecked: 0 };

  for (const file of files) {
    if (skipSelf.has(resolve(file))) continue;
    report.totalChecked++;
    const name = basename(file);
    if (ARTIFACT_FILES.has(name) || name.endsWith(".bunfs-snapshot") || name.endsWith(".bla-sidecar.v1.json") || name.endsWith(".bla-manifest.json")) {
      report.artifacts.push(relative(root, file));
    } else if (JS_EXTS.has(extname(file))) {
      const src = readFileSync(file, "utf8");
      if (/Math\.imul\([^)]+\)\s*&\s*[17]/i.test(src) || POISON_REGEX.test(src) || BLA_IDENT_STEMS.test(src)) {
        report.poisonedFiles.push(relative(root, file));
      }
    }
  }
  for (const d of ARTIFACT_DIRS) {
    if (existsSync(join(root, d))) report.artifacts.push(`${d}/ (directory)`);
  }
  return report;
}

/** Clean target directory */
export function cleanTarget(targetDir) {
  const root = resolve(targetDir);
  const thisFile = fileURLToPath(import.meta.url);
  const skipSelf = new Set([thisFile, resolve(root, "unblind.mjs"), resolve(root, "unbla.mjs")]);
  const files = walk(root);
  const result = {
    deletedArtifacts: [],
    cleanedFiles: [],
    totalPredicatesFolded: 0,
    totalDeadBranchesCut: 0,
    totalSymbolsPurged: 0,
    bytesSaved: 0
  };

  // 1. Remove artifact directories & files
  for (const d of ARTIFACT_DIRS) {
    const dPath = join(root, d);
    if (existsSync(dPath)) {
      rmSync(dPath, { recursive: true, force: true });
      result.deletedArtifacts.push(`${d}/`);
    }
  }
  for (const file of files) {
    if (skipSelf.has(resolve(file))) continue;
    const name = basename(file);
    if (ARTIFACT_FILES.has(name) || name.endsWith(".bunfs-snapshot") || name.endsWith(".bla-sidecar.v1.json") || name.endsWith(".bla-manifest.json")) {
      unlinkSync(file);
      result.deletedArtifacts.push(relative(root, file));
    }
  }

  // 2. Clean JS/TS source files
  const sourceFiles = files.filter(f => JS_EXTS.has(extname(f)) && existsSync(f) && !skipSelf.has(resolve(f)));
  for (const file of sourceFiles) {
    const original = readFileSync(file, "utf8");
    const { code: cleaned, stats, modified } = cleanCode(original);
    if (modified) {
      writeFileSync(file, cleaned, "utf8");
      result.cleanedFiles.push(relative(root, file));
      result.totalPredicatesFolded += stats.predicatesFolded;
      result.totalDeadBranchesCut += stats.deadBranchesCut;
      result.totalSymbolsPurged += stats.symbolsPurged;
      result.bytesSaved += Math.max(0, original.length - cleaned.length);
    }
  }
  return result;
}

// CLI Entrypoint
const isEntry = process.argv[1] && (fileURLToPath(import.meta.url) === resolve(process.argv[1]) || /unbla(?:\.m?js)?$/i.test(process.argv[1]));
if (isEntry) {
  const args = process.argv.slice(2);
  const isScan = args.includes("--scan") || args[0] === "scan";
  const isHelp = args.includes("-h") || args.includes("--help");
  const targetDir = args.find(a => !a.startsWith("-") && a !== "scan" && a !== "clean") || ".";

  if (isHelp) {
    console.log(`
🛡️  UNBLIND — Antidote against BLA (Blind LLM Agents) context poisoners
Repository: https://github.com/yoshikobaru/unblind

Usage:
  npx github:yoshikobaru/unblind [dir]         Clean project in-place (default)
  npx github:yoshikobaru/unblind clean [dir]   Clean project in-place
  npx github:yoshikobaru/unblind scan [dir]    Scan for BLA artifacts without modifying
  npx github:yoshikobaru/unblind --help        Show this help
`);
    process.exit(0);
  }

  const absTarget = resolve(targetDir);
  console.log(`\x1b[36m⚡ UNBLIND v1.0.0\x1b[0m — Target: \x1b[33m${absTarget}\x1b[0m`);

  if (isScan) {
    const report = scanTarget(absTarget);
    console.log(`\nInspected ${report.totalChecked} files.`);
    if (report.artifacts.length === 0 && report.poisonedFiles.length === 0) {
      console.log(`\x1b[32m✔ CLEAN: No BLA artifacts or poison signatures found.\x1b[0m\n`);
    } else {
      console.log(`\x1b[31m⚠ THREAT DETECTED: BLA context poison found!\x1b[0m`);
      if (report.artifacts.length) console.log(`  Artifacts (${report.artifacts.length}):`, report.artifacts);
      if (report.poisonedFiles.length) console.log(`  Poisoned files (${report.poisonedFiles.length}):`, report.poisonedFiles);
      console.log(`\n\x1b[33mRun "npx github:yoshikobaru/unblind clean ${targetDir}" to disinfect.\x1b[0m\n`);
    }
  } else {
    const res = cleanTarget(absTarget);
    const estTokens = Math.round(res.bytesSaved / 4);
    console.log(`\n\x1b[32m✔ Disinfection complete!\x1b[0m`);
    console.log(`  • Artifacts deleted:     ${res.deletedArtifacts.length}`);
    console.log(`  • Files sanitized:       ${res.cleanedFiles.length}`);
    console.log(`  • Predicates folded:     ${res.totalPredicatesFolded}`);
    console.log(`  • Dead branches cut:     ${res.totalDeadBranchesCut}`);
    console.log(`  • Poison symbols purged: ${res.totalSymbolsPurged}`);
    console.log(`  • Est. tokens saved:     ~${estTokens.toLocaleString()} tokens (${(res.bytesSaved / 1024).toFixed(1)} KB)`);
    console.log(`\n\x1b[32m✨ Code is clean, formatted, and ready for AI analysis.\x1b[0m\n`);
  }
}
